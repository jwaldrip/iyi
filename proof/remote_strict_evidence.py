"""Descriptor-relative, no-follow evidence access for the remote controller."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import tarfile


class UnsafeEvidenceError(Exception):
    pass


def _parts(path):
    parts = path.split('/')
    if not parts or any(p in ('', '.', '..') for p in parts):
        raise UnsafeEvidenceError('INVALID-RELATIVE-NAME')
    return parts


class OwnedRoot:
    def __init__(self, path, *, create=False):
        # macOS exposes top-level system aliases (/tmp -> /private/tmp, /var -> /private/var,
        # which contains $TMPDIR). Follow only that top-level alias; every component below
        # the owned root is still opened with O_NOFOLLOW.
        path = os.path.abspath(path)
        top = path.strip('/').split('/')[0] if path != '/' else ''
        if top and os.path.islink('/' + top):
            path = os.path.realpath('/' + top) + path[len(top) + 1:]
        self.path = path
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.strip('/').split('/'):
                if not component:
                    continue
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            self.fd = fd
            self.identities = {}
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        os.close(self.fd)

    def remember(self, name, fd):
        st = os.fstat(fd)
        identity = (st.st_dev, st.st_ino)
        previous = self.identities.setdefault(name, identity)
        if previous != identity:
            raise UnsafeEvidenceError('REPLACED-DIRECTORY ' + name)

    def parent(self, name):
        parts = _parts(name)
        fd = os.dup(self.fd)
        try:
            prefix = []
            for component in parts[:-1]:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                prefix.append(component)
                self.remember('/'.join(prefix), nxt)
                os.close(fd)
                fd = nxt
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def open_writer(self, name):
        parent, leaf = self.parent(name)
        try:
            fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise UnsafeEvidenceError('UNSAFE-WRITER ' + name)
                os.ftruncate(fd, 0)
                return os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(parent)

    def write(self, name, data, *, append=False):
        parent, leaf = self.parent(name)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if append else 0)
            fd = os.open(leaf, flags, 0o600, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink != 1:
                    raise UnsafeEvidenceError('UNSAFE-WRITER ' + name)
                if not append:
                    os.ftruncate(fd, 0)
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def add_file(self, tar, name, arcname, *, optional=False, manifest=None):
        try:
            parent, leaf = self.parent(name)
        except FileNotFoundError:
            if optional:
                return
            raise
        try:
            try:
                fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                if optional:
                    return
                raise
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                    raise UnsafeEvidenceError('UNSAFE-MEMBER ' + name)
                info = tarfile.TarInfo(arcname)
                info.size, info.mode, info.mtime = before.st_size, 0o644, 0
                digest = hashlib.sha256()
                class Reader:
                    count = 0
                    def read(self, size):
                        data = os.read(fd, size)
                        self.count += len(data)
                        digest.update(data)
                        return data
                reader = Reader()
                tar.addfile(info, reader)
                count = reader.count
                after = os.fstat(fd)
                current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
                if identity(before) != identity(after) or identity(before) != identity(current) or count != before.st_size:
                    raise UnsafeEvidenceError('UNSTABLE-MEMBER ' + name)
                if manifest is not None:
                    manifest.append({'path': arcname, 'bytes': count, 'sha256': digest.hexdigest()})
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def walk(self, name, include):
        try:
            parent, leaf = self.parent(name)
        except FileNotFoundError:
            return
        try:
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            os.close(parent)
            return
        os.close(parent)
        self.remember(name, fd)
        def visit(directory, rel):
            for entry in sorted(os.listdir(directory)):
                relative = rel + '/' + entry
                st = os.stat(entry, dir_fd=directory, follow_symlinks=False)
                if not include(relative, stat.S_ISDIR(st.st_mode)):
                    continue
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(entry, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    self.remember(relative, child)
                    try:
                        yield from visit(child, relative)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    yield relative
                else:
                    raise UnsafeEvidenceError('UNSAFE-MEMBER ' + relative)
        try:
            yield from visit(fd, name)
        finally:
            os.close(fd)


def seal(report_dir, artifacts_dir, unit, attempt, chain_id, sequence, failed=False, artifacts_root=None, report_root=None):
    slug = unit.replace('/', '_')
    archive_dir = os.path.join(artifacts_dir, 'incremental-archives')
    report = OwnedRoot(report_dir) if os.path.lexists(report_dir) else None
    artifacts = OwnedRoot(artifacts_dir)
    if report_root is not None:
        if report is None:
            artifacts.close()
            raise UnsafeEvidenceError('MISSING-REPORT-ROOT')
        old_report, current_report = os.fstat(report_root.fd), os.fstat(report.fd)
        if (old_report.st_dev, old_report.st_ino) != (current_report.st_dev, current_report.st_ino):
            report.close()
            artifacts.close()
            raise UnsafeEvidenceError('REPLACED-REPORT-ROOT')
    if artifacts_root is not None:
        old, current = os.fstat(artifacts_root.fd), os.fstat(artifacts.fd)
        if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
            artifacts.close()
            if report: report.close()
            raise UnsafeEvidenceError('REPLACED-ARTIFACT-ROOT')
    try:
        os.mkdir('incremental-archives', 0o700, dir_fd=artifacts.fd)
    except FileExistsError:
        pass
    archives = OwnedRoot(archive_dir)
    expected, actual = os.stat('incremental-archives', dir_fd=artifacts.fd, follow_symlinks=False), os.fstat(archives.fd)
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
        raise UnsafeEvidenceError('REPLACED-ARCHIVE-ROOT')
    name = f"evidence-{chain_id[:8] if chain_id else 'prepin'}-seq{sequence:03d}-{slug}-a{attempt}.tar.gz"
    path = os.path.join(archive_dir, name)
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=archives.fd)
        with os.fdopen(fd, 'wb', closefd=False) as target:
            with tarfile.open(fileobj=target, mode='w:gz', format=tarfile.PAX_FORMAT) as tar:
                manifest = []
                if report:
                    for rel in ('pin.json', 'final.json', 'run3/required.json'):
                        report.add_file(tar, rel, 'meta/' + rel, optional=True, manifest=manifest)
                for rel, arc in [('stage-journal.jsonl', 'controller/stage-journal.jsonl'), (f'controller-logs/{slug}-a{attempt}.log', f'controller-logs/{slug}-a{attempt}.log')]:
                    artifacts.add_file(tar, rel, arc, optional=True, manifest=manifest)
                if unit == 'terminal':
                    for rel in ('strict-controller-summary.json', 'terminal-envelope.json'):
                        artifacts.add_file(tar, rel, 'controller/' + rel, manifest=manifest)
                if report and unit not in ('plan', 'pin', 'terminal'):
                    base = f'{unit}/a{attempt}'
                    def include(rel, is_dir):
                        sub = rel[len(base)+1:].split('/')
                        first = sub[0]
                        if unit == 'run1' and (first == 'rg9_work' or first.endswith(('.tmp', '.cache'))): return False
                        if unit == 'run2':
                            if first in ('run2.tmp', 'run2.cache') or first.endswith(('.tmp', '.cache')): return False
                            if first == 'scratch' and len(sub) > 1 and sub[1] != 'rows': return False
                        if unit.startswith('run3'):
                            if first in ('t', 'c', 'bin'): return False
                            if first == 's':
                                if not failed: return False
                                if len(sub) < 3: return is_dir
                                if sub[2] != 'mods': return False
                                if len(sub) == 3: return is_dir
                        return True
                    for rel in report.walk(base, include):
                        report.add_file(tar, rel, 'attempt/' + rel[len(base)+1:], manifest=manifest)
                document = {'version': 1, 'members': manifest}
                if unit == 'pin' and chain_id is None:
                    document['pin_state'] = 'present-unestablished' if any(m['path'] == 'meta/pin.json' for m in manifest) else 'absent'
                data = json.dumps(document, sort_keys=True).encode()
                info = tarfile.TarInfo('evidence-manifest.json')
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                tar.addfile(info, io.BytesIO(data))
            target.flush()
            os.fsync(fd)
        os.close(fd)
        fd = None
        readfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=archives.fd)
        try:
            h = hashlib.sha256()
            n = 0
            while True:
                chunk = os.read(readfd, 65536)
                if not chunk: break
                h.update(chunk)
                n += len(chunk)
        finally:
            os.close(readfd)
        return path, n, h.hexdigest()
    except BaseException:
        try: os.unlink(name, dir_fd=archives.fd)
        except FileNotFoundError: pass
        raise
    finally:
        if fd is not None: os.close(fd)
        if report: report.close()
        artifacts.close()
        archives.close()
