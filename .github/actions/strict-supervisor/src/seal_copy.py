"""Read sealed files through retained, no-follow directory descriptors."""
import hashlib
import os
import stat
import sys


def normalize(path):
    path = os.path.abspath(path)
    if sys.platform == 'darwin' and (path == '/tmp' or path.startswith('/tmp/')):
        return '/private' + path
    if sys.platform == 'darwin' and (path == '/var' or path.startswith('/var/')):
        return '/private' + path
    return path


def open_root(path):
    path = normalize(path)
    parts = [part for part in path.split(os.sep) if part]
    chain = [os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in parts:
            chain.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain[-1]))
        return path, parts, chain
    except BaseException:
        for fd in reversed(chain):
            os.close(fd)
        raise


def check_chain(parts, chain):
    for i, part in enumerate(parts):
        expected = os.fstat(chain[i + 1])
        current = os.stat(part, dir_fd=chain[i], follow_symlinks=False)
        if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError('directory component replaced')


def stable_stat(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def copy(root, source, target, expected_size, expected_hash):
    root, root_parts, chain = open_root(root)
    parts = os.path.relpath(normalize(source), root).split(os.sep)
    if any(p in ('', '.', '..') for p in parts):
        for fd in reversed(chain):
            os.close(fd)
        raise ValueError('archive outside owned root')
    rootfd = chain[-1]
    opened = [rootfd]
    out = None
    try:
        for component in parts[:-1]:
            opened.append(os.open(component, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=opened[-1]))
        # O_NONBLOCK: opening a FIFO for reading must not block before the regular-file check refuses it.
        filefd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=opened[-1])
        opened.append(filefd)
        before = os.fstat(filefd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('archive is not a singly linked regular file')
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h, count = hashlib.sha256(), 0
        while True:
            data = os.read(filefd, 1024 * 1024)
            if not data:
                break
            h.update(data)
            count += len(data)
            view = memoryview(data)
            while view:
                view = view[os.write(out, view):]
        after = os.fstat(filefd)
        if stable_stat(before) != stable_stat(after):
            raise ValueError('archive changed during copy')
        if count != int(expected_size) or h.hexdigest() != expected_hash:
            raise ValueError('archive digest or byte count mismatch')
        check_chain(root_parts, chain)
        check_chain(parts, opened)
        os.fsync(out)
    finally:
        if out is not None:
            os.close(out)
        for fd in reversed(opened[1:]):
            os.close(fd)
        for fd in reversed(chain):
            os.close(fd)


def read_completion(root):
    _, root_parts, chain = open_root(root)
    rootfd = chain[-1]
    fd = None
    try:
        fd = os.open('controller-completion.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rootfd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4 * 1024 * 1024:
            raise ValueError('invalid completion file')
        chunks, count = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > 4 * 1024 * 1024:
                raise ValueError('completion file too large')
        after = os.fstat(fd)
        if stable_stat(before) != stable_stat(after) or count != after.st_size:
            raise ValueError('completion changed while reading')
        check_chain(root_parts, chain)
        check_chain(['controller-completion.json'], [rootfd, fd])
        sys.stdout.buffer.write(b''.join(chunks))
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(chain):
            os.close(item)


if __name__ == '__main__':
    if sys.argv[1] == '--read-completion':
        read_completion(sys.argv[2])
    else:
        copy(*sys.argv[1:])
