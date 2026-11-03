"""Copy one sealed archive through no-follow root-relative descriptors."""
import hashlib
import os
import stat
import sys


def copy(root, source, target, expected_size, expected_hash):
    root = os.path.realpath(root)
    source = os.path.abspath(source)
    # Darwin's /tmp is a system alias for /private/tmp, not an owned symlink.
    if sys.platform == 'darwin' and source.startswith('/tmp/'):
        source = '/private' + source
    rel = os.path.relpath(source, root)
    parts = rel.split(os.sep)
    if os.path.isabs(rel) or any(p in ('', '.', '..') for p in parts):
        raise ValueError('archive outside owned root')
    flags = os.O_RDONLY | os.O_NOFOLLOW
    opened = []
    out = None
    try:
        rootfd = os.open(root, flags | os.O_DIRECTORY)
        opened.append(rootfd)
        for component in parts[:-1]:
            opened.append(os.open(component, flags | os.O_DIRECTORY, dir_fd=opened[-1]))
        filefd = os.open(parts[-1], flags, dir_fd=opened[-1])
        opened.append(filefd)
        before = os.fstat(filefd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('archive is not a singly linked regular file')
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        h = hashlib.sha256()
        count = 0
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
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('archive changed during copy')
        if count != int(expected_size) or h.hexdigest() != expected_hash:
            raise ValueError('archive digest or byte count mismatch')
        for idx, component in enumerate(parts):
            expected = os.fstat(opened[idx + 1])
            current = os.stat(component, dir_fd=opened[idx], follow_symlinks=False)
            if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError('archive component replaced during copy')
        os.fsync(out)
    finally:
        if out is not None:
            os.close(out)
        for fd in reversed(opened):
            os.close(fd)


if __name__ == '__main__':
    copy(*sys.argv[1:])
