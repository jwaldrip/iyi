"""Protected snapshot staging primitives. Runtime staging is deliberately held.

The fixture helper models the copy and verification protocol; it does not establish
root ownership or authorization. No privileged command is run by this module.
"""
import hashlib
import os
import re
import stat
import time

try:
    from . import host_custody_authorization as authorization
except ImportError:
    import host_custody_authorization as authorization


ROLES = {
    "observer": "observer",
    "bpf_object": "observer.bpf.o",
    "dependencies": "dependencies",
    "recipe": "recipe",
    "exec_config": "exec-config",
}
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class StageRefused(RuntimeError):
    pass


def stage(subject):
    """Production entry point. Real authorization is mandatory and currently held.

    There is intentionally no executor parameter, fixture bypass, or source path
    supplied by the subject. Even if authorization becomes available, this must
    remain held until the privileged implementation has been reviewed and wired.
    """
    authorization.authorize_runtime(subject)
    raise StageRefused("protected staging executor and platform qualification are not integrated")


def _open_regular(root_fd, relative):
    """Open each component relative to a trusted directory FD, never following links."""
    if type(relative) is not str:
        raise StageRefused("invalid source")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise StageRefused("invalid source component")
    directory = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or os.lseek(fd, 0, os.SEEK_CUR) != 0:
                raise StageRefused("source is not a regular file at offset zero")
            return fd, st
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(directory)


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _valid_meta(meta, size, digest, mode):
    return (type(meta) is dict and set(meta) == {"size", "sha256", "device", "inode", "uid", "gid", "mode", "nlink", "file_type"}
            and meta["file_type"] == "regular" and meta["uid"] == 0 and meta["gid"] == 0
            and meta["mode"] == mode and meta["nlink"] == 1 and meta["size"] == size
            and meta["sha256"] == digest and type(meta["device"]) is int
            and type(meta["inode"]) is int and meta["inode"] > 0)


def _stage_fixture(root_fd, artifacts, executor, timeout):
    """Test-only model using an injected in-memory executor, never an admission path.

    Executor must implement create_directory, begin, write, finish, inspect,
    expose and abort. It is deliberately not accepted by the production entry.
    """
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or not 0 < timeout < float("inf"):
        raise StageRefused("finite timeout required")
    if type(artifacts) is not dict or set(artifacts) != set(ROLES):
        raise StageRefused("all fixed roles required")
    for role, spec in artifacts.items():
        if (type(spec) is not dict or set(spec) != {"size", "sha256", "file_type", "mode"}
                or type(spec["size"]) is not int or not 0 <= spec["size"] < 2**63 - 1
                or type(spec["sha256"]) is not str or not _HEX.fullmatch(spec["sha256"])
                or spec["file_type"] != "regular" or type(spec["mode"]) is not int
                or spec["mode"] != (0o555 if role == "observer" else 0o444)):
            raise StageRefused("invalid artifact policy")
    deadline = time.monotonic() + timeout
    def timely():
        if time.monotonic() >= deadline:
            raise StageRefused("staging deadline exceeded")
    verified = {}
    try:
        directory = executor.create_directory()
        if (type(directory) is not dict or set(directory) != {"device", "inode", "uid", "gid", "mode", "nlink", "file_type"}
                or directory["file_type"] != "directory" or directory["uid"] != 0
                or directory["gid"] != 0 or directory["mode"] != 0o700
                or type(directory["inode"]) is not int or directory["inode"] <= 0
                or type(directory["nlink"]) is not int or directory["nlink"] < 2):
            raise StageRefused("invalid private destination")
        for role, basename in ROLES.items():
            timely()
            spec = artifacts[role]
            fd, before = _open_regular(root_fd, basename)
            try:
                executor.begin(role, basename, spec["size"] + 1)
                count = 0
                digest = hashlib.sha256()
                while count <= spec["size"]:
                    timely()
                    chunk = os.read(fd, min(65536, spec["size"] + 1 - count))
                    if not chunk:
                        break
                    count += len(chunk)
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        timely()
                        n = executor.write(role, view)
                        if type(n) is not int or n <= 0 or n > len(view):
                            raise StageRefused("invalid or failed courier write")
                        view = view[n:]
                after = os.fstat(fd)
                if _identity(before) != _identity(after):
                    raise StageRefused("source changed during copy")
                if count != spec["size"] or digest.hexdigest() != spec["sha256"]:
                    raise StageRefused("source size or digest mismatch")
                if executor.finish(role) != 0:
                    raise StageRefused("copy utility failed")
            finally:
                os.close(fd)
            timely()
            meta = executor.inspect(role)
            if not _valid_meta(meta, spec["size"], spec["sha256"], 0o600):
                raise StageRefused("destination readback rejected")
            verified[role] = meta
        if len({(m["device"], m["inode"]) for m in verified.values()}) != len(ROLES):
            raise StageRefused("destination inode reused")
        # All readbacks precede any exposure, and each final mode is checked.
        for role in ROLES:
            timely()
            executor.expose(role, artifacts[role]["mode"])
        for role in ROLES:
            timely()
            meta = executor.inspect(role)
            if not _valid_meta(meta, artifacts[role]["size"], artifacts[role]["sha256"], artifacts[role]["mode"]):
                raise StageRefused("exposed destination rejected")
            if (meta["device"], meta["inode"]) != (verified[role]["device"], verified[role]["inode"]):
                raise StageRefused("destination replaced during exposure")
            verified[role] = meta
        return {"directory": directory, "artifacts": verified}
    except BaseException:
        executor.abort()
        raise
