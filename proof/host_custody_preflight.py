#!/usr/bin/env python3
"""Inventory only. Observations are neither authorization nor runtime proof."""
import hashlib
import json
import os
import stat
import sys

TEXT_LIMIT = 16384
BTF_LIMIT = 64 * 1024 * 1024
ENV_LIMIT = 4096

# Fixed paths only. In particular, no environment variable selects a host path.
TEXT_FILES = {
    "kernel_release": "proc/sys/kernel/osrelease",
    "boot_id": "proc/sys/kernel/random/boot_id",
    "pid1_comm": "proc/1/comm",
    "pid1_cgroup": "proc/1/cgroup",
    "cgroup_controllers": "sys/fs/cgroup/cgroup.controllers",
    "cgroup_subtree_control": "sys/fs/cgroup/cgroup.subtree_control",
    "memfd_noexec": "proc/sys/vm/memfd_noexec",
    "yama_ptrace_scope": "proc/sys/kernel/yama/ptrace_scope",
    "active_lsms": "sys/kernel/security/lsm",
    "lockdown": "sys/kernel/security/lockdown",
}
METADATA_PATHS = {
    "root": ".", "var": "var", "var_lib": "var/lib",
    "run": "run", "systemd_runtime": "run/systemd/system",
    "system_bus_socket": "run/dbus/system_bus_socket",
    "systemd_private_socket": "run/systemd/private",
    "cgroup_root": "sys/fs/cgroup", "cgroup_procs": "sys/fs/cgroup/cgroup.procs",
    "docker_socket": "run/docker.sock", "usr": "usr", "usr_bin": "usr/bin",
    "systemd": "usr/lib/systemd/systemd", "systemctl": "usr/bin/systemctl",
    "python3": "usr/bin/python3", "install": "usr/bin/install",
    "sha256sum": "usr/bin/sha256sum", "lib64": "lib64",
    "loader": "lib64/ld-linux-x86-64.so.2",
}
ENV_FIELDS = {
    "repository": "GITHUB_REPOSITORY", "workflow": "GITHUB_WORKFLOW",
    "workflow_ref": "GITHUB_WORKFLOW_REF", "workflow_sha": "GITHUB_WORKFLOW_SHA",
    "event_name": "GITHUB_EVENT_NAME", "ref": "GITHUB_REF", "event_sha": "GITHUB_SHA",
    "run_id": "GITHUB_RUN_ID", "run_attempt": "GITHUB_RUN_ATTEMPT",
    "job": "GITHUB_JOB", "runner_os": "RUNNER_OS", "runner_arch": "RUNNER_ARCH",
    "runner_name": "RUNNER_NAME", "image_os": "ImageOS", "image_version": "ImageVersion",
    "workspace": "GITHUB_WORKSPACE",
}


def observed(value, source):
    return {"status": "observed", "value": value, "source": source}


def unavailable(source, reason):
    return {"status": "unavailable", "value": None, "source": source, "reason": reason}


def _reason(exc):
    return type(exc).__name__


class SafeRoot:
    """Open beneath a trusted root, rejecting symlinks at every component."""
    def __init__(self, root):
        self.root = root

    def _parent(self, path):
        parts = path.split("/")
        if path == ".":
            parts = ["."]
        elif not parts or any(p in ("", ".", "..") for p in parts):
            raise ValueError("invalid relative path")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(self.root, flags)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, limit):
        source = "/" + path
        try:
            parent, name = self._parent(path)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            finally:
                os.close(parent)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError("not a regular file")
                data = bytearray()
                while len(data) <= limit:
                    chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > limit:
                    raise ValueError("file exceeds limit")
                return bytes(data), None
            finally:
                os.close(fd)
        except (OSError, ValueError) as exc:
            return None, unavailable(source, _reason(exc))

    def metadata(self, path):
        source = "/" + path
        try:
            parent, name = self._parent(path)
            try:
                st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
            return observed({"uid": st.st_uid, "gid": st.st_gid,
                             "mode": stat.S_IMODE(st.st_mode),
                             "type": stat.S_IFMT(st.st_mode),
                             "device": st.st_dev, "inode": st.st_ino}, source)
        except (OSError, ValueError) as exc:
            return unavailable(source, _reason(exc))

    def link(self, path):
        source = "/" + path
        try:
            parent, name = self._parent(path)
            try:
                target = os.readlink(name, dir_fd=parent)
            finally:
                os.close(parent)
            if len(target.encode()) > TEXT_LIMIT:
                raise ValueError("link target exceeds limit")
            return observed(target, source)
        except (OSError, ValueError) as exc:
            return unavailable(source, _reason(exc))


def text(root, path):
    data, error = root.read(path, TEXT_LIMIT)
    if error:
        return error
    try:
        value = data.decode("utf-8", errors="strict").strip()
        if not value or "\x00" in value:
            raise ValueError("empty or invalid text")
        return observed(value, "/" + path)
    except (UnicodeError, ValueError) as exc:
        return unavailable("/" + path, _reason(exc))


def env_value(env, name):
    value = env.get(name)
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > ENV_LIMIT or "\x00" in value:
        return unavailable("env:" + name, "missing or invalid")
    return observed(value, "env:" + name)


def collect(root_path="/", workspace_path=".", env=None):
    env = os.environ if env is None else env
    root = SafeRoot(root_path)
    inventory = {name: text(root, path) for name, path in TEXT_FILES.items()}
    for name, leaf in (("uid_map", "uid_map"), ("gid_map", "gid_map"),
                       ("process_status", "status"), ("mountinfo", "mountinfo")):
        inventory[name] = text(root, "proc/%d/%s" % (os.getpid(), leaf))
    data, error = root.read("sys/kernel/btf/vmlinux", BTF_LIMIT)
    inventory["btf_sha256"] = error or observed(hashlib.sha256(data).hexdigest(), "/sys/kernel/btf/vmlinux")
    inventory["pid1_exe_link"] = root.link("proc/1/exe")
    inventory["systemd_version"] = unavailable("filesystem", "no independently readable version source selected")
    inventory["staging_target"] = unavailable("future launch design", "no staging target selected")
    inventory["cgroup_manager_interface"] = unavailable("filesystem inventory", "manager operations have not been probed")
    inventory["manager_dbus_availability"] = unavailable("/run/dbus/system_bus_socket", "socket metadata does not establish manager availability")
    inventory["approval_subject"] = unavailable("authenticated approval channel", "no authenticated approval subject supplied")
    inventory["files"] = {name: root.metadata(path) for name, path in METADATA_PATHS.items()}
    inventory["process_identity"] = observed({"uid": os.getuid(), "euid": os.geteuid(),
                                               "gid": os.getgid(), "egid": os.getegid(),
                                               "groups": os.getgroups()}, "process credentials")
    identity = {name: env_value(env, key) for name, key in ENV_FIELDS.items()}
    identity["checkout_head"] = text(SafeRoot(workspace_path), ".git/HEAD")
    return {
        "schema": "iyi-host-custody-preflight-v1",
        "strict_eligible": False, "load_attempted": False, "attach_attempted": False,
        "exec_identity_tested": False,
        "threat_model": "A host runner user with passwordless sudo executing hostile arbitrary code can defeat local root-owned staging and systemd collection. A separate trust domain is required for that adversary.",
        "identity": identity, "inventory": inventory,
    }


def main():
    json.dump(collect(), sys.stdout, sort_keys=True, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
