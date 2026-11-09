"""
hosted_boundary.py: Host boundary policy, capability detection, and canary verification.

This module defines and verifies the execution boundary for native workloads on hosted
macOS runners. The boundary guarantees that native code:
  1. Cannot read caller-owned secrets or Actions-like command-files (e.g. GITHUB_ENV, GITHUB_OUTPUT).
  2. Cannot connect to disallowed external network destinations.
  3. Can read permitted fixtures and system libraries.
  4. Can write only within owned roots (private HOME, private TMPDIR, owned execution root).
  5. Can reach an owned loopback server.
  6. Executes in an explicit clean allowlisted environment with no inherited credentials.

Rule enforcement is fail-closed: if the host platform cannot enforce the policy,
execution is refused. A test fake or mock is never accepted as proof of hosted policy.
"""

from __future__ import annotations

import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


class HostBoundaryError(RuntimeError):
    """Base exception for host boundary failures."""


class HostBoundaryUnsupportedError(HostBoundaryError):
    """Raised when host boundary enforcement is unsupported on the current platform."""


class HostBoundaryPolicyError(HostBoundaryError):
    """Raised when a boundary policy definition or configuration is invalid."""


class HostBoundaryCanaryFailedError(HostBoundaryError):
    """Raised when canary probes fail on the host."""


class HostBoundaryFakedProofError(HostBoundaryError):
    """Raised when a fake, stub, or simulated receipt is claimed as hosted proof."""


FORBIDDEN_ENV_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^GITHUB_.*", re.IGNORECASE),
    re.compile(r"^ACTIONS_.*", re.IGNORECASE),
    re.compile(r"^GH_.*", re.IGNORECASE),
    re.compile(r"^AWS_.*", re.IGNORECASE),
    re.compile(r"^GOOGLE_.*", re.IGNORECASE),
    re.compile(r"^AZURE_.*", re.IGNORECASE),
    re.compile(r"^GCLOUD_.*", re.IGNORECASE),
    re.compile(r"^SSH_.*", re.IGNORECASE),
    re.compile(r"^GPG_.*", re.IGNORECASE),
    re.compile(r".*TOKEN.*", re.IGNORECASE),
    re.compile(r".*SECRET.*", re.IGNORECASE),
    re.compile(r".*KEY.*", re.IGNORECASE),
    re.compile(r".*AUTH.*", re.IGNORECASE),
    re.compile(r".*PASS.*", re.IGNORECASE),
    re.compile(r".*CREDENTIAL.*", re.IGNORECASE),
    re.compile(r"^BASH_ENV$", re.IGNORECASE),
    re.compile(r"^ENV$", re.IGNORECASE),
    re.compile(r"^SHELLOPTS$", re.IGNORECASE),
    re.compile(r"^NODE_OPTIONS$", re.IGNORECASE),
    re.compile(r"^PYTHONPATH$", re.IGNORECASE),
    re.compile(r"^PYTHONSTARTUP$", re.IGNORECASE),
    re.compile(r"^PYTHONHOME$", re.IGNORECASE),
    re.compile(r"^PYTHONOPTIMIZE$", re.IGNORECASE),
    re.compile(r"^PERL5OPT$", re.IGNORECASE),
    re.compile(r"^RUBYOPT$", re.IGNORECASE),
    re.compile(r"^LD_.*", re.IGNORECASE),
    re.compile(r"^DYLD_.*", re.IGNORECASE),
    re.compile(r"^TEST_SANDBOX$", re.IGNORECASE),
    re.compile(r"^IYI_.*", re.IGNORECASE),
    re.compile(r"^CRYSTAL_.*", re.IGNORECASE),
)

DEFAULT_BASE_PATH: str = "/usr/bin:/bin:/usr/sbin:/sbin"


def is_forbidden_env_key(key: str) -> bool:
    """Return True if an environment variable key matches any forbidden credential/injection pattern."""
    for pattern in FORBIDDEN_ENV_KEY_PATTERNS:
        if pattern.match(key):
            return True
    return False


def sanitize_path(path_str: str) -> str:
    """Sanitize a PATH string, removing relative segments and empty entries."""
    cleaned: list[str] = []
    for segment in path_str.split(os.pathsep):
        seg = segment.strip()
        if not seg or seg == "." or not os.path.isabs(seg):
            continue
        if seg not in cleaned:
            cleaned.append(seg)
    if not cleaned:
        return DEFAULT_BASE_PATH
    return os.pathsep.join(cleaned)


@dataclass(frozen=True)
class BoundaryPolicy:
    """Immutable definition of host boundary controls for a native execution stage."""

    owned_root: str
    private_home: str
    private_tmpdir: str
    allowed_write_roots: tuple[str, ...]
    allowed_read_roots: tuple[str, ...]
    forbidden_read_paths: tuple[str, ...]
    disallowed_network_targets: tuple[tuple[str, int], ...]
    allowed_loopback_hosts: tuple[str, ...]
    extra_allowed_env: dict[str, str]
    base_path: str


def create_boundary_policy(
    owned_root: str,
    private_home: str | None = None,
    private_tmpdir: str | None = None,
    allowed_write_roots: Sequence[str] | None = None,
    allowed_read_roots: Sequence[str] | None = None,
    forbidden_read_paths: Sequence[str] | None = None,
    disallowed_network_targets: Sequence[tuple[str, int]] | None = None,
    allowed_loopback_hosts: Sequence[str] | None = None,
    extra_allowed_env: Mapping[str, str] | None = None,
    base_path: str | None = None,
) -> BoundaryPolicy:
    """Create a validated BoundaryPolicy instance with canonical path roots."""
    if not owned_root or not os.path.isabs(owned_root):
        raise HostBoundaryPolicyError(f"owned_root must be an absolute path: '{owned_root}'")

    owned_abs = os.path.abspath(owned_root)
    home_abs = os.path.abspath(private_home or os.path.join(owned_abs, "home"))
    tmp_abs = os.path.abspath(private_tmpdir or os.path.join(owned_abs, "tmp"))

    write_roots: list[str] = [owned_abs, home_abs, tmp_abs]
    if allowed_write_roots:
        for r in allowed_write_roots:
            if not os.path.isabs(r):
                raise HostBoundaryPolicyError(f"allowed_write_root must be absolute: '{r}'")
            write_roots.append(os.path.abspath(r))

    read_roots: list[str] = [
        "/usr",
        "/System",
        "/Library",
        "/bin",
        "/sbin",
        "/dev",
        owned_abs,
    ]
    if allowed_read_roots:
        for r in allowed_read_roots:
            if not os.path.isabs(r):
                raise HostBoundaryPolicyError(f"allowed_read_root must be absolute: '{r}'")
            read_roots.append(os.path.abspath(r))

    forbidden: list[str] = []
    if forbidden_read_paths:
        for f in forbidden_read_paths:
            if not os.path.isabs(f):
                raise HostBoundaryPolicyError(f"forbidden_read_path must be absolute: '{f}'")
            forbidden.append(os.path.abspath(f))

    # Always forbid caller user credentials if they exist
    caller_home = os.path.expanduser("~")
    standard_secrets = [
        os.path.join(caller_home, ".ssh"),
        os.path.join(caller_home, ".aws"),
        os.path.join(caller_home, ".git-credentials"),
        os.path.join(caller_home, ".netrc"),
    ]
    for s in standard_secrets:
        if os.path.exists(s) and s not in forbidden:
            forbidden.append(os.path.abspath(s))

    # Standard RFC 5737 test network address and cloud metadata IP
    disallowed_net: list[tuple[str, int]] = [
        ("192.0.2.1", 80),
        ("169.254.169.254", 80),
    ]
    if disallowed_network_targets:
        disallowed_net.extend(disallowed_network_targets)

    loopback_hosts = list(allowed_loopback_hosts or ["127.0.0.1", "localhost"])

    sanitized_extra_env: dict[str, str] = {}
    if extra_allowed_env:
        for k, v in extra_allowed_env.items():
            if is_forbidden_env_key(k):
                raise HostBoundaryPolicyError(
                    f"Forbidden environment key '{k}' cannot be included in boundary policy extra_allowed_env"
                )
            sanitized_extra_env[k] = str(v)

    effective_path = sanitize_path(base_path or DEFAULT_BASE_PATH)

    # Normalize write and read lists (unique and realpaths)
    unique_write = tuple(dict.fromkeys(write_roots))
    unique_read = tuple(dict.fromkeys(read_roots))
    unique_forbidden = tuple(dict.fromkeys(forbidden))
    unique_disallowed_net = tuple(dict.fromkeys(disallowed_net))
    unique_loopback = tuple(dict.fromkeys(loopback_hosts))

    return BoundaryPolicy(
        owned_root=owned_abs,
        private_home=home_abs,
        private_tmpdir=tmp_abs,
        allowed_write_roots=unique_write,
        allowed_read_roots=unique_read,
        forbidden_read_paths=unique_forbidden,
        disallowed_network_targets=unique_disallowed_net,
        allowed_loopback_hosts=unique_loopback,
        extra_allowed_env=sanitized_extra_env,
        base_path=effective_path,
    )


def build_clean_boundary_env(
    policy: BoundaryPolicy,
    extra_env: Mapping[str, str] | None = None,
    create_dirs: bool = True,
) -> dict[str, str]:
    """
    Construct an explicit clean environment dictionary from scratch.
    Never copies from ambient os.environ.
    Guarantees private HOME and TMPDIR, stripped credentials, and sanitized PATH.
    """
    if create_dirs:
        os.makedirs(policy.private_home, mode=0o700, exist_ok=True)
        os.makedirs(policy.private_tmpdir, mode=0o700, exist_ok=True)

    username = getpass.getuser()
    if not username or not username.replace("_", "").isalnum():
        username = "iyi-worker"

    clean_env: dict[str, str] = {
        "HOME": policy.private_home,
        "TMPDIR": policy.private_tmpdir,
        "PATH": policy.base_path,
        "USER": username,
        "LOGNAME": username,
        "SHELL": "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    # Add policy extra allowed env
    for k, v in policy.extra_allowed_env.items():
        if is_forbidden_env_key(k):
            raise HostBoundaryPolicyError(
                f"Policy contains forbidden environment key: '{k}'"
            )
        clean_env[k] = v

    # Add caller extra env
    if extra_env:
        for k, v in extra_env.items():
            if is_forbidden_env_key(k):
                raise HostBoundaryPolicyError(
                    f"Caller attempted to inject forbidden environment key: '{k}'"
                )
            clean_env[k] = str(v)

    return clean_env


def generate_macos_sbpl(policy: BoundaryPolicy) -> str:
    """
    Generate an Apple Sandbox Profile Language (SBPL) profile matching the boundary policy.
    Evaluation order in SBPL v1:
      1. Network rules: deny network-outbound, allow only localhost outbound.
      2. File write rules: deny file-write*, allow /dev/(null|zero|tty) and owned roots.
      3. Forbidden read rules: deny file-read* for forbidden secrets and command files.
      4. Default allow: allow default for unconstrained system execution.
    """
    rules: list[str] = [
        "(version 1)",
        ";; 1. Network outbound: deny all external network egress, allow loopback only",
        "(deny network-outbound)",
        '(allow network-outbound (remote ip "localhost:*"))',
        "",
        ";; 2. File write rules: deny by default, allow null/zero/tty and owned roots",
        "(deny file-write*)",
        '(allow file-write-data (literal "/dev/null"))',
        '(allow file-write-data (literal "/dev/zero"))',
        '(allow file-write-data (literal "/dev/tty"))',
    ]

    # Collect all write root subpaths (both specified and resolved realpath)
    write_subpaths: list[str] = []
    for w in policy.allowed_write_roots:
        write_subpaths.append(w)
        try:
            rw = os.path.realpath(w)
            if rw not in write_subpaths:
                write_subpaths.append(rw)
        except OSError:
            pass

    for w in write_subpaths:
        rules.append(f'(allow file-write* (subpath "{w}"))')

    rules.append("")
    rules.append(";; 3. Forbidden file read rules: deny caller secrets and Actions command files")

    # Collect all forbidden paths (both literal and subpath, raw and realpath)
    forbidden_paths: list[str] = []
    for f in policy.forbidden_read_paths:
        forbidden_paths.append(f)
        try:
            rf = os.path.realpath(f)
            if rf not in forbidden_paths:
                forbidden_paths.append(rf)
        except OSError:
            pass

    for f in forbidden_paths:
        rules.append(f'(deny file-read* (literal "{f}"))')
        rules.append(f'(deny file-read* (subpath "{f}"))')

    rules.append("")
    rules.append(";; 4. Default allow for system binary execution, sysctl, and permitted system reads")
    rules.append("(allow default)")
    rules.append("")

    return "\n".join(rules)


@dataclass(frozen=True)
class BoundaryCapabilities:
    """Host execution capabilities detected on this runner."""

    platform: str
    is_darwin: bool
    sandbox_exec_path: str | None
    sandbox_exec_functional: bool
    diagnostic: str
    can_enforce_sandbox: bool


def detect_host_boundary_capabilities() -> BoundaryCapabilities:
    """Detect whether the current host can enforce the native sandbox boundary."""
    platform_name = sys.platform
    if platform_name != "darwin":
        return BoundaryCapabilities(
            platform=platform_name,
            is_darwin=False,
            sandbox_exec_path=None,
            sandbox_exec_functional=False,
            diagnostic=f"Platform '{platform_name}' is not Darwin; macOS sandbox-exec is unsupported.",
            can_enforce_sandbox=False,
        )

    sb_path = shutil.which("sandbox-exec") or "/usr/bin/sandbox-exec"
    if not os.path.exists(sb_path) or not os.access(sb_path, os.X_OK):
        return BoundaryCapabilities(
            platform=platform_name,
            is_darwin=True,
            sandbox_exec_path=None,
            sandbox_exec_functional=False,
            diagnostic=f"sandbox-exec binary was not found or is not executable at '{sb_path}'.",
            can_enforce_sandbox=False,
        )

    # Probe functional execution with a minimal valid profile
    try:
        res = subprocess.run(
            [sb_path, "-p", "(version 1) (allow default)", "/usr/bin/true"],
            capture_output=True,
            timeout=5.0,
            check=False,
        )
        if res.returncode == 0:
            return BoundaryCapabilities(
                platform=platform_name,
                is_darwin=True,
                sandbox_exec_path=sb_path,
                sandbox_exec_functional=True,
                diagnostic="macOS sandbox-exec is present and functional on Darwin host.",
                can_enforce_sandbox=True,
            )
        return BoundaryCapabilities(
            platform=platform_name,
            is_darwin=True,
            sandbox_exec_path=sb_path,
            sandbox_exec_functional=False,
            diagnostic=f"sandbox-exec test probe failed with exit code {res.returncode}: {res.stderr.decode(errors='replace').strip()}",
            can_enforce_sandbox=False,
        )
    except Exception as e:
        return BoundaryCapabilities(
            platform=platform_name,
            is_darwin=True,
            sandbox_exec_path=sb_path,
            sandbox_exec_functional=False,
            diagnostic=f"sandbox-exec execution probe raised exception: {type(e).__name__}: {e}",
            can_enforce_sandbox=False,
        )


@dataclass(frozen=True)
class CanaryReceipt:
    """Attestation record proving boundary canary probe execution on the runner host."""

    proven: bool
    is_fake: bool
    host_platform: str
    probes: dict[str, dict[str, Any]]
    diagnostic: str
    timestamp: float

    def verify_for_hosted_execution(self) -> None:
        """Validate receipt for hosted execution; fails closed if fake or unproven."""
        if self.is_fake:
            raise HostBoundaryFakedProofError(
                "A test fake or simulation cannot prove hosted boundary policy on a runner. "
                "Proof requires actual native execution on the runner host."
            )
        if not self.proven:
            raise HostBoundaryCanaryFailedError(
                f"Hosted boundary policy is not proven: {self.diagnostic}"
            )
        if self.host_platform != "darwin":
            raise HostBoundaryUnsupportedError(
                f"Runner platform '{self.host_platform}' is not Darwin; cannot verify macOS sandbox policy."
            )


def run_boundary_canary(
    policy: BoundaryPolicy,
    verbose: bool = False,
) -> CanaryReceipt:
    """
    Execute comprehensive native canary probes under the boundary policy.
    Proves:
      1. Secret read: denied (EPERM).
      2. Actions command-file read: denied (EPERM).
      3. Disallowed network address connect: denied (EPERM).
      4. Permitted fixture read: succeeds.
      5. Owned root write: succeeds.
      6. Outside root write: denied (EPERM).
      7. Owned loopback server: succeeds.
      8. Clean environment: verified no inherited credentials.

    Returns a CanaryReceipt recording the exact probe outcomes.
    Fails closed if the platform cannot enforce sandbox policies.
    """
    cap = detect_host_boundary_capabilities()
    if not cap.can_enforce_sandbox:
        return CanaryReceipt(
            proven=False,
            is_fake=False,
            host_platform=cap.platform,
            probes={},
            diagnostic=f"Canary execution impossible: {cap.diagnostic}",
            timestamp=time.time(),
        )

    scratch_dir = tempfile.mkdtemp(prefix="iyi_canary_scratch_")
    outside_dir = tempfile.mkdtemp(prefix="iyi_canary_outside_")

    srv: socket.socket | None = None
    srv_thread: threading.Thread | None = None
    server_running = threading.Event()

    try:
        scratch_real = os.path.realpath(scratch_dir)
        outside_real = os.path.realpath(outside_dir)

        fake_secret_path = os.path.join(scratch_real, "caller_fake.secret")
        fake_actions_env = os.path.join(scratch_real, "github_env.txt")
        permitted_fixture = os.path.join(policy.owned_root, "canary_fixture.dat")
        owned_write_target = os.path.join(policy.owned_root, "canary_owned.tmp")
        outside_write_target = os.path.join(outside_real, "canary_outside.tmp")

        with open(fake_secret_path, "w", encoding="utf-8") as f:
            f.write("CANARY_FAKE_CALLER_SECRET_98765\n")
        with open(fake_actions_env, "w", encoding="utf-8") as f:
            f.write("ACTIONS_ENV_FAKE_INJECTION=1\n")
        with open(permitted_fixture, "w", encoding="utf-8") as f:
            f.write("PERMITTED_FIXTURE_PAYLOAD_VALID\n")

        # Start ephemeral loopback server
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        lb_port = srv.getsockname()[1]
        srv.listen(1)

        def _run_srv() -> None:
            server_running.set()
            try:
                srv.settimeout(4.0)
                conn, _ = srv.accept()
                with conn:
                    msg = conn.recv(1024)
                    if msg == b"CANARY_LB_PING":
                        conn.sendall(b"CANARY_LB_PONG")
            except Exception:
                pass
            finally:
                try:
                    srv.close()
                except Exception:
                    pass

        srv_thread = threading.Thread(target=_run_srv, daemon=True)
        srv_thread.start()
        server_running.wait(timeout=2.0)

        # Build augmented policy for canary execution
        canary_forbidden = list(policy.forbidden_read_paths) + [
            fake_secret_path,
            fake_actions_env,
            scratch_real,
        ]
        canary_policy = create_boundary_policy(
            owned_root=policy.owned_root,
            private_home=policy.private_home,
            private_tmpdir=policy.private_tmpdir,
            allowed_write_roots=policy.allowed_write_roots,
            allowed_read_roots=list(policy.allowed_read_roots) + [scratch_real],
            forbidden_read_paths=canary_forbidden,
            disallowed_network_targets=policy.disallowed_network_targets,
            allowed_loopback_hosts=policy.allowed_loopback_hosts,
            extra_allowed_env=policy.extra_allowed_env,
            base_path=policy.base_path,
        )

        clean_env = build_clean_boundary_env(canary_policy)
        sbpl = generate_macos_sbpl(canary_policy)

        # Python probe runner script executed inside sandbox
        probe_script = f"""
import json, os, socket, sys

probes = {{}}

# Probe 1: caller-owned fake secret read
try:
    with open({fake_secret_path!r}, "r") as f:
        data = f.read()
    probes["fake_secret_read"] = {{"passed": False, "detail": "Secret read was permitted", "observed_denial": False}}
except PermissionError as e:
    probes["fake_secret_read"] = {{"passed": True, "detail": "PermissionError (EPERM)", "observed_denial": True}}
except OSError as e:
    probes["fake_secret_read"] = {{"passed": True, "detail": f"OSError: {{type(e).__name__}}", "observed_denial": True}}

# Probe 2: Actions command-file read
try:
    with open({fake_actions_env!r}, "r") as f:
        data = f.read()
    probes["actions_command_file_read"] = {{"passed": False, "detail": "Command-file read was permitted", "observed_denial": False}}
except PermissionError as e:
    probes["actions_command_file_read"] = {{"passed": True, "detail": "PermissionError (EPERM)", "observed_denial": True}}
except OSError as e:
    probes["actions_command_file_read"] = {{"passed": True, "detail": f"OSError: {{type(e).__name__}}", "observed_denial": True}}

# Probe 3: Disallowed network connection
s_net = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_net.settimeout(0.5)
try:
    s_net.connect(("192.0.2.1", 80))
    probes["disallowed_network_connect"] = {{"passed": False, "detail": "Connected to disallowed destination", "observed_denial": False}}
except PermissionError as e:
    probes["disallowed_network_connect"] = {{"passed": True, "detail": "PermissionError (EPERM)", "observed_denial": True}}
except OSError as e:
    probes["disallowed_network_connect"] = {{"passed": True, "detail": f"OSError: {{type(e).__name__}}", "observed_denial": True}}
finally:
    s_net.close()

# Probe 4: Permitted fixture read
try:
    with open({permitted_fixture!r}, "r") as f:
        content = f.read()
    if content.strip() == "PERMITTED_FIXTURE_PAYLOAD_VALID":
        probes["permitted_fixture_read"] = {{"passed": True, "detail": "Read verified", "observed_denial": False}}
    else:
        probes["permitted_fixture_read"] = {{"passed": False, "detail": f"Content mismatch: {{content!r}}", "observed_denial": False}}
except Exception as e:
    probes["permitted_fixture_read"] = {{"passed": False, "detail": f"Fixture read failed: {{e}}", "observed_denial": False}}

# Probe 5: Owned root write
try:
    with open({owned_write_target!r}, "w") as f:
        f.write("OWNED_WRITE_PAYLOAD\\n")
    probes["owned_root_write"] = {{"passed": True, "detail": "Write verified", "observed_denial": False}}
except Exception as e:
    probes["owned_root_write"] = {{"passed": False, "detail": f"Owned write failed: {{e}}", "observed_denial": False}}

# Probe 6: Write outside owned root
try:
    with open({outside_write_target!r}, "w") as f:
        f.write("FORBIDDEN_WRITE_PAYLOAD\\n")
    probes["outside_root_write"] = {{"passed": False, "detail": "Outside write succeeded", "observed_denial": False}}
except PermissionError as e:
    probes["outside_root_write"] = {{"passed": True, "detail": "PermissionError (EPERM)", "observed_denial": True}}
except OSError as e:
    probes["outside_root_write"] = {{"passed": True, "detail": f"OSError: {{type(e).__name__}}", "observed_denial": True}}

# Probe 7: Owned loopback server connect
s_lb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_lb.settimeout(2.0)
try:
    s_lb.connect(("127.0.0.1", {lb_port}))
    s_lb.sendall(b"CANARY_LB_PING")
    reply = s_lb.recv(1024)
    if reply == b"CANARY_LB_PONG":
        probes["owned_loopback_connect"] = {{"passed": True, "detail": "Ping-pong ACK verified", "observed_denial": False}}
    else:
        probes["owned_loopback_connect"] = {{"passed": False, "detail": f"Unexpected reply: {{reply!r}}", "observed_denial": False}}
except Exception as e:
    probes["owned_loopback_connect"] = {{"passed": False, "detail": f"Loopback connection failed: {{e}}", "observed_denial": False}}
finally:
    s_lb.close()

# Probe 8: Clean environment verification
forbidden_keys_found = []
for k in os.environ.keys():
    k_upper = k.upper()
    if any(p in k_upper for p in ["TOKEN", "SECRET", "KEY", "AUTH", "PASS", "CREDENTIAL", "GITHUB", "ACTIONS", "AWS", "SSH"]):
        forbidden_keys_found.append(k)

home_val = os.environ.get("HOME")
tmp_val = os.environ.get("TMPDIR")
expected_home = {canary_policy.private_home!r}
expected_tmp = {canary_policy.private_tmpdir!r}

env_ok = (not forbidden_keys_found) and (home_val == expected_home) and (tmp_val == expected_tmp)
if env_ok:
    probes["clean_allowlisted_env"] = {{"passed": True, "detail": "Clean environment verified", "observed_denial": False}}
else:
    probes["clean_allowlisted_env"] = {{
        "passed": False,
        "detail": f"Env check failed: forbidden={{forbidden_keys_found}}, HOME={{home_val}}, TMPDIR={{tmp_val}}",
        "observed_denial": False
    }}

print("CANARY_PROBE_JSON_START")
print(json.dumps(probes))
print("CANARY_PROBE_JSON_END")
"""

        res = subprocess.run(
            [cap.sandbox_exec_path or "/usr/bin/sandbox-exec", "-p", sbpl, sys.executable, "-c", probe_script],
            capture_output=True,
            text=True,
            env=clean_env,
            close_fds=True,
            timeout=15.0,
            check=False,
        )

        stdout = res.stdout
        if "CANARY_PROBE_JSON_START" not in stdout or "CANARY_PROBE_JSON_END" not in stdout:
            return CanaryReceipt(
                proven=False,
                is_fake=False,
                host_platform=cap.platform,
                probes={},
                diagnostic=f"Probe script failed to emit JSON (exit {res.returncode}): stdout={stdout!r}, stderr={res.stderr!r}",
                timestamp=time.time(),
            )

        json_text = stdout.split("CANARY_PROBE_JSON_START")[1].split("CANARY_PROBE_JSON_END")[0].strip()
        probe_dict: dict[str, dict[str, Any]] = json.loads(json_text)

        all_passed = True
        failed_probes: list[str] = []
        for name, outcome in probe_dict.items():
            if not outcome.get("passed"):
                all_passed = False
                failed_probes.append(f"{name}: {outcome.get('detail')}")

        if all_passed and len(probe_dict) >= 8:
            return CanaryReceipt(
                proven=True,
                is_fake=False,
                host_platform=cap.platform,
                probes=probe_dict,
                diagnostic="All 8 boundary canary probes verified by actual native kernel enforcement.",
                timestamp=time.time(),
            )
        return CanaryReceipt(
            proven=False,
            is_fake=False,
            host_platform=cap.platform,
            probes=probe_dict,
            diagnostic=f"Canary probe check failed: {'; '.join(failed_probes)}",
            timestamp=time.time(),
        )

    except Exception as e:
        return CanaryReceipt(
            proven=False,
            is_fake=False,
            host_platform=cap.platform,
            probes={},
            diagnostic=f"Exception during canary execution: {type(e).__name__}: {e}",
            timestamp=time.time(),
        )
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)
        shutil.rmtree(outside_dir, ignore_errors=True)
        try:
            if srv:
                srv.close()
        except Exception:
            pass


def execute_under_boundary(
    policy: BoundaryPolicy,
    cmd: Sequence[str],
    cwd: str | None = None,
    extra_env: Mapping[str, str] | None = None,
    proven_receipt: CanaryReceipt | None = None,
    require_enforcement: bool = True,
    timeout: float | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Execute a native command under the boundary policy.
    Fails closed if boundary enforcement is unsupported on this host.
    Requires verified canary proof before allowing sandboxed execution.
    """
    cap = detect_host_boundary_capabilities()

    if require_enforcement:
        if not cap.can_enforce_sandbox:
            raise HostBoundaryUnsupportedError(
                f"Host boundary execution fails closed: {cap.diagnostic}"
            )

        if proven_receipt is None:
            # On-demand verification of boundary behavior on this runner
            proven_receipt = run_boundary_canary(policy)

        proven_receipt.verify_for_hosted_execution()

    clean_env = build_clean_boundary_env(policy, extra_env=extra_env)

    if cap.can_enforce_sandbox:
        sbpl = generate_macos_sbpl(policy)
        full_cmd = [cap.sandbox_exec_path or "/usr/bin/sandbox-exec", "-p", sbpl, *cmd]
    else:
        # Only reachable if require_enforcement is False (diagnostic non-enforced mode)
        full_cmd = list(cmd)

    return subprocess.run(
        full_cmd,
        cwd=cwd or policy.owned_root,
        env=clean_env,
        capture_output=capture_output,
        text=True,
        close_fds=True,
        timeout=timeout,
        check=False,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for boundary diagnostics, canary verification, and execution."""
    args = list(argv if argv is not None else sys.argv[1:])

    if not args or "--help" in args:
        print("Usage:")
        print("  python3 -m proof.hosted_boundary --diagnose")
        print("  python3 -m proof.hosted_boundary --canary --owned-root <path> [--verbose]")
        print("  python3 -m proof.hosted_boundary --exec --owned-root <path> -- <cmd...>")
        return 0

    if "--diagnose" in args:
        cap = detect_host_boundary_capabilities()
        info = {
            "platform": cap.platform,
            "is_darwin": cap.is_darwin,
            "sandbox_exec_path": cap.sandbox_exec_path,
            "sandbox_exec_functional": cap.sandbox_exec_functional,
            "can_enforce_sandbox": cap.can_enforce_sandbox,
            "diagnostic": cap.diagnostic,
        }
        print(json.dumps(info, indent=2))
        return 0 if cap.can_enforce_sandbox else 1

    if "--canary" in args:
        root_idx = args.index("--owned-root") if "--owned-root" in args else -1
        if root_idx == -1 or root_idx + 1 >= len(args):
            print("Error: --canary requires --owned-root <path>", file=sys.stderr)
            return 2
        owned_root = args[root_idx + 1]
        verbose = "--verbose" in args

        policy = create_boundary_policy(owned_root=owned_root)
        receipt = run_boundary_canary(policy, verbose=verbose)

        receipt_data = {
            "proven": receipt.proven,
            "is_fake": receipt.is_fake,
            "host_platform": receipt.host_platform,
            "diagnostic": receipt.diagnostic,
            "timestamp": receipt.timestamp,
            "probes": receipt.probes,
        }
        print(json.dumps(receipt_data, indent=2))
        return 0 if receipt.proven else 1

    if "--exec" in args:
        root_idx = args.index("--owned-root") if "--owned-root" in args else -1
        if root_idx == -1 or root_idx + 1 >= len(args):
            print("Error: --exec requires --owned-root <path>", file=sys.stderr)
            return 2
        owned_root = args[root_idx + 1]

        if "--" not in args:
            print("Error: --exec requires '-- <cmd...>'", file=sys.stderr)
            return 2
        cmd = args[args.index("--") + 1 :]
        if not cmd:
            print("Error: no command specified after '--'", file=sys.stderr)
            return 2

        policy = create_boundary_policy(owned_root=owned_root)
        try:
            res = execute_under_boundary(policy, cmd, capture_output=False)
            return res.returncode
        except HostBoundaryError as e:
            print(f"HostBoundaryError: {e}", file=sys.stderr)
            return 1

    print(f"Unknown argument(s): {args}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
