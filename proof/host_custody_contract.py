"""Offline consistency checks for proposed custody records, never an admission gate.

All inputs, including claims about authentication and PID 1, are untrusted data.
No result establishes authenticity, user authorization, or runtime eligibility.
"""

from dataclasses import dataclass
from enum import Enum
import re


class Status(Enum):
    REFUSED = "refused"
    CONSISTENT_UNATTESTED = "consistent_unattested"


@dataclass(frozen=True)
class Assessment:
    status: Status
    reasons: tuple[str, ...]
    runtime_admission: bool = False
    authority_verified: bool = False
    user_authorization_verified: bool = False
    terminal_independently_attested: bool = False


# Upper bounds apply before traversing any attacker-controlled container.
_MAX_TEXT = 512
_MAX_ITEMS = 64
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}\Z")
_ROLES = frozenset({"observer", "bpf_object", "dependencies", "recipe", "exec_config"})


def _plain(value, depth=0):
    if depth > 2:
        return False
    if type(value) is dict:
        return (len(value) <= _MAX_ITEMS
                and all(type(k) is str and len(k) <= _MAX_TEXT
                        and _plain(v, depth + 1) for k, v in value.items()))
    if type(value) is str:
        return len(value) <= _MAX_TEXT
    if type(value) is int:
        return -(2**63) <= value <= 2**63 - 1
    return type(value) is bool


def _record(value, keys):
    return type(value) is dict and len(value) == len(keys) and set(value) == set(keys)


def _id(value):
    return type(value) is str and len(value) <= _MAX_TEXT and _ID.fullmatch(value) is not None


def _digest(value):
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _number(value, low=0, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def _true(value):
    return value is True


def _false(value):
    return value is False


def _artifacts(value):
    return (type(value) is dict and len(value) == len(_ROLES)
            and set(value) == _ROLES and all(_digest(v) for v in value.values()))


def assess(expected, inventory, protected_copy, terminal):
    """Check bounded structured claims. Even a consistent set is not trusted.

    The caller must supply ordinary built-in dicts and scalar values; missing,
    extra, malformed and contradictory fields refuse. No filesystem, process,
    cryptographic authentication, or live-system operation occurs here.
    """
    if not all(_plain(record) for record in (expected, inventory, protected_copy, terminal)):
        return Assessment(Status.REFUSED, ("input is not bounded plain data",))
    ek = {"workflow", "checkout", "run", "attempt", "boot_id", "unit", "invocation_id",
          "cgroup", "authority", "reviewer", "artifacts", "diagnostic_digest"}
    ik = {"workflow", "checkout", "run", "attempt", "boot_id", "manager_pid",
          "workload_uid", "observer_uid", "collector_uid", "hostile_host_user",
          "host_user_sudo", "host_user_docker_control", "bootstrap_before_hostile",
          "root_repo_code_executed", "strict_eligible", "load_attempted",
          "attach_attempted", "exec_identity_tested"}
    ck = {"workflow", "checkout", "run", "attempt", "boot_id", "artifacts",
          "fresh_inodes", "root_private", "source_bounded_regular_nofollow",
          "readback_verified", "readonly_exposed", "observer_separate_uid"}
    tk = {"workflow", "checkout", "run", "attempt", "boot_id", "unit", "invocation_id",
          "cgroup", "exec_config_digest", "manager_pid", "main_pid", "started_ns",
          "exited_ns", "exec_main_code", "exec_main_status", "result", "restarts",
          "diagnostics_complete", "diagnostic_digest", "diagnostic_readback_digest",
          "collector_protected", "manager_status_present"}
    if not all((_record(expected, ek), _record(inventory, ik),
                _record(protected_copy, ck), _record(terminal, tk))):
        return Assessment(Status.REFUSED, ("missing, extra, or malformed record fields",))

    reasons = []
    common = ("workflow", "checkout", "run", "attempt", "boot_id")
    for record in (expected, inventory, protected_copy, terminal):
        if (not all(_id(record[k]) for k in ("workflow", "checkout", "boot_id"))
                or not _number(record["run"], 1) or not _number(record["attempt"], 1)):
            reasons.append("invalid run identity")
        if any(type(record[k]) is not type(expected[k]) or record[k] != expected[k] for k in common):
            reasons.append("run identity mismatch")
    if (not all(_id(expected[k]) for k in ("unit", "invocation_id", "authority", "reviewer"))
            or type(expected["cgroup"]) is not str or not expected["cgroup"].startswith("/")
            or not _id(expected["cgroup"][1:])):
        reasons.append("missing or invalid external authority or invocation identity")
    if not _artifacts(expected["artifacts"]) or not _artifacts(protected_copy["artifacts"]):
        reasons.append("invalid approved or copied artifact identities")
    elif expected["artifacts"] != protected_copy["artifacts"]:
        reasons.append("protected copy differs from approved artifacts")
    if not _digest(expected["diagnostic_digest"]):
        reasons.append("invalid approved diagnostic digest")

    if not (_number(inventory["manager_pid"], 1, 1)
            and all(_number(inventory[k], 1, 2**31 - 1) for k in
                    ("workload_uid", "observer_uid", "collector_uid"))):
        reasons.append("missing or invalid manager or nonroot identity")
    elif len({inventory["workload_uid"], inventory["observer_uid"], inventory["collector_uid"]}) != 3:
        reasons.append("workload, observer and collector identities are not separate")
    for key in ("hostile_host_user", "host_user_sudo", "host_user_docker_control"):
        if type(inventory[key]) is not bool:
            reasons.append("unknown host authority")
    if (inventory["hostile_host_user"] is True and
            (inventory["host_user_sudo"] is not False or inventory["host_user_docker_control"] is not False)):
        reasons.append("hostile host user has or may have root-equivalent authority")
    if not _true(inventory["bootstrap_before_hostile"]) or not _false(inventory["root_repo_code_executed"]):
        reasons.append("bootstrap ordering or root repository-code ban not established")
    if not all(_false(inventory[k]) for k in ("strict_eligible", "load_attempted", "attach_attempted", "exec_identity_tested")):
        reasons.append("preflight must not claim eligibility or execution")
    if not all(_true(protected_copy[k]) for k in
               ("fresh_inodes", "root_private", "source_bounded_regular_nofollow", "readback_verified",
                "readonly_exposed", "observer_separate_uid")):
        reasons.append("protected copy custody claim incomplete")

    if any(type(terminal[k]) is not type(expected[k]) or terminal[k] != expected[k]
           for k in ("unit", "invocation_id", "cgroup")):
        reasons.append("terminal invocation identity mismatch")
    if (not _number(terminal["manager_pid"], 1, 1) or not _number(terminal["main_pid"], 1, 2**31 - 1)
            or not _number(terminal["started_ns"], 1) or not _number(terminal["exited_ns"], 1)
            or (type(terminal["started_ns"]) is int and type(terminal["exited_ns"]) is int
                and terminal["exited_ns"] <= terminal["started_ns"])):
        reasons.append("invalid manager, process or terminal timestamps")
    if (terminal["exec_main_code"] != "exited" or type(terminal["exec_main_code"]) is not str
            or not _number(terminal["exec_main_status"], 0, 0) or terminal["result"] != "success"
            or type(terminal["result"]) is not str or not _number(terminal["restarts"], 0, 0)
            or not _true(terminal["manager_status_present"])):
        reasons.append("manager terminal status missing or not a normal zero exit")
    if not all(_true(terminal[k]) for k in ("diagnostics_complete", "collector_protected")):
        reasons.append("terminal collection or diagnostics incomplete")
    if (not _digest(terminal["exec_config_digest"]) or not _artifacts(expected["artifacts"])
            or terminal["exec_config_digest"] != expected["artifacts"]["exec_config"]):
        reasons.append("terminal execution configuration mismatch")
    if (not _digest(terminal["diagnostic_digest"]) or not _digest(terminal["diagnostic_readback_digest"])
            or terminal["diagnostic_digest"] != expected["diagnostic_digest"]
            or terminal["diagnostic_readback_digest"] != expected["diagnostic_digest"]):
        reasons.append("diagnostic output or protected readback mismatch")
    if reasons:
        return Assessment(Status.REFUSED, tuple(dict.fromkeys(reasons)))
    return Assessment(Status.CONSISTENT_UNATTESTED,
                      ("claims are internally consistent only; authority, authorization and collector are unverified",))
