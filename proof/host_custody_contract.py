"""Offline consistency checks for proposed custody records, never an admission gate.

All inputs, including claims about authentication and PID 1, are untrusted data.
No result establishes authenticity, user authorization, or runtime eligibility.
"""

from dataclasses import dataclass
from enum import Enum
import re
import hashlib
import json


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

# These records are data contracts, not attestations. A digest identifies typed
# canonical bytes; it does not authenticate their author or their observations.
ARTIFACT_BASENAMES = {
    "observer": "observer", "bpf_object": "observer.bpf.o",
    "dependencies": "dependencies", "recipe": "recipe", "exec_config": "exec-config",
}
LIMIT_FIELDS = frozenset({
    "staging_temp_bytes", "diagnostic_file_bytes", "diagnostic_total_bytes",
    "export_bytes", "manager_response_bytes", "record_bytes", "descriptor_count",
    "collector_memory_bytes", "staging_deadline_ms", "observer_deadline_ms",
    "manager_query_deadline_ms", "finalization_deadline_ms", "launch_attempts",
    "collection_attempts",
})
_SUBJECT_FIELDS = frozenset({
    "schema", "repository", "recipe_revision", "source_revision", "workflow_path",
    "workflow_blob", "run", "attempt", "job", "branch", "trust_model", "profile",
    "build_artifact_id", "build_manifest_digest", "artifacts", "loader_policy_digest",
    "libc_identity_digest", "loader_config_policy_digest", "collector_source_digest",
    "collector_config_digest", "unit_template_digest", "effective_property_policy_digest",
    "output_schema_digest", "limits", "payload_cage_policy_digest", "strict_eligible",
})
_SUBJECT_DIGESTS = frozenset({
    "build_manifest_digest", "loader_policy_digest", "libc_identity_digest",
    "loader_config_policy_digest", "collector_source_digest", "collector_config_digest",
    "unit_template_digest", "effective_property_policy_digest", "output_schema_digest",
    "payload_cage_policy_digest",
})


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _closed(value, fields, label):
    _require(_record(value, fields), f"{label}: missing or unknown fields")


def _positive(value):
    return _number(value, 1)


def validate_subject(subject):
    """Validate the closed approval subject; no values here confer authority."""
    _closed(subject, _SUBJECT_FIELDS, "subject")
    _require(subject["schema"] == "CustodySubjectV1", "subject schema")
    for key in ("repository", "job", "branch", "build_artifact_id"):
        _require(_id(subject[key]), f"invalid {key}")
    for key in ("recipe_revision", "source_revision", "workflow_blob"):
        value = subject[key]
        _require(type(value) is str and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value)
                 is not None, f"invalid git object id: {key}")
    path = subject["workflow_path"]
    _require(type(path) is str and path.startswith(".github/workflows/") and
             _id(path[1:]) and all(part not in ("", ".", "..") for part in path.split("/")),
             "invalid registered workflow path")
    _require(_positive(subject["run"]) and _positive(subject["attempt"]), "run identity")
    _require(subject["trust_model"] == "trusted-host-isolated-payload-v1", "trust model")
    _require(subject["profile"] in ("custody-fixture", "bpf-canary"), "profile")
    _require(subject["strict_eligible"] is False, "strict eligibility forbidden")
    for key in _SUBJECT_DIGESTS:
        _require(_digest(subject[key]), f"invalid {key}")
    artifacts = subject["artifacts"]
    _closed(artifacts, _ROLES, "artifacts")
    for role, artifact in artifacts.items():
        _closed(artifact, {"size", "sha256", "file_type", "mode"}, role)
        _require(_positive(artifact["size"]) and _digest(artifact["sha256"]), "artifact bytes")
        _require(artifact["file_type"] == "regular", "artifact type")
        _require(type(artifact["mode"]) is int and artifact["mode"] ==
                 (0o555 if role == "observer" else 0o444), "artifact mode")
    limits = subject["limits"]
    _closed(limits, LIMIT_FIELDS, "limits")
    _require(all(_positive(v) for v in limits.values()), "limits must be finite positive integers")
    _require(limits["launch_attempts"] == 1 and limits["collection_attempts"] == 1,
             "one launch and collection, without retries")
    _require(limits["diagnostic_file_bytes"] <= limits["diagnostic_total_bytes"],
             "diagnostic limits inconsistent")


def _typed_digest(kind, value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
    return hashlib.sha256(kind.encode("ascii") + b"\0" + payload).hexdigest()


def subject_digest(subject):
    validate_subject(subject)
    return _typed_digest("CustodySubjectV1", subject)


def unit_name(subject):
    """The unit name is derived after hashing and is not part of the subject."""
    return f"iyi-custody-{subject['run']}-{subject['attempt']}-{subject_digest(subject)}.service"


def _metadata(value, label, directory=False):
    _closed(value, {"device", "inode", "uid", "gid", "mode", "nlink"}, label)
    _require(_number(value["device"]) and _positive(value["inode"]) and
             _number(value["uid"], 0, 0) and _number(value["gid"]) and
             _positive(value["nlink"]) and _number(value["mode"], 0, 0o7777), label)
    if directory:
        _require(value["mode"] == 0o700, "root directory must be private")


def validate_snapshot(subject, snapshot):
    _closed(snapshot, {"subject_digest", "directory", "artifacts", "utilities",
                       "all_verified_before_exposure", "no_retained_writers"}, "snapshot")
    _require(snapshot["subject_digest"] == subject_digest(subject), "snapshot subject mismatch")
    _metadata(snapshot["directory"], "directory", directory=True)
    _closed(snapshot["artifacts"], _ROLES, "snapshot artifacts")
    inodes = set()
    for role, artifact in snapshot["artifacts"].items():
        _closed(artifact, {"size", "sha256", "device", "inode", "uid", "gid", "mode", "nlink"}, role)
        meta = {k: artifact[k] for k in ("device", "inode", "uid", "gid", "mode", "nlink")}
        _metadata(meta, role)
        approved = subject["artifacts"][role]
        _require(all(artifact[k] == approved[k] and type(artifact[k]) is type(approved[k])
                     for k in ("size", "sha256", "mode")), "snapshot artifact mismatch")
        _require(artifact["nlink"] == 1, "snapshot link count")
        identity = (artifact["device"], artifact["inode"])
        _require(identity not in inodes, "snapshot inode reused")
        inodes.add(identity)
    utilities = snapshot["utilities"]
    _require(type(utilities) is list and 0 < len(utilities) <= _MAX_ITEMS, "utilities")
    for utility in utilities:
        _closed(utility, {"path", "sha256", "argv", "exit_code"}, "utility")
        _require(type(utility["path"]) is str and utility["path"].startswith("/") and
                 len(utility["path"]) <= _MAX_TEXT and _digest(utility["sha256"]), "utility identity")
        _require(type(utility["argv"]) is list and 0 < len(utility["argv"]) <= _MAX_ITEMS and
                 all(type(v) is str and len(v) <= _MAX_TEXT for v in utility["argv"]), "utility argv")
        _require(_number(utility["exit_code"], 0, 0), "utility failed")
    _require(snapshot["all_verified_before_exposure"] is True and
             snapshot["no_retained_writers"] is True, "snapshot custody incomplete")


def snapshot_digest(subject, snapshot):
    validate_snapshot(subject, snapshot)
    return _typed_digest("ProtectedSnapshotV1", snapshot)


def validate_launch(subject, snapshot, launch):
    fields = {"subject_digest", "snapshot_digest", "boot_id", "manager_owner", "manager_uid",
              "manager_pid", "unit_name", "unit_object", "invocation_id", "observer_uid",
              "observer_gid", "collector_uid", "payload_uid", "effective_properties_digest",
              "main_pid", "exec_main_pid", "cgroup", "start_monotonic", "control_descriptor"}
    _closed(launch, fields, "launch")
    _require(launch["subject_digest"] == subject_digest(subject) and
             launch["snapshot_digest"] == snapshot_digest(subject, snapshot), "launch digest mismatch")
    _require(launch["unit_name"] == unit_name(subject), "unit name mismatch")
    for key in ("boot_id", "invocation_id"):
        _require(_id(launch[key]), f"invalid {key}")
    _require(type(launch["manager_owner"]) is str and
             re.fullmatch(r":[0-9]+\.[0-9]+", launch["manager_owner"]) is not None and
             all(type(launch[k]) is str and launch[k].startswith("/") and _id(launch[k][1:])
                 for k in ("unit_object", "cgroup")), "manager/unit/cgroup identity")
    _require(_number(launch["manager_uid"], 0, 0) and _number(launch["manager_pid"], 1, 1),
             "manager is not PID 1 root")
    for key in ("observer_uid", "observer_gid", "collector_uid", "payload_uid", "main_pid",
                "exec_main_pid", "start_monotonic"):
        _require(_positive(launch[key]), f"invalid {key}")
    _require(len({launch["observer_uid"], launch["collector_uid"], launch["payload_uid"]}) == 3,
             "UIDs must differ")
    _require(launch["main_pid"] == launch["exec_main_pid"], "process mismatch")
    _require(_digest(launch["effective_properties_digest"]), "effective properties")
    control = launch["control_descriptor"]
    _closed(control, {"kind", "direction", "inherited"}, "control descriptor")
    _require(control["kind"] in ("pipe", "socketpair") and control["direction"] == "collector-to-observer"
             and control["inherited"] is True, "control descriptor")


def launch_digest(subject, snapshot, launch):
    validate_launch(subject, snapshot, launch)
    return _typed_digest("LaunchBindingV1", launch)


def validate_terminal(subject, snapshot, launch, terminal):
    fields = {"subject_digest", "snapshot_digest", "launch_digest", "boot_id", "manager_owner",
              "unit_name", "unit_object", "invocation_id", "exec_main_pid", "start_monotonic",
              "exit_monotonic", "exec_main_code", "exec_main_status", "result", "n_restarts",
              "outputs", "export"}
    _closed(terminal, fields, "terminal")
    _require(terminal["launch_digest"] == launch_digest(subject, snapshot, launch), "launch digest mismatch")
    for key in ("subject_digest", "snapshot_digest", "boot_id", "manager_owner", "unit_name",
                "unit_object", "invocation_id", "exec_main_pid", "start_monotonic"):
        _require(type(terminal[key]) is type(launch[key]) and terminal[key] == launch[key], f"{key} mismatch")
    _require(_positive(terminal["exit_monotonic"]) and
             terminal["exit_monotonic"] > launch["start_monotonic"], "terminal time")
    _require(type(terminal["exec_main_code"]) is int and terminal["exec_main_code"] == 1 and
             _number(terminal["exec_main_status"], 0, 0) and terminal["result"] == "success" and
             _number(terminal["n_restarts"], 0, 0), "terminal is not normal zero exit")
    _closed(terminal["outputs"], {"stdout", "stderr"}, "outputs")
    total = 0
    output_inodes = set()
    for output in terminal["outputs"].values():
        _closed(output, {"device", "inode", "uid", "gid", "mode", "nlink", "size", "sha256"}, "output")
        _require(_number(output["device"]) and _positive(output["inode"]) and
                 output["uid"] == launch["collector_uid"] and type(output["uid"]) is int and
                 _number(output["gid"]) and type(output["mode"]) is int and output["mode"] == 0o600 and
                 _number(output["nlink"], 1, 1) and _number(output["size"]) and
                 output["size"] <= subject["limits"]["diagnostic_file_bytes"] and
                 _digest(output["sha256"]), "output identity")
        identity = (output["device"], output["inode"])
        _require(identity not in output_inodes, "output inode reused")
        output_inodes.add(identity)
        total += output["size"]
    _require(total <= subject["limits"]["diagnostic_total_bytes"], "output total")
    export = terminal["export"]
    _closed(export, {"identity", "size", "sha256", "readback_sha256"}, "export")
    _require(_id(export["identity"]) and _number(export["size"]) and
             export["size"] <= subject["limits"]["export_bytes"] and
             _digest(export["sha256"]) and export["sha256"] == export["readback_sha256"], "export readback")
