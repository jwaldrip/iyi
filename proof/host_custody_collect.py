"""Pure custody evidence consistency checks, not PID 1 attestation.

These checks consume observations only. They do not establish who made them,
release a process, read files, contact the bus, or grant runtime authority.
A production collector must obtain every value independently from protected
resources and qualify the system bus and descriptor transport first.
"""
import hashlib
import json
import re

from host_custody_systemd import CustodyRefused, _UNIT


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OWNER = re.compile(r":1\.[0-9]+\Z")
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_OBJECT = re.compile(r"/org/freedesktop/systemd1/unit/[A-Za-z0-9_]+\Z")
_LAUNCH = frozenset({"subject_digest", "snapshot_digest", "boot_id", "manager_owner", "manager_uid", "manager_pid", "unit_name", "unit_object", "invocation_id", "observer_uid", "observer_gid", "collector_uid", "payload_uid", "effective_properties_digest", "main_pid", "exec_main_pid", "cgroup", "start_monotonic", "control_descriptor"})
_TERMINAL = frozenset({"subject_digest", "snapshot_digest", "boot_id", "manager_owner", "unit_name", "unit_object", "invocation_id", "exec_main_pid", "start_monotonic", "exit_monotonic", "exec_main_code", "exec_main_status", "result", "n_restarts", "outputs", "launch_digest", "export"})
_OUTPUT = frozenset({"device", "inode", "uid", "gid", "mode", "nlink", "size", "sha256"})
_EXPORT = frozenset({"identity", "size", "sha256", "readback_sha256"})


def _closed(value, keys):
    return type(value) is dict and set(value) == keys


def _integer(value, low=0, high=2**63 - 1):
    return type(value) is int and low <= value <= high


def _match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _digest(value):
    return _match(_HEX, value)


def canonical_digest(record):
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(b"LaunchBindingV1\0" + encoded).hexdigest()


def manager_identity(name_owner, owner_uid, owner_pid):
    """Validate observed bus owner credentials, without authenticating them."""
    if not _match(_OWNER, name_owner) or type(owner_uid) is not int or owner_uid != 0 or type(owner_pid) is not int or owner_pid != 1:
        raise CustodyRefused("manager is not the PID 1 root bus owner")


def validate_launch(launch, expected_subject, expected_snapshot, expected_properties, manager):
    if not _closed(launch, _LAUNCH) or not _closed(manager, {"owner", "uid", "pid"}):
        raise CustodyRefused("missing or extra launch identity")
    manager_identity(manager["owner"], manager["uid"], manager["pid"])
    if (not all(_digest(v) for v in (expected_subject, expected_snapshot, expected_properties)) or
        launch["subject_digest"] != expected_subject or launch["snapshot_digest"] != expected_snapshot or
        launch["effective_properties_digest"] != expected_properties or
        not _match(_BOOT, launch["boot_id"]) or launch["manager_owner"] != manager["owner"] or
        type(launch["manager_uid"]) is not int or launch["manager_uid"] != 0 or
        type(launch["manager_pid"]) is not int or launch["manager_pid"] != 1 or
        not _match(_UNIT, launch["unit_name"]) or not _match(_OBJECT, launch["unit_object"]) or
        type(launch["invocation_id"]) is not str or re.fullmatch(r"[0-9a-f]{32}", launch["invocation_id"]) is None or
        launch["invocation_id"] == "0" * 32):
        raise CustodyRefused("invalid launch provenance")
    if _UNIT.fullmatch(launch["unit_name"]).group(3) != expected_subject:
        raise CustodyRefused("unit is not bound to subject")
    ids = [launch[k] for k in ("observer_uid", "observer_gid", "collector_uid", "payload_uid")]
    if not all(_integer(v, 1, 2**32 - 2) for v in ids) or len({ids[0], ids[2], ids[3]}) != 3:
        raise CustodyRefused("observer, collector and payload identities must be distinct and nonroot")
    if (not _integer(launch["main_pid"], 2, 2**32 - 1) or launch["main_pid"] != launch["exec_main_pid"] or
        type(launch["exec_main_pid"]) is not int or not _integer(launch["start_monotonic"], 1) or
        type(launch["cgroup"]) is not str or not launch["cgroup"].startswith("/") or
        len(launch["cgroup"]) > 4096 or ".." in launch["cgroup"].split("/") or
        launch["control_descriptor"] != {"kind": "pipe", "direction": "collector-to-observer", "inherited": True} or
        type(launch["control_descriptor"]) is not dict or type(launch["control_descriptor"].get("inherited")) is not bool):
        raise CustodyRefused("missing live launch or private barrier binding")


def validate_terminal(launch, terminal, manager, output_bytes, export_bytes, output_limit, output_total_limit, export_limit):
    """Check independent observations against a *previously validated* launch.

    Successful return means consistency only, never strict eligibility. The
    caller must run validate_launch against the authenticated live observation.
    """
    if not _closed(launch, _LAUNCH) or not _closed(terminal, _TERMINAL) or not _closed(manager, {"owner", "uid", "pid"}):
        raise CustodyRefused("missing terminal evidence")
    validate_launch(launch, launch["subject_digest"], launch["snapshot_digest"], launch["effective_properties_digest"], manager)
    manager_identity(manager["owner"], manager["uid"], manager["pid"])
    if manager["owner"] != launch["manager_owner"]:
        raise CustodyRefused("manager owner changed")
    for key in ("subject_digest", "snapshot_digest", "boot_id", "manager_owner", "unit_name", "unit_object", "invocation_id", "exec_main_pid", "start_monotonic"):
        if type(terminal[key]) is not type(launch[key]) or terminal[key] != launch[key]:
            raise CustodyRefused("terminal belongs to another launch")
    if (terminal["launch_digest"] != canonical_digest(launch) or
        not _integer(terminal["exit_monotonic"], launch["start_monotonic"] + 1) or
        type(terminal["exec_main_code"]) is not int or terminal["exec_main_code"] != 1 or
        type(terminal["exec_main_status"]) is not int or terminal["exec_main_status"] != 0 or
        terminal["result"] != "success" or type(terminal["n_restarts"]) is not int or terminal["n_restarts"] != 0):
        raise CustodyRefused("PID 1 did not record one normal zero exit")
    if not _integer(output_limit, 1) or not _integer(output_total_limit, 1) or not _integer(export_limit, 1):
        raise CustodyRefused("finite output limits required")
    if not _closed(terminal["outputs"], {"stdout", "stderr"}) or not _closed(output_bytes, {"stdout", "stderr"}):
        raise CustodyRefused("both output files are required")
    if any(type(data) is not bytes for data in output_bytes.values()) or sum(map(len, output_bytes.values())) > output_total_limit:
        raise CustodyRefused("total diagnostic output exceeds its bound")
    identities = set()
    for role in ("stdout", "stderr"):
        item, data = terminal["outputs"][role], output_bytes[role]
        if (not _closed(item, _OUTPUT) or type(data) is not bytes or len(data) > output_limit or
            not _integer(item["device"]) or not _integer(item["inode"], 1) or
            item["uid"] != launch["collector_uid"] or type(item["uid"]) is not int or
            not _integer(item["gid"]) or type(item["mode"]) is not int or item["mode"] != 0o600 or
            type(item["nlink"]) is not int or item["nlink"] != 1 or
            type(item["size"]) is not int or item["size"] != len(data) or
            not _digest(item["sha256"]) or hashlib.sha256(data).hexdigest() != item["sha256"]):
            raise CustodyRefused("output identity, limit or bytes do not match")
        identity = (item["device"], item["inode"])
        if identity in identities:
            raise CustodyRefused("output files share an inode")
        identities.add(identity)
    export = terminal["export"]
    if (not _closed(export, _EXPORT) or type(export_bytes) is not bytes or len(export_bytes) > export_limit or
        type(export["identity"]) is not str or not 1 <= len(export["identity"]) <= 512 or
        type(export["size"]) is not int or export["size"] != len(export_bytes) or
        not _digest(export["sha256"]) or export["sha256"] != export["readback_sha256"] or
        hashlib.sha256(export_bytes).hexdigest() != export["readback_sha256"]):
        raise CustodyRefused("export readback is absent or mismatched")
    return {"consistent_unattested": True, "strict_eligible": False}
