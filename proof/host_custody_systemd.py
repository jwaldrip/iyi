"""Offline policy compiler for the unqualified, capability-free custody unit.

This module does not contact systemd. Typed values are busctl JSON property
objects (``type`` and ``data``), not parsed ``systemctl`` display strings.
The real adapter, FD-store transport, platform qualification and authorization
are not present. Consequently the production entry point always refuses.
"""
import re
from pathlib import Path


class CustodyRefused(ValueError):
    pass


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_UNIT = re.compile(r"iyi-custody-([1-9][0-9]*)-([1-9][0-9]*)-([0-9a-f]{64})\.service\Z")


def unit_name(run, attempt, subject_digest):
    if (type(run) is not int or type(attempt) is not int or
            not 0 < run < 2**63 or not 0 < attempt < 2**63 or
            type(subject_digest) is not str or not _HEX.fullmatch(subject_digest)):
        raise CustodyRefused("invalid unit identity")
    return f"iyi-custody-{run}-{attempt}-{subject_digest}.service"


def _paths(name):
    if type(name) is not str or not _UNIT.fullmatch(name):
        raise CustodyRefused("invalid owned unit name")
    digest = _UNIT.fullmatch(name).group(3)
    root = f"/run/iyi-custody/{digest}"
    return digest, root, root + "/observer"


def render_unit(name):
    digest, root, observer = _paths(name)
    # This file is part of the source identity that must be approved; reading
    # it here is an offline compiler operation, not privileged staging.
    template = Path(__file__).with_name("host_observer.service.in").read_text(encoding="utf-8")
    try:
        return template.format(subject_digest=digest, output_dir=root, observer=observer)
    except (KeyError, ValueError, IndexError) as exc:
        raise CustodyRefused("invalid unit template") from exc
def _typed(signature, data):
    return {"type": signature, "data": [data]}


def expected_prestart_properties(name):
    """Exact projected properties; no assertion about an unqualified busctl.

    The real adapter must retrieve every one from PID 1, preserve signatures,
    and reject unavailable or additional policy-affecting properties.
    """
    _, root, observer = _paths(name)
    return {
        "Id": _typed("s", name),
        "LoadState": _typed("s", "loaded"),
        "ActiveState": _typed("s", "inactive"),
        "SubState": _typed("s", "dead"),
        "FragmentPath": _typed("s", "/run/systemd/system/" + name),
        "DropInPaths": _typed("as", []),
        "Type": _typed("s", "exec"),
        "DynamicUser": _typed("b", True),
        "User": _typed("s", ""),
        "Group": _typed("s", ""),
        "SupplementaryGroups": _typed("as", []),
        "Restart": _typed("s", "no"),
        "RemainAfterExit": _typed("b", True),
        "CollectMode": _typed("s", "inactive"),
        "NotifyAccess": _typed("s", "none"),
        "NoNewPrivileges": _typed("b", True),
        "PrivateUsers": _typed("b", False),
        "CapabilityBoundingSet": _typed("t", 0),
        "AmbientCapabilities": _typed("t", 0),
        "ExecStart": _typed("a(sasbttttuii)", [[observer, [observer], False, 0, 0, 0, 0, 0, 0, 0]]),
        "ExecStartPre": _typed("a(sasbttttuii)", []),
        "ExecStartPost": _typed("a(sasbttttuii)", []),
        "ExecStop": _typed("a(sasbttttuii)", []),
        "ExecStopPost": _typed("a(sasbttttuii)", []),
        "ExecReload": _typed("a(sasbttttuii)", []),
        "PIDFile": _typed("s", ""),
        "SuccessExitStatus": _typed("(aiai)", [[], []]),
        "RestartPreventExitStatus": _typed("(aiai)", [[], []]),
        "RestartForceExitStatus": _typed("(aiai)", [[], []]),
        "SuccessAction": _typed("s", "none"),
        "FailureAction": _typed("s", "none"),
        "StandardInput": _typed("s", "fd"),
        "StandardInputFileDescriptorName": _typed("s", "control"),
        "StandardOutput": _typed("s", "file"),
        "StandardOutputFile": _typed("s", root + "/stdout"),
        "StandardError": _typed("s", "file"),
        "StandardErrorFile": _typed("s", root + "/stderr"),
        "NRestarts": _typed("u", 0),
        "MainPID": _typed("u", 0),
        "ExecMainPID": _typed("u", 0),
    }


def _same_typed(actual, expected):
    # bool is a subclass of int in Python; recursively demand exact types.
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(_same_typed(actual[k], v) for k, v in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_same_typed(a, b) for a, b in zip(actual, expected))
    return actual == expected


def validate_prestart(name, properties):
    expected = expected_prestart_properties(name)
    if not _same_typed(properties, expected):
        raise CustodyRefused("effective unit properties are not the closed prestart policy")


def launch(subject):
    """Production boundary: authorization currently always refuses.

    Even if authorization is implemented later, never silently acquire a
    production backend: the reviewed native adapter and barrier are missing.
    """
    from host_custody_authorization import authorize_runtime
    authorize_runtime(subject)
    raise CustodyRefused("real manager adapter and private descriptor transport are unqualified")
