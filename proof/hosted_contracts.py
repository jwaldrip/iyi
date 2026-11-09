#!/usr/bin/env python3
"""
proof/hosted_contracts.py: Shared immutable contracts, closed schemas,
and canonical serialization for GitHub-hosted Linux strict proof controller (PR147).

Implements PlanControllerRepairs Sections 3.1-3.6 and ReviewControllerReadiness:
- Canonical duplicate-rejecting JSON with compact UTF-8 formatting and newline termination.
- Strict rejection of non-finite numbers (NaN, Inf, overflow exponents), booleans as numeric types,
  unsupported schemas, and unknown fields.
- Frozen, deeply immutable dataclasses:
  * ResourcePolicy (closed schema with all stage limits per 3.4)
  * CagePolicy (closed schema with complete isolation dimensions per 3.4)
  * EvidencePolicy (closed schema with 15 explicit evidence ceilings per 3.6)
  * QualificationRequirements (exact 144/144 RG2/RG2a, 0 exclusions/failures, 142+2, 117 siblings, Run2 28/116/144, frames, --crystal)
  * ExecutionSubject (immutable candidate execution subject)
  * ValidationRef (with optional platform artifact_digest and mandatory evidence member size/sha256)
  * StructuralIndependentReviewRef (structural review reference, explicitly separated from verified authority)
  * ProofManifest (v2: "iyi-hosted-linux-proof-v2", with cryptographic referential integrity verification in __post_init__)
  * ExecutionContext (with positive ASCII IDs, ISO timestamps, and immutable platform response digests)
  * CheckpointDescriptor (with exact outcome set, tuple commands, and immutable evidence maps)
- Validated constructors: every field, closed allowlist, and referential join is enforced in __post_init__,
  preventing constructor bypass.
- Preserves v1 personal approval comment prefix ("iyi-strict-linux-authorization-v1 sha256:").
- Preserves unconditional refusal paths:
  * Independent review unauthenticated refusal
  * Strict controller origin capture transport refusal
"""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import math
import re
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union


# Protocol Constants
SCHEMA_MANIFEST_V2 = "iyi-hosted-linux-proof-v2"
BACKEND_NAME = "github-hosted-linux-docker"
AUTH_COMMENT_PREFIX = "iyi-strict-linux-authorization-v1 sha256:"
AUTH_REFUSED_EXIT_CODE = 5


# Shared Error Hierarchy
class ContractError(Exception):
    """Base exception for hosted proof contract errors."""


class DuplicateKeyError(ContractError):
    """Raised when duplicate keys are encountered in JSON."""


class NonFiniteNumberError(ContractError):
    """Raised when NaN, Infinity, or out-of-range exponent is encountered."""


class TypeValidationError(ContractError):
    """Raised when field type or value format fails validation."""


class UnknownFieldError(ContractError):
    """Raised when an unrecognized field is encountered in a closed schema."""


class UnsupportedSchemaError(ContractError):
    """Raised when an unsupported schema identifier is encountered."""


class ReferenceIntegrityError(ContractError):
    """Raised when cross-record cryptographic digest bindings mismatch."""


class ValidationReferenceMismatch(ReferenceIntegrityError):
    """Raised when ValidationRef subject digest does not match ExecutionSubject."""


class ReviewReferenceMismatch(ReferenceIntegrityError):
    """Raised when StructuralIndependentReviewRef subject or validation digest does not match."""


class ReviewUnauthenticatedError(ContractError):
    """Raised when independent review lacks authenticated cryptographic attestation."""


class StrictHaltRefusal(ContractError):
    """Raised when strict execution is halted fail-closed by security policy."""


# Canonical JSON Serialization and Strict Deserialization
def canonical_json_bytes(data: Any) -> bytes:
    """
    Serialize data to deterministic, canonical UTF-8 bytes:
    - Sorted keys
    - Compact formatting without extra whitespace (separators=(',', ':'))
    - Newline-terminated
    - Reject non-finite floats (NaN, Inf, -Inf)
    """
    def _validate_finite(obj: Any) -> None:
        if isinstance(obj, float):
            if not math.isfinite(obj):
                raise NonFiniteNumberError(f"Non-finite float value forbidden: {obj}")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if not isinstance(k, str):
                    raise TypeValidationError(f"Dictionary keys must be strings, got {type(k).__name__}")
                _validate_finite(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _validate_finite(item)

    _validate_finite(data)
    encoded = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return (encoded + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def _unique_keys_pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate key detected in JSON: {key!r}")
        result[key] = value
    return result


def _strict_parse_float(val: str) -> float:
    f = float(val)
    if not math.isfinite(f):
        raise NonFiniteNumberError(f"Non-finite float forbidden in JSON: {val}")
    if "e" in val.lower():
        parts = val.lower().split("e", 1)
        try:
            exp_val = int(parts[1])
            if abs(exp_val) > 308:
                raise NonFiniteNumberError(f"Float exponent exceeds limits: {val}")
        except ValueError as exc:
            raise NonFiniteNumberError(f"Malformed exponent in JSON float: {val}") from exc
    return f


def parse_strict_json(
    raw: bytes | str,
    allowed_keys: Optional[Set[str]] = None,
) -> Any:
    """
    Parse JSON text with strict validation:
    - Reject duplicate keys
    - Reject non-finite numbers (NaN, Infinity, -Infinity, excessive exponents)
    - Optionally reject keys not in allowed_keys
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TypeValidationError(f"JSON input must be valid UTF-8: {exc}") from exc
    else:
        text = raw

    def _reject_constant(val: str) -> None:
        raise NonFiniteNumberError(f"Non-finite constant forbidden in JSON: {val!r}")

    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_keys_pairs_hook,
            parse_constant=_reject_constant,
            parse_float=_strict_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise TypeValidationError(f"Malformed JSON: {exc}") from exc

    if allowed_keys is not None and isinstance(data, dict):
        unknown = set(data.keys()) - allowed_keys
        if unknown:
            raise UnknownFieldError(f"Unknown fields detected in JSON: {sorted(unknown)}")

    return data


# Strict Type Validation Helpers
def require_str(val: Any, name: str, pattern: Optional[str] = None) -> str:
    if not isinstance(val, str):
        raise TypeValidationError(f"{name} must be a string, got {type(val).__name__}")
    if pattern and not re.fullmatch(pattern, val):
        raise TypeValidationError(f"{name} does not match required format {pattern}: {val!r}")
    return val


def require_ascii_str(val: Any, name: str, pattern: Optional[str] = None) -> str:
    s = require_str(val, name, pattern)
    if not s.isascii():
        raise TypeValidationError(f"{name} must contain only ASCII characters")
    return s


def require_sha256(val: Any, name: str) -> str:
    return require_ascii_str(val, name, r"^[0-9a-f]{64}$")


def require_sha1_or_commit(val: Any, name: str) -> str:
    return require_ascii_str(val, name, r"^[0-9a-f]{40}$")


def require_positive_ascii_id(val: Any, name: str) -> str:
    if type(val) is bool:
        raise TypeValidationError(f"{name} cannot be a boolean")
    if isinstance(val, int):
        if val <= 0:
            raise TypeValidationError(f"{name} must be a positive integer, got {val}")
        return str(val)
    if not isinstance(val, str):
        raise TypeValidationError(f"{name} must be an ASCII positive numeric string, got {type(val).__name__}")
    if not re.fullmatch(r"^[1-9][0-9]*$", val):
        raise TypeValidationError(f"{name} must be an ASCII positive numeric string matching ^[1-9][0-9]*$, got {val!r}")
    return val


def require_int(val: Any, name: str, min_val: Optional[int] = None) -> int:
    if type(val) is bool or not isinstance(val, int):
        raise TypeValidationError(f"{name} must be an integer, got {type(val).__name__}")
    if min_val is not None and val < min_val:
        raise TypeValidationError(f"{name} must be >= {min_val}, got {val}")
    return val


def require_float(val: Any, name: str) -> float:
    if type(val) is bool or not isinstance(val, (int, float)):
        raise TypeValidationError(f"{name} must be a numeric float, got {type(val).__name__}")
    f = float(val)
    if not math.isfinite(f):
        raise NonFiniteNumberError(f"{name} must be finite: {f}")
    return f


def require_bool(val: Any, name: str, expected: Optional[bool] = None) -> bool:
    if type(val) is not bool:
        raise TypeValidationError(f"{name} must be a boolean (True/False), got {type(val).__name__} ({val!r})")
    if expected is not None and val is not expected:
        raise TypeValidationError(f"{name} must be {expected}, got {val}")
    return val


def parse_utc_iso_timestamp(val: Any, name: str) -> datetime.datetime:
    """Parse and validate a UTC ISO-8601 timestamp ending in 'Z'."""
    s = require_ascii_str(val, name)
    if not re.fullmatch(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", s):
        raise TypeValidationError(f"{name} must match format YYYY-MM-DDTHH:MM:SS[.ffffff]Z, got {val!r}")
    iso_clean = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(iso_clean)
    except ValueError as exc:
        raise TypeValidationError(f"{name} has invalid calendar date/time ({val!r}): {exc}") from exc
    if dt.tzinfo is None or dt.utcoffset() != datetime.timedelta(0):
        raise TypeValidationError(f"{name} must be in UTC timezone (+00:00 or Z)")
    return dt


def require_iso_timestamp(val: Any, name: str) -> str:
    """Validate that val is a semantically valid UTC ISO-8601 timestamp ending in Z."""
    _ = parse_utc_iso_timestamp(val, name)
    return str(val)


def validate_timestamp_and_epoch(
    iso_ts: str,
    epoch_sec: float,
    name: str = "timestamp",
    max_drift_sec: float = 1.0,
) -> float:
    """
    Validate that an ISO timestamp and numeric epoch represent the same point in time.
    Epoch must be strictly positive and finite.
    """
    dt = parse_utc_iso_timestamp(iso_ts, f"{name}_iso")
    require_float(epoch_sec, f"{name}_epoch")
    if epoch_sec <= 0.0:
        raise TypeValidationError(f"{name}_epoch must be positive, got {epoch_sec}")
    computed_epoch = dt.timestamp()
    if abs(epoch_sec - computed_epoch) > max_drift_sec:
        raise TypeValidationError(
            f"{name}_epoch ({epoch_sec}) does not match {name}_iso ({iso_ts}, parsed epoch {computed_epoch:.3f})"
        )
    return computed_epoch


def validate_strict_pairs_map(
    val: Any,
    name: str,
    *,
    allowed_value_types: Tuple[type, ...] = (str, int, float, bool),
    value_validator: Optional[Callable[[Any, str], Any]] = None,
) -> Tuple[Tuple[str, Any], ...]:
    """
    Validate and return a canonical sorted tuple of unique (key, value) pairs.
    - Keys must be non-empty ASCII strings.
    - Duplicate keys are strictly rejected (raises DuplicateKeyError).
    - Values must be strictly immutable atomic types (no dict, list, set).
    - Float values must be finite (raises NonFiniteNumberError on NaN/Inf).
    - Optional value_validator can validate/normalize values (e.g. require_sha256).
    """
    pairs: List[Tuple[str, Any]] = []
    if isinstance(val, dict):
        for k, v in val.items():
            pairs.append((k, v))
    elif isinstance(val, (tuple, list)):
        for item in val:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise TypeValidationError(f"{name} pair items must be 2-tuples (key, value), got {item!r}")
            pairs.append((item[0], item[1]))
    else:
        raise TypeValidationError(f"{name} must be a dict or sequence of (key, value) pairs, got {type(val).__name__}")

    seen_keys: Set[str] = set()
    cleaned_pairs: List[Tuple[str, Any]] = []

    for k, v in pairs:
        key_str = require_ascii_str(k, f"{name} key")
        if key_str in seen_keys:
            raise DuplicateKeyError(f"Duplicate key in {name}: {key_str!r}")
        seen_keys.add(key_str)

        if isinstance(v, (dict, list, set)):
            raise TypeValidationError(f"{name}[{key_str!r}] cannot be mutable container ({type(v).__name__})")

        if not any(type(v) is t for t in allowed_value_types):
            allowed_names = [t.__name__ for t in allowed_value_types]
            raise TypeValidationError(
                f"{name}[{key_str!r}] value type {type(v).__name__} not in allowed types: {allowed_names}"
            )

        if isinstance(v, float):
            if not math.isfinite(v):
                raise NonFiniteNumberError(f"{name}[{key_str!r}] has non-finite float: {v}")

        if value_validator is not None:
            v = value_validator(v, f"{name}[{key_str!r}]")

        cleaned_pairs.append((key_str, v))

    return tuple(sorted(cleaned_pairs, key=lambda p: p[0]))


def require_dict(val: Any, name: str, allowed_keys: Optional[Set[str]] = None) -> Dict[str, Any]:
    if not isinstance(val, dict):
        raise TypeValidationError(f"{name} must be a dictionary, got {type(val).__name__}")
    if allowed_keys is not None:
        unknown = set(val.keys()) - allowed_keys
        if unknown:
            raise UnknownFieldError(f"Unknown fields in {name}: {sorted(unknown)}")
    return dict(val)


# Closed Policy Schemas (Frozen & Recursively Immutable)
@dataclasses.dataclass(frozen=True)
class ResourcePolicy:
    """Closed resource allocation schema with all stage limits per PlanControllerRepairs 3.4."""
    driver_limit_sec: int
    grace_sec: int
    payload_budget_sec: int
    host_job_limit_sec: int
    finalization_alloc_sec: int
    min_disk_gib: float
    stage_build_limit_sec: int
    stage_version_limit_sec: int
    stage_plan_limit_sec: int
    stage_pin_limit_sec: int
    stage_run1_limit_sec: int
    stage_run2_limit_sec: int
    stage_final_limit_sec: int

    _ALLOWED_KEYS = {
        "driver_limit_sec", "grace_sec", "payload_budget_sec",
        "host_job_limit_sec", "finalization_alloc_sec", "min_disk_gib",
        "stage_build_limit_sec", "stage_version_limit_sec", "stage_plan_limit_sec",
        "stage_pin_limit_sec", "stage_run1_limit_sec", "stage_run2_limit_sec",
        "stage_final_limit_sec",
    }

    def __post_init__(self) -> None:
        require_int(self.driver_limit_sec, "driver_limit_sec", min_val=1)
        require_int(self.grace_sec, "grace_sec", min_val=1)
        require_int(self.payload_budget_sec, "payload_budget_sec", min_val=1)
        require_int(self.host_job_limit_sec, "host_job_limit_sec", min_val=1)
        require_int(self.finalization_alloc_sec, "finalization_alloc_sec", min_val=1)
        min_disk = float(require_float(self.min_disk_gib, "min_disk_gib"))
        if min_disk < 1.0:
            raise TypeValidationError("min_disk_gib must be >= 1.0")
        object.__setattr__(self, "min_disk_gib", min_disk)
        require_int(self.stage_build_limit_sec, "stage_build_limit_sec", min_val=1)
        require_int(self.stage_version_limit_sec, "stage_version_limit_sec", min_val=1)
        require_int(self.stage_plan_limit_sec, "stage_plan_limit_sec", min_val=1)
        require_int(self.stage_pin_limit_sec, "stage_pin_limit_sec", min_val=1)
        require_int(self.stage_run1_limit_sec, "stage_run1_limit_sec", min_val=1)
        require_int(self.stage_run2_limit_sec, "stage_run2_limit_sec", min_val=1)
        require_int(self.stage_final_limit_sec, "stage_final_limit_sec", min_val=1)

        if self.payload_budget_sec + self.finalization_alloc_sec > self.host_job_limit_sec:
            raise TypeValidationError(
                f"payload_budget_sec ({self.payload_budget_sec}) + finalization_alloc_sec ({self.finalization_alloc_sec}) "
                f"> host_job_limit_sec ({self.host_job_limit_sec})"
            )
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourcePolicy:
        require_dict(data, "ResourcePolicy", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"ResourcePolicy missing keys: {sorted(missing)}")
        return cls(
            driver_limit_sec=require_int(data["driver_limit_sec"], "driver_limit_sec", min_val=1),
            grace_sec=require_int(data["grace_sec"], "grace_sec", min_val=1),
            payload_budget_sec=require_int(data["payload_budget_sec"], "payload_budget_sec", min_val=1),
            host_job_limit_sec=require_int(data["host_job_limit_sec"], "host_job_limit_sec", min_val=1),
            finalization_alloc_sec=require_int(data["finalization_alloc_sec"], "finalization_alloc_sec", min_val=1),
            min_disk_gib=require_float(data["min_disk_gib"], "min_disk_gib"),
            stage_build_limit_sec=require_int(data["stage_build_limit_sec"], "stage_build_limit_sec", min_val=1),
            stage_version_limit_sec=require_int(data["stage_version_limit_sec"], "stage_version_limit_sec", min_val=1),
            stage_plan_limit_sec=require_int(data["stage_plan_limit_sec"], "stage_plan_limit_sec", min_val=1),
            stage_pin_limit_sec=require_int(data["stage_pin_limit_sec"], "stage_pin_limit_sec", min_val=1),
            stage_run1_limit_sec=require_int(data["stage_run1_limit_sec"], "stage_run1_limit_sec", min_val=1),
            stage_run2_limit_sec=require_int(data["stage_run2_limit_sec"], "stage_run2_limit_sec", min_val=1),
            stage_final_limit_sec=require_int(data["stage_final_limit_sec"], "stage_final_limit_sec", min_val=1),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

PRODUCTION_RESOURCE_DRIVER_LIMIT_SEC = 2100
PRODUCTION_RESOURCE_GRACE_SEC = 30
PRODUCTION_RESOURCE_HOST_JOB_LIMIT_SEC = 21600
PRODUCTION_RESOURCE_PAYLOAD_BUDGET_SEC = 19800
PRODUCTION_RESOURCE_FINALIZATION_ALLOC_SEC = 1800
PRODUCTION_RESOURCE_MIN_DISK_GIB = 20.0
PRODUCTION_STAGE_BUILD_LIMIT_SEC = 1200
PRODUCTION_STAGE_VERSION_LIMIT_SEC = 60
PRODUCTION_STAGE_PLAN_LIMIT_SEC = 600
PRODUCTION_STAGE_PIN_LIMIT_SEC = 600
PRODUCTION_STAGE_RUN1_LIMIT_SEC = 1800
PRODUCTION_STAGE_RUN2_LIMIT_SEC = 3600
PRODUCTION_STAGE_FINAL_LIMIT_SEC = 1200


def build_production_resource_policy() -> ResourcePolicy:
    """Build the exact production ResourcePolicy approved per Plan 3.4."""
    return ResourcePolicy(
        driver_limit_sec=PRODUCTION_RESOURCE_DRIVER_LIMIT_SEC,
        grace_sec=PRODUCTION_RESOURCE_GRACE_SEC,
        payload_budget_sec=PRODUCTION_RESOURCE_PAYLOAD_BUDGET_SEC,
        host_job_limit_sec=PRODUCTION_RESOURCE_HOST_JOB_LIMIT_SEC,
        finalization_alloc_sec=PRODUCTION_RESOURCE_FINALIZATION_ALLOC_SEC,
        min_disk_gib=PRODUCTION_RESOURCE_MIN_DISK_GIB,
        stage_build_limit_sec=PRODUCTION_STAGE_BUILD_LIMIT_SEC,
        stage_version_limit_sec=PRODUCTION_STAGE_VERSION_LIMIT_SEC,
        stage_plan_limit_sec=PRODUCTION_STAGE_PLAN_LIMIT_SEC,
        stage_pin_limit_sec=PRODUCTION_STAGE_PIN_LIMIT_SEC,
        stage_run1_limit_sec=PRODUCTION_STAGE_RUN1_LIMIT_SEC,
        stage_run2_limit_sec=PRODUCTION_STAGE_RUN2_LIMIT_SEC,
        stage_final_limit_sec=PRODUCTION_STAGE_FINAL_LIMIT_SEC,
    )


def validate_production_resource_policy(policy: ResourcePolicy) -> None:
    """Enforce that policy matches the exact approved production settings and budget relationships."""
    if not isinstance(policy, ResourcePolicy):
        raise TypeValidationError(f"Expected ResourcePolicy instance, got {type(policy).__name__}")
    expected = build_production_resource_policy()
    if policy != expected:
        diffs = []
        for k in ResourcePolicy._ALLOWED_KEYS:
            act = getattr(policy, k)
            exp = getattr(expected, k)
            if act != exp:
                diffs.append(f"{k}: actual={act} != expected={exp}")
        raise ReferenceIntegrityError(f"ResourcePolicy does not match approved production policy: {', '.join(diffs)}")


@dataclasses.dataclass(frozen=True)
class CagePolicy:
    """Closed container cage isolation policy schema per PlanControllerRepairs 3.4."""
    uid: int
    gid: int
    network: str
    read_only_root: bool
    drop_capabilities: str
    no_new_privileges: bool
    private_pid_namespace: bool
    default_confined_seccomp: bool
    init_process: bool
    pids_limit: int
    tmpfs_tmp_size: str
    tmpfs_dev_shm_size: str

    _ALLOWED_KEYS = {
        "uid", "gid", "network", "read_only_root",
        "drop_capabilities", "no_new_privileges", "private_pid_namespace",
        "default_confined_seccomp", "init_process", "pids_limit",
        "tmpfs_tmp_size", "tmpfs_dev_shm_size",
    }

    def __post_init__(self) -> None:
        require_int(self.uid, "uid", min_val=1)
        require_int(self.gid, "gid", min_val=1)
        require_ascii_str(self.network, "network")
        if self.network != "none":
            raise TypeValidationError("network must be 'none'")
        require_bool(self.read_only_root, "read_only_root", expected=True)
        require_ascii_str(self.drop_capabilities, "drop_capabilities")
        if self.drop_capabilities != "ALL":
            raise TypeValidationError("drop_capabilities must be 'ALL'")
        require_bool(self.no_new_privileges, "no_new_privileges", expected=True)
        require_bool(self.private_pid_namespace, "private_pid_namespace", expected=True)
        require_bool(self.default_confined_seccomp, "default_confined_seccomp", expected=True)
        require_bool(self.init_process, "init_process", expected=True)
        require_int(self.pids_limit, "pids_limit", min_val=16)
        require_ascii_str(self.tmpfs_tmp_size, "tmpfs_tmp_size")
        if not self.tmpfs_tmp_size:
            raise TypeValidationError("tmpfs_tmp_size cannot be empty")
        require_ascii_str(self.tmpfs_dev_shm_size, "tmpfs_dev_shm_size")
        if not self.tmpfs_dev_shm_size:
            raise TypeValidationError("tmpfs_dev_shm_size cannot be empty")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CagePolicy:
        require_dict(data, "CagePolicy", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"CagePolicy missing keys: {sorted(missing)}")
        return cls(
            uid=require_int(data["uid"], "uid", min_val=1),
            gid=require_int(data["gid"], "gid", min_val=1),
            network=require_ascii_str(data["network"], "network"),
            read_only_root=require_bool(data["read_only_root"], "read_only_root", expected=True),
            drop_capabilities=require_ascii_str(data["drop_capabilities"], "drop_capabilities"),
            no_new_privileges=require_bool(data["no_new_privileges"], "no_new_privileges", expected=True),
            private_pid_namespace=require_bool(data["private_pid_namespace"], "private_pid_namespace", expected=True),
            default_confined_seccomp=require_bool(data["default_confined_seccomp"], "default_confined_seccomp", expected=True),
            init_process=require_bool(data["init_process"], "init_process", expected=True),
            pids_limit=require_int(data["pids_limit"], "pids_limit", min_val=16),
            tmpfs_tmp_size=require_ascii_str(data["tmpfs_tmp_size"], "tmpfs_tmp_size"),
            tmpfs_dev_shm_size=require_ascii_str(data["tmpfs_dev_shm_size"], "tmpfs_dev_shm_size"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

PRODUCTION_CAGE_UID = 65534
PRODUCTION_CAGE_GID = 65534
PRODUCTION_CAGE_NETWORK = "none"
PRODUCTION_CAGE_DROP_CAPABILITIES = "ALL"
PRODUCTION_CAGE_PIDS_LIMIT = 128
PRODUCTION_CAGE_TMPFS_TMP_SIZE = "2g"
PRODUCTION_CAGE_TMPFS_DEV_SHM_SIZE = "1g"


def build_production_cage_policy() -> CagePolicy:
    """Build the exact production CagePolicy approved per Plan 3.4."""
    return CagePolicy(
        uid=PRODUCTION_CAGE_UID,
        gid=PRODUCTION_CAGE_GID,
        network=PRODUCTION_CAGE_NETWORK,
        read_only_root=True,
        drop_capabilities=PRODUCTION_CAGE_DROP_CAPABILITIES,
        no_new_privileges=True,
        private_pid_namespace=True,
        default_confined_seccomp=True,
        init_process=True,
        pids_limit=PRODUCTION_CAGE_PIDS_LIMIT,
        tmpfs_tmp_size=PRODUCTION_CAGE_TMPFS_TMP_SIZE,
        tmpfs_dev_shm_size=PRODUCTION_CAGE_TMPFS_DEV_SHM_SIZE,
    )


def validate_production_cage_policy(policy: CagePolicy) -> None:
    """Enforce that policy matches the exact approved production cage settings."""
    if not isinstance(policy, CagePolicy):
        raise TypeValidationError(f"Expected CagePolicy instance, got {type(policy).__name__}")
    expected = build_production_cage_policy()
    if policy != expected:
        diffs = []
        for k in CagePolicy._ALLOWED_KEYS:
            act = getattr(policy, k)
            exp = getattr(expected, k)
            if act != exp:
                diffs.append(f"{k}: actual={act} != expected={exp}")
        raise ReferenceIntegrityError(f"CagePolicy does not match approved production policy: {', '.join(diffs)}")


@dataclasses.dataclass(frozen=True)
class EvidencePolicy:
    """Closed evidence collection ceilings and limits schema per PlanControllerRepairs 3.6."""
    max_file_bytes: int
    max_aggregate_unique_inode_bytes: int
    max_archive_emitted_bytes: int
    max_directory_entries: int
    max_directory_depth: int
    max_path_bytes: int
    max_aliases: int
    max_json_bytes: int
    max_ledger_line_bytes: int
    max_ledger_line_count: int
    max_structured_records: int
    max_witness_events: int
    max_held_descriptors: int
    max_helper_memory_bytes: int
    collection_deadline_sec: int

    _ALLOWED_KEYS = {
        "max_file_bytes", "max_aggregate_unique_inode_bytes", "max_archive_emitted_bytes",
        "max_directory_entries", "max_directory_depth", "max_path_bytes", "max_aliases",
        "max_json_bytes", "max_ledger_line_bytes", "max_ledger_line_count",
        "max_structured_records", "max_witness_events", "max_held_descriptors",
        "max_helper_memory_bytes", "collection_deadline_sec",
    }

    def __post_init__(self) -> None:
        require_int(self.max_file_bytes, "max_file_bytes", min_val=1)
        require_int(self.max_aggregate_unique_inode_bytes, "max_aggregate_unique_inode_bytes", min_val=1)
        require_int(self.max_archive_emitted_bytes, "max_archive_emitted_bytes", min_val=1)
        require_int(self.max_directory_entries, "max_directory_entries", min_val=1)
        require_int(self.max_directory_depth, "max_directory_depth", min_val=1)
        require_int(self.max_path_bytes, "max_path_bytes", min_val=1)
        require_int(self.max_aliases, "max_aliases", min_val=1)
        require_int(self.max_json_bytes, "max_json_bytes", min_val=1)
        require_int(self.max_ledger_line_bytes, "max_ledger_line_bytes", min_val=1)
        require_int(self.max_ledger_line_count, "max_ledger_line_count", min_val=1)
        require_int(self.max_structured_records, "max_structured_records", min_val=1)
        require_int(self.max_witness_events, "max_witness_events", min_val=1)
        require_int(self.max_held_descriptors, "max_held_descriptors", min_val=1)
        require_int(self.max_helper_memory_bytes, "max_helper_memory_bytes", min_val=1)
        require_int(self.collection_deadline_sec, "collection_deadline_sec", min_val=1)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidencePolicy:
        require_dict(data, "EvidencePolicy", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"EvidencePolicy missing keys: {sorted(missing)}")
        return cls(
            max_file_bytes=require_int(data["max_file_bytes"], "max_file_bytes", min_val=1),
            max_aggregate_unique_inode_bytes=require_int(data["max_aggregate_unique_inode_bytes"], "max_aggregate_unique_inode_bytes", min_val=1),
            max_archive_emitted_bytes=require_int(data["max_archive_emitted_bytes"], "max_archive_emitted_bytes", min_val=1),
            max_directory_entries=require_int(data["max_directory_entries"], "max_directory_entries", min_val=1),
            max_directory_depth=require_int(data["max_directory_depth"], "max_directory_depth", min_val=1),
            max_path_bytes=require_int(data["max_path_bytes"], "max_path_bytes", min_val=1),
            max_aliases=require_int(data["max_aliases"], "max_aliases", min_val=1),
            max_json_bytes=require_int(data["max_json_bytes"], "max_json_bytes", min_val=1),
            max_ledger_line_bytes=require_int(data["max_ledger_line_bytes"], "max_ledger_line_bytes", min_val=1),
            max_ledger_line_count=require_int(data["max_ledger_line_count"], "max_ledger_line_count", min_val=1),
            max_structured_records=require_int(data["max_structured_records"], "max_structured_records", min_val=1),
            max_witness_events=require_int(data["max_witness_events"], "max_witness_events", min_val=1),
            max_held_descriptors=require_int(data["max_held_descriptors"], "max_held_descriptors", min_val=1),
            max_helper_memory_bytes=require_int(data["max_helper_memory_bytes"], "max_helper_memory_bytes", min_val=1),
            collection_deadline_sec=require_int(data["collection_deadline_sec"], "collection_deadline_sec", min_val=1),
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class QualificationRequirements:
    rg2_evaluated: int                          # Exactly 144
    rg2_passed: int                             # Exactly 144
    rg2_exclusions: int                         # Exactly 0
    rg2_failures: int                           # Exactly 0
    rg2a_evaluated: int                         # Exactly 144
    rg2a_passed: int                            # Exactly 144
    rg2a_exclusions: int                        # Exactly 0
    rg2a_failures: int                          # Exactly 0
    selectors_142_digest: str                   # 64-hex SHA-256 of canonical original 142 selectors list
    additions_2_digest: str                     # 64-hex SHA-256 of canonical 2 additions list
    corpus_144_selectors_digest: str            # 64-hex SHA-256 of complete 144 selectors list
    rg9_programs_total: int                     # Exactly 144
    siblings_117_manifest_digest: str           # 64-hex SHA-256 of 117 sibling identities manifest
    run2_samples: int                           # Exactly 28 (sample-program count)
    run2_std_exercises: int                     # Exactly 116 (std-exercise-program count)
    run2_total_corpus: int                      # Exactly 144 (total corpus programs)
    run2_failures: int                          # Exactly 0
    run2_exclusions: int                        # Exactly 0
    run3_inventory_manifest_digest: str         # 64-hex SHA-256 of complete source-grounded Run 3 inventory
    named_frames_required: bool                 # Strictly True
    crystal_flag_intact: bool                   # Strictly True

    _ALLOWED_KEYS = {
        "rg2_evaluated", "rg2_passed", "rg2_exclusions", "rg2_failures",
        "rg2a_evaluated", "rg2a_passed", "rg2a_exclusions", "rg2a_failures",
        "selectors_142_digest", "additions_2_digest", "corpus_144_selectors_digest",
        "rg9_programs_total", "siblings_117_manifest_digest",
        "run2_samples", "run2_std_exercises", "run2_total_corpus",
        "run2_failures", "run2_exclusions",
        "run3_inventory_manifest_digest",
        "named_frames_required", "crystal_flag_intact",
    }

    def __post_init__(self) -> None:
        if require_int(self.rg2_evaluated, "rg2_evaluated") != 144:
            raise TypeValidationError(f"rg2_evaluated must be exactly 144, got {self.rg2_evaluated}")
        if require_int(self.rg2_passed, "rg2_passed") != 144:
            raise TypeValidationError(f"rg2_passed must be exactly 144, got {self.rg2_passed}")
        if require_int(self.rg2_exclusions, "rg2_exclusions") != 0:
            raise TypeValidationError(f"rg2_exclusions must be exactly 0, got {self.rg2_exclusions}")
        if require_int(self.rg2_failures, "rg2_failures") != 0:
            raise TypeValidationError(f"rg2_failures must be exactly 0, got {self.rg2_failures}")

        if require_int(self.rg2a_evaluated, "rg2a_evaluated") != 144:
            raise TypeValidationError(f"rg2a_evaluated must be exactly 144, got {self.rg2a_evaluated}")
        if require_int(self.rg2a_passed, "rg2a_passed") != 144:
            raise TypeValidationError(f"rg2a_passed must be exactly 144, got {self.rg2a_passed}")
        if require_int(self.rg2a_exclusions, "rg2a_exclusions") != 0:
            raise TypeValidationError(f"rg2a_exclusions must be exactly 0, got {self.rg2a_exclusions}")
        if require_int(self.rg2a_failures, "rg2a_failures") != 0:
            raise TypeValidationError(f"rg2a_failures must be exactly 0, got {self.rg2a_failures}")

        require_sha256(self.selectors_142_digest, "selectors_142_digest")
        require_sha256(self.additions_2_digest, "additions_2_digest")
        require_sha256(self.corpus_144_selectors_digest, "corpus_144_selectors_digest")

        if require_int(self.rg9_programs_total, "rg9_programs_total") != 144:
            raise TypeValidationError(f"rg9_programs_total must be exactly 144, got {self.rg9_programs_total}")

        require_sha256(self.siblings_117_manifest_digest, "siblings_117_manifest_digest")

        if require_int(self.run2_samples, "run2_samples") != 28:
            raise TypeValidationError(f"run2_samples must be exactly 28, got {self.run2_samples}")
        if require_int(self.run2_std_exercises, "run2_std_exercises") != 116:
            raise TypeValidationError(f"run2_std_exercises must be exactly 116, got {self.run2_std_exercises}")
        if require_int(self.run2_total_corpus, "run2_total_corpus") != 144:
            raise TypeValidationError(f"run2_total_corpus must be exactly 144, got {self.run2_total_corpus}")
        if require_int(self.run2_failures, "run2_failures") != 0:
            raise TypeValidationError(f"run2_failures must be exactly 0, got {self.run2_failures}")
        if require_int(self.run2_exclusions, "run2_exclusions") != 0:
            raise TypeValidationError(f"run2_exclusions must be exactly 0, got {self.run2_exclusions}")

        require_sha256(self.run3_inventory_manifest_digest, "run3_inventory_manifest_digest")

        require_bool(self.named_frames_required, "named_frames_required", expected=True)
        require_bool(self.crystal_flag_intact, "crystal_flag_intact", expected=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> QualificationRequirements:
        require_dict(data, "QualificationRequirements", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"QualificationRequirements missing keys: {sorted(missing)}")
        return cls(
            rg2_evaluated=require_int(data["rg2_evaluated"], "rg2_evaluated"),
            rg2_passed=require_int(data["rg2_passed"], "rg2_passed"),
            rg2_exclusions=require_int(data["rg2_exclusions"], "rg2_exclusions"),
            rg2_failures=require_int(data["rg2_failures"], "rg2_failures"),
            rg2a_evaluated=require_int(data["rg2a_evaluated"], "rg2a_evaluated"),
            rg2a_passed=require_int(data["rg2a_passed"], "rg2a_passed"),
            rg2a_exclusions=require_int(data["rg2a_exclusions"], "rg2a_exclusions"),
            rg2a_failures=require_int(data["rg2a_failures"], "rg2a_failures"),
            selectors_142_digest=require_sha256(data["selectors_142_digest"], "selectors_142_digest"),
            additions_2_digest=require_sha256(data["additions_2_digest"], "additions_2_digest"),
            corpus_144_selectors_digest=require_sha256(data["corpus_144_selectors_digest"], "corpus_144_selectors_digest"),
            rg9_programs_total=require_int(data["rg9_programs_total"], "rg9_programs_total"),
            siblings_117_manifest_digest=require_sha256(data["siblings_117_manifest_digest"], "siblings_117_manifest_digest"),
            run2_samples=require_int(data["run2_samples"], "run2_samples"),
            run2_std_exercises=require_int(data["run2_std_exercises"], "run2_std_exercises"),
            run2_total_corpus=require_int(data["run2_total_corpus"], "run2_total_corpus"),
            run2_failures=require_int(data["run2_failures"], "run2_failures"),
            run2_exclusions=require_int(data["run2_exclusions"], "run2_exclusions"),
            run3_inventory_manifest_digest=require_sha256(data["run3_inventory_manifest_digest"], "run3_inventory_manifest_digest"),
            named_frames_required=require_bool(data["named_frames_required"], "named_frames_required", expected=True),
            crystal_flag_intact=require_bool(data["crystal_flag_intact"], "crystal_flag_intact", expected=True),
        )
    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

def compute_manifest_digest(identities: Sequence[str]) -> str:
    """
    Compute canonical SHA-256 digest over a sequence of string identities.
    Validates that each item is an ASCII string, rejects duplicates, and serializes
    sorted list via canonical_json_bytes.
    """
    cleaned: List[str] = []
    seen: Set[str] = set()
    for item in identities:
        s = require_ascii_str(item, "manifest identity")
        if s in seen:
            raise DuplicateKeyError(f"Duplicate identity in manifest: {s!r}")
        seen.add(s)
        cleaned.append(s)
    return sha256_bytes(canonical_json_bytes(sorted(cleaned)))


def validate_qualification_ground_truth(
    qual: QualificationRequirements,
    *,
    original_142_selectors: Sequence[str],
    additions_2_selectors: Sequence[str],
    complete_144_corpus: Sequence[str],
    siblings_117_manifest: Sequence[str],
    run3_inventory_manifest: Sequence[str],
) -> None:
    """
    Validate that QualificationRequirements digests match actual source-grounded
    identities, verifying exact counts, disjoint union, and digest integrity.
    """
    if not isinstance(qual, QualificationRequirements):
        raise TypeValidationError(f"Expected QualificationRequirements, got {type(qual).__name__}")

    orig_set: Set[str] = set()
    for s in original_142_selectors:
        val = require_ascii_str(s, "original_142_selector")
        if val in orig_set:
            raise DuplicateKeyError(f"Duplicate in original 142 selectors: {val}")
        orig_set.add(val)
    if len(orig_set) != 142:
        raise TypeValidationError(f"Expected exactly 142 original selectors, got {len(orig_set)}")

    add_set: Set[str] = set()
    for s in additions_2_selectors:
        val = require_ascii_str(s, "additions_2_selector")
        if val in add_set:
            raise DuplicateKeyError(f"Duplicate in 2 additions selectors: {val}")
        add_set.add(val)
    if len(add_set) != 2:
        raise TypeValidationError(f"Expected exactly 2 additions, got {len(add_set)}")

    if not orig_set.isdisjoint(add_set):
        overlap = orig_set & add_set
        raise ReferenceIntegrityError(f"Original 142 and additions are not disjoint; overlap: {sorted(overlap)}")

    corpus_set: Set[str] = set()
    for s in complete_144_corpus:
        val = require_ascii_str(s, "complete_144_corpus_item")
        if val in corpus_set:
            raise DuplicateKeyError(f"Duplicate in 144 corpus: {val}")
        corpus_set.add(val)
    if len(corpus_set) != 144:
        raise TypeValidationError(f"Expected exactly 144 corpus items, got {len(corpus_set)}")

    if (orig_set | add_set) != corpus_set:
        diff_missing = corpus_set - (orig_set | add_set)
        diff_extra = (orig_set | add_set) - corpus_set
        raise ReferenceIntegrityError(
            f"Corpus 144 must equal original 142 union 2 additions. Missing: {sorted(diff_missing)}, Extra: {sorted(diff_extra)}"
        )

    sibs_set: Set[str] = set()
    for s in siblings_117_manifest:
        val = require_ascii_str(s, "sibling_117_item")
        if val in sibs_set:
            raise DuplicateKeyError(f"Duplicate in sibling 117 manifest: {val}")
        sibs_set.add(val)
    if len(sibs_set) != 117:
        raise TypeValidationError(f"Expected exactly 117 sibling identities, got {len(sibs_set)}")

    run3_set: Set[str] = set()
    for s in run3_inventory_manifest:
        val = require_ascii_str(s, "run3_inventory_item")
        if val in run3_set:
            raise DuplicateKeyError(f"Duplicate in Run 3 inventory: {val}")
        run3_set.add(val)
    if len(run3_set) < 29:
        raise TypeValidationError(f"Expected at least 29 Run 3 inventory items, got {len(run3_set)}")

    orig_digest = compute_manifest_digest(list(orig_set))
    if orig_digest != qual.selectors_142_digest:
        raise ReferenceIntegrityError(
            f"selectors_142_digest mismatch: expected {qual.selectors_142_digest}, computed {orig_digest}"
        )

    add_digest = compute_manifest_digest(list(add_set))
    if add_digest != qual.additions_2_digest:
        raise ReferenceIntegrityError(
            f"additions_2_digest mismatch: expected {qual.additions_2_digest}, computed {add_digest}"
        )

    corpus_digest = compute_manifest_digest(list(corpus_set))
    if corpus_digest != qual.corpus_144_selectors_digest:
        raise ReferenceIntegrityError(
            f"corpus_144_selectors_digest mismatch: expected {qual.corpus_144_selectors_digest}, computed {corpus_digest}"
        )

    sibs_digest = compute_manifest_digest(list(sibs_set))
    if sibs_digest != qual.siblings_117_manifest_digest:
        raise ReferenceIntegrityError(
            f"siblings_117_manifest_digest mismatch: expected {qual.siblings_117_manifest_digest}, computed {sibs_digest}"
        )

    run3_digest = compute_manifest_digest(list(run3_set))
    if run3_digest != qual.run3_inventory_manifest_digest:
        raise ReferenceIntegrityError(
            f"run3_inventory_manifest_digest mismatch: expected {qual.run3_inventory_manifest_digest}, computed {run3_digest}"
        )


def build_grounded_qualification_requirements(
    *,
    original_142_selectors: Sequence[str],
    additions_2_selectors: Sequence[str],
    complete_144_corpus: Sequence[str],
    siblings_117_manifest: Sequence[str],
    run3_inventory_manifest: Sequence[str],
) -> QualificationRequirements:
    """Construct QualificationRequirements bound to validated ground-truth manifests."""
    orig_digest = compute_manifest_digest(original_142_selectors)
    add_digest = compute_manifest_digest(additions_2_selectors)
    corpus_digest = compute_manifest_digest(complete_144_corpus)
    sibs_digest = compute_manifest_digest(siblings_117_manifest)
    run3_digest = compute_manifest_digest(run3_inventory_manifest)

    qual = QualificationRequirements(
        rg2_evaluated=144,
        rg2_passed=144,
        rg2_exclusions=0,
        rg2_failures=0,
        rg2a_evaluated=144,
        rg2a_passed=144,
        rg2a_exclusions=0,
        rg2a_failures=0,
        selectors_142_digest=orig_digest,
        additions_2_digest=add_digest,
        corpus_144_selectors_digest=corpus_digest,
        rg9_programs_total=144,
        siblings_117_manifest_digest=sibs_digest,
        run2_samples=28,
        run2_std_exercises=116,
        run2_total_corpus=144,
        run2_failures=0,
        run2_exclusions=0,
        run3_inventory_manifest_digest=run3_digest,
        named_frames_required=True,
        crystal_flag_intact=True,
    )
    validate_qualification_ground_truth(
        qual,
        original_142_selectors=original_142_selectors,
        additions_2_selectors=additions_2_selectors,
        complete_144_corpus=complete_144_corpus,
        siblings_117_manifest=siblings_117_manifest,
        run3_inventory_manifest=run3_inventory_manifest,
    )
    return qual


# Primary Immutable Data Models
@dataclasses.dataclass(frozen=True)
class ExecutionSubject:
    """Complete, immutable candidate execution subject bound prior to approval."""
    repository: str
    c_sha: str
    p_sha: str
    w_sha: str
    workflow_path: str
    workflow_blob: str
    run_id: str
    run_attempt: int
    job_key: str
    report_path: str
    image: str
    image_digest: str
    lock_path: str
    lock_sha256: str
    expected_bundle_sha256: str
    resource_policy: ResourcePolicy
    cage_policy: CagePolicy
    evidence_policy: EvidencePolicy
    w_interface_version: str
    census_digest: str
    logical_slot_manifest_digest: str
    qualification_requirements: QualificationRequirements

    _ALLOWED_KEYS = {
        "repository", "c_sha", "p_sha", "w_sha", "workflow_path", "workflow_blob",
        "run_id", "run_attempt", "job_key", "report_path", "image", "image_digest",
        "lock_path", "lock_sha256", "expected_bundle_sha256", "resource_policy",
        "cage_policy", "evidence_policy", "w_interface_version", "census_digest",
        "logical_slot_manifest_digest", "qualification_requirements",
    }

    def __post_init__(self) -> None:
        require_ascii_str(self.repository, "repository")
        require_sha1_or_commit(self.c_sha, "c_sha")
        require_sha1_or_commit(self.p_sha, "p_sha")
        require_sha1_or_commit(self.w_sha, "w_sha")
        require_ascii_str(self.workflow_path, "workflow_path")
        require_sha1_or_commit(self.workflow_blob, "workflow_blob")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        require_ascii_str(self.job_key, "job_key")
        require_str(self.report_path, "report_path", r"^/private/tmp/iyp-[0-9a-f]{8}$")
        require_ascii_str(self.image, "image")
        require_str(self.image_digest, "image_digest", r"^sha256:[0-9a-f]{64}$")
        require_ascii_str(self.lock_path, "lock_path")
        require_sha256(self.lock_sha256, "lock_sha256")
        require_sha256(self.expected_bundle_sha256, "expected_bundle_sha256")
        if not isinstance(self.resource_policy, ResourcePolicy):
            raise TypeValidationError("resource_policy must be a ResourcePolicy")
        if not isinstance(self.cage_policy, CagePolicy):
            raise TypeValidationError("cage_policy must be a CagePolicy")
        if not isinstance(self.evidence_policy, EvidencePolicy):
            raise TypeValidationError("evidence_policy must be an EvidencePolicy")
        require_ascii_str(self.w_interface_version, "w_interface_version")
        require_sha256(self.census_digest, "census_digest")
        require_sha256(self.logical_slot_manifest_digest, "logical_slot_manifest_digest")
        if not isinstance(self.qualification_requirements, QualificationRequirements):
            raise TypeValidationError("qualification_requirements must be a QualificationRequirements")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionSubject:
        require_dict(data, "ExecutionSubject", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"ExecutionSubject missing required keys: {sorted(missing)}")

        res_p = data["resource_policy"]
        resource_policy = res_p if isinstance(res_p, ResourcePolicy) else ResourcePolicy.from_dict(require_dict(res_p, "resource_policy"))

        cage_p = data["cage_policy"]
        cage_policy = cage_p if isinstance(cage_p, CagePolicy) else CagePolicy.from_dict(require_dict(cage_p, "cage_policy"))

        ev_p = data["evidence_policy"]
        evidence_policy = ev_p if isinstance(ev_p, EvidencePolicy) else EvidencePolicy.from_dict(require_dict(ev_p, "evidence_policy"))

        qual_p = data["qualification_requirements"]
        qualification_requirements = qual_p if isinstance(qual_p, QualificationRequirements) else QualificationRequirements.from_dict(require_dict(qual_p, "qualification_requirements"))

        return cls(
            repository=data["repository"],
            c_sha=data["c_sha"],
            p_sha=data["p_sha"],
            w_sha=data["w_sha"],
            workflow_path=data["workflow_path"],
            workflow_blob=data["workflow_blob"],
            run_id=data["run_id"],
            run_attempt=data["run_attempt"],
            job_key=data["job_key"],
            report_path=data["report_path"],
            image=data["image"],
            image_digest=data["image_digest"],
            lock_path=data["lock_path"],
            lock_sha256=data["lock_sha256"],
            expected_bundle_sha256=data["expected_bundle_sha256"],
            resource_policy=resource_policy,
            cage_policy=cage_policy,
            evidence_policy=evidence_policy,
            w_interface_version=data["w_interface_version"],
            census_digest=data["census_digest"],
            logical_slot_manifest_digest=data["logical_slot_manifest_digest"],
            qualification_requirements=qualification_requirements,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository": self.repository,
            "c_sha": self.c_sha,
            "p_sha": self.p_sha,
            "w_sha": self.w_sha,
            "workflow_path": self.workflow_path,
            "workflow_blob": self.workflow_blob,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "job_key": self.job_key,
            "report_path": self.report_path,
            "image": self.image,
            "image_digest": self.image_digest,
            "lock_path": self.lock_path,
            "lock_sha256": self.lock_sha256,
            "expected_bundle_sha256": self.expected_bundle_sha256,
            "resource_policy": self.resource_policy.to_dict(),
            "cage_policy": self.cage_policy.to_dict(),
            "evidence_policy": self.evidence_policy.to_dict(),
            "w_interface_version": self.w_interface_version,
            "census_digest": self.census_digest,
            "logical_slot_manifest_digest": self.logical_slot_manifest_digest,
            "qualification_requirements": self.qualification_requirements.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclasses.dataclass(frozen=True)
class ValidationRef:
    """Authenticated reference to subject-bound validation proof run and artifact."""
    subject_digest: str
    validation_repository: str
    validation_workflow: str
    validation_c_sha: str
    run_id: str
    run_attempt: int
    job_id: str
    artifact_id: str
    artifact_digest: Optional[str]
    evidence_member_size: int
    evidence_member_sha256: str

    _ALLOWED_KEYS = {
        "subject_digest", "validation_repository", "validation_workflow",
        "validation_c_sha", "run_id", "run_attempt", "job_id", "artifact_id",
        "artifact_digest", "evidence_member_size", "evidence_member_sha256",
    }

    def __post_init__(self) -> None:
        require_sha256(self.subject_digest, "subject_digest")
        require_ascii_str(self.validation_repository, "validation_repository")
        require_ascii_str(self.validation_workflow, "validation_workflow")
        require_sha1_or_commit(self.validation_c_sha, "validation_c_sha")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        object.__setattr__(self, "job_id", require_positive_ascii_id(self.job_id, "job_id"))
        object.__setattr__(self, "artifact_id", require_positive_ascii_id(self.artifact_id, "artifact_id"))
        if self.artifact_digest is not None:
            require_sha256(self.artifact_digest, "artifact_digest")
        require_int(self.evidence_member_size, "evidence_member_size", min_val=1)
        require_sha256(self.evidence_member_sha256, "evidence_member_sha256")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ValidationRef:
        require_dict(data, "ValidationRef", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"ValidationRef missing required keys: {sorted(missing)}")

        return cls(
            subject_digest=data["subject_digest"],
            validation_repository=data["validation_repository"],
            validation_workflow=data["validation_workflow"],
            validation_c_sha=data["validation_c_sha"],
            run_id=data["run_id"],
            run_attempt=data["run_attempt"],
            job_id=data["job_id"],
            artifact_id=data["artifact_id"],
            artifact_digest=data["artifact_digest"],
            evidence_member_size=data["evidence_member_size"],
            evidence_member_sha256=data["evidence_member_sha256"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())

def validate_validation_ref_to_subject(validation_ref: ValidationRef, subject: ExecutionSubject) -> None:
    """Validate cross-record reference and environment consistency between ValidationRef and ExecutionSubject."""
    if not isinstance(validation_ref, ValidationRef):
        raise TypeValidationError(f"Expected ValidationRef, got {type(validation_ref).__name__}")
    if not isinstance(subject, ExecutionSubject):
        raise TypeValidationError(f"Expected ExecutionSubject, got {type(subject).__name__}")

    subj_digest = subject.digest()
    if validation_ref.subject_digest != subj_digest:
        raise ValidationReferenceMismatch(
            f"ValidationRef subject_digest mismatch: expected {subj_digest}, got {validation_ref.subject_digest}"
        )
    if validation_ref.validation_repository != subject.repository:
        raise ValidationReferenceMismatch(
            f"ValidationRef repository mismatch: subject has {subject.repository!r}, validation has {validation_ref.validation_repository!r}"
        )
    if validation_ref.validation_c_sha != subject.c_sha:
        raise ValidationReferenceMismatch(
            f"ValidationRef c_sha mismatch: subject has {subject.c_sha}, validation has {validation_ref.validation_c_sha}"
        )
    if validation_ref.validation_workflow != subject.workflow_path:
        raise ValidationReferenceMismatch(
            f"ValidationRef workflow mismatch: subject has {subject.workflow_path!r}, validation has {validation_ref.validation_workflow!r}"
        )


@dataclasses.dataclass(frozen=True)
class StructuralIndependentReviewRef:
    """
    Structural reference to independent review attestation binding subject and validation.
    Note: A structural reference does NOT constitute authenticated authority until verified
    against an independent cryptographic signature or trusted channel policy.
    """
    subject_digest: str
    validation_ref_digest: str
    attestation_digest: str
    reviewer_identity: str
    verification_evidence: Tuple[Tuple[str, str], ...]
    decision: str

    _ALLOWED_KEYS = {
        "subject_digest", "validation_ref_digest", "attestation_digest",
        "reviewer_identity", "verification_evidence", "decision",
    }

    def __post_init__(self) -> None:
        require_sha256(self.subject_digest, "subject_digest")
        require_sha256(self.validation_ref_digest, "validation_ref_digest")
        require_sha256(self.attestation_digest, "attestation_digest")
        require_ascii_str(self.reviewer_identity, "reviewer_identity")
        ve = validate_strict_pairs_map(
            self.verification_evidence,
            "verification_evidence",
            allowed_value_types=(str, int, float, bool),
        )
        object.__setattr__(self, "verification_evidence", ve)
        if self.decision != "GO":
            raise TypeValidationError("decision must be 'GO'")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StructuralIndependentReviewRef:
        require_dict(data, "StructuralIndependentReviewRef", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"StructuralIndependentReviewRef missing required keys: {sorted(missing)}")

        ve_pairs = validate_strict_pairs_map(
            data["verification_evidence"],
            "verification_evidence",
            allowed_value_types=(str, int, float, bool),
        )
        return cls(
            subject_digest=data["subject_digest"],
            validation_ref_digest=data["validation_ref_digest"],
            attestation_digest=data["attestation_digest"],
            reviewer_identity=data["reviewer_identity"],
            verification_evidence=ve_pairs,
            decision=data["decision"],
        )

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["verification_evidence"] = dict(self.verification_evidence)
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclasses.dataclass(frozen=True)
class ProofManifest:
    """Canonical invocation manifest (schema iyi-hosted-linux-proof-v2) for personal approval."""
    schema: str
    subject: ExecutionSubject
    validation: ValidationRef
    review: StructuralIndependentReviewRef

    _ALLOWED_KEYS = {"schema", "subject", "validation", "review"}

    def __post_init__(self) -> None:
        if self.schema != SCHEMA_MANIFEST_V2:
            raise UnsupportedSchemaError(
                f"Unsupported manifest schema: {self.schema!r}, expected {SCHEMA_MANIFEST_V2!r}"
            )
        if not isinstance(self.subject, ExecutionSubject):
            raise TypeValidationError("subject must be an ExecutionSubject")
        if not isinstance(self.validation, ValidationRef):
            raise TypeValidationError("validation must be a ValidationRef")
        if not isinstance(self.review, StructuralIndependentReviewRef):
            raise TypeValidationError("review must be a StructuralIndependentReviewRef")

        # Cryptographic referential integrity verification across joined records
        validate_validation_ref_to_subject(self.validation, self.subject)

        if self.review.subject_digest != subj_digest:
            raise ReviewReferenceMismatch(
                f"StructuralIndependentReviewRef subject_digest mismatch: expected {subj_digest}, got {self.review.subject_digest}"
            )

        val_digest = self.validation.digest()
        if self.review.validation_ref_digest != val_digest:
            raise ReviewReferenceMismatch(
                f"StructuralIndependentReviewRef validation_ref_digest mismatch: expected {val_digest}, got {self.review.validation_ref_digest}"
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProofManifest:
        require_dict(data, "ProofManifest", cls._ALLOWED_KEYS)
        schema = require_str(data.get("schema", ""), "schema")
        if schema != SCHEMA_MANIFEST_V2:
            raise UnsupportedSchemaError(
                f"Unsupported manifest schema: {schema!r}, expected {SCHEMA_MANIFEST_V2!r}"
            )

        subj_data = data["subject"]
        subject = subj_data if isinstance(subj_data, ExecutionSubject) else ExecutionSubject.from_dict(require_dict(subj_data, "subject"))

        val_data = data["validation"]
        validation = val_data if isinstance(val_data, ValidationRef) else ValidationRef.from_dict(require_dict(val_data, "validation"))

        rev_data = data["review"]
        review = rev_data if isinstance(rev_data, StructuralIndependentReviewRef) else StructuralIndependentReviewRef.from_dict(require_dict(rev_data, "review"))

        return cls(
            schema=schema,
            subject=subject,
            validation=validation,
            review=review,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "subject": self.subject.to_dict(),
            "validation": self.validation.to_dict(),
            "review": self.review.to_dict(),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclasses.dataclass(frozen=True)
class ExecutionContext:
    """Authenticated platform context for the running strict-proof job."""
    manifest_digest: str
    subject_digest: str
    repository: str
    run_id: str
    run_attempt: int
    job_key: str
    job_id: str
    runner_identity: str
    job_started_at_iso: str
    job_started_at_epoch: float
    platform_response_digests: Tuple[Tuple[str, str], ...]

    _ALLOWED_KEYS = {
        "manifest_digest", "subject_digest", "repository", "run_id",
        "run_attempt", "job_key", "job_id", "runner_identity",
        "job_started_at_iso", "job_started_at_epoch", "platform_response_digests",
    }

    def __post_init__(self) -> None:
        require_sha256(self.manifest_digest, "manifest_digest")
        require_sha256(self.subject_digest, "subject_digest")
        require_ascii_str(self.repository, "repository")
        object.__setattr__(self, "run_id", require_positive_ascii_id(self.run_id, "run_id"))
        require_int(self.run_attempt, "run_attempt", min_val=1)
        require_ascii_str(self.job_key, "job_key")
        object.__setattr__(self, "job_id", require_positive_ascii_id(self.job_id, "job_id"))
        require_ascii_str(self.runner_identity, "runner_identity")
        epoch = float(require_float(self.job_started_at_epoch, "job_started_at_epoch"))
        object.__setattr__(self, "job_started_at_epoch", epoch)
        validate_timestamp_and_epoch(self.job_started_at_iso, epoch, "job_started_at")
        prd = validate_strict_pairs_map(
            self.platform_response_digests,
            "platform_response_digests",
            allowed_value_types=(str,),
            value_validator=require_sha256,
        )
        object.__setattr__(self, "platform_response_digests", prd)
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionContext:
        require_dict(data, "ExecutionContext", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"ExecutionContext missing required keys: {sorted(missing)}")
        return cls(
            manifest_digest=data["manifest_digest"],
            subject_digest=data["subject_digest"],
            repository=data["repository"],
            run_id=data["run_id"],
            run_attempt=data["run_attempt"],
            job_key=data["job_key"],
            job_id=data["job_id"],
            runner_identity=data["runner_identity"],
            job_started_at_iso=data["job_started_at_iso"],
            job_started_at_epoch=data["job_started_at_epoch"],
            platform_response_digests=validate_strict_pairs_map(
                data["platform_response_digests"],
                "platform_response_digests",
                allowed_value_types=(str,),
                value_validator=require_sha256,
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["platform_response_digests"] = dict(self.platform_response_digests)
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())


@dataclasses.dataclass(frozen=True)
class CheckpointDescriptor:
    """Immutable record of an executed stage/attempt outcome."""
    manifest_digest: str
    subject_digest: str
    execution_context_digest: str
    launch_id: str
    stage: str
    attempt: int
    command: Tuple[str, ...]
    exit_code: int
    outcome: str
    chain_id: Optional[str]
    compiler_sha256: Optional[str]
    effective_policy: Tuple[Tuple[str, Any], ...]
    teardown_disposition: Tuple[Tuple[str, Any], ...]
    evidence_digests: Tuple[Tuple[str, str], ...]
    timestamp: str

    _ALLOWED_KEYS = {
        "manifest_digest", "subject_digest", "execution_context_digest",
        "launch_id", "stage", "attempt", "command", "exit_code", "outcome",
        "chain_id", "compiler_sha256", "effective_policy", "teardown_disposition",
        "evidence_digests", "timestamp",
    }

    _ALLOWED_OUTCOMES = {"PASS", "FAIL", "TIMEOUT", "INVALID", "STOP"}

    def __post_init__(self) -> None:
        require_sha256(self.manifest_digest, "manifest_digest")
        require_sha256(self.subject_digest, "subject_digest")
        require_sha256(self.execution_context_digest, "execution_context_digest")
        object.__setattr__(self, "launch_id", require_positive_ascii_id(self.launch_id, "launch_id"))
        require_ascii_str(self.stage, "stage")
        require_int(self.attempt, "attempt", min_val=1)
        if not isinstance(self.command, tuple) or not all(isinstance(c, str) for c in self.command):
            raise TypeValidationError("command must be a tuple of strings")
        require_int(self.exit_code, "exit_code")
        if self.outcome not in self._ALLOWED_OUTCOMES:
            raise TypeValidationError(f"Invalid outcome: {self.outcome!r}")
        if self.chain_id is not None:
            require_ascii_str(self.chain_id, "chain_id")
        if self.compiler_sha256 is not None:
            require_sha256(self.compiler_sha256, "compiler_sha256")
        pol = validate_strict_pairs_map(
            self.effective_policy,
            "effective_policy",
            allowed_value_types=(str, int, float, bool),
        )
        object.__setattr__(self, "effective_policy", pol)
        teardown = validate_strict_pairs_map(
            self.teardown_disposition,
            "teardown_disposition",
            allowed_value_types=(str, int, float, bool),
        )
        object.__setattr__(self, "teardown_disposition", teardown)
        ev_digests = validate_strict_pairs_map(
            self.evidence_digests,
            "evidence_digests",
            allowed_value_types=(str,),
            value_validator=require_sha256,
        )
        object.__setattr__(self, "evidence_digests", ev_digests)
        require_iso_timestamp(self.timestamp, "timestamp")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CheckpointDescriptor:
        require_dict(data, "CheckpointDescriptor", cls._ALLOWED_KEYS)
        missing = cls._ALLOWED_KEYS - set(data.keys())
        if missing:
            raise TypeValidationError(f"CheckpointDescriptor missing required keys: {sorted(missing)}")

        cmd_val = data["command"]
        if not isinstance(cmd_val, (list, tuple)) or not all(isinstance(c, str) for c in cmd_val):
            raise TypeValidationError("command must be list or tuple of strings")

        return cls(
            manifest_digest=data["manifest_digest"],
            subject_digest=data["subject_digest"],
            execution_context_digest=data["execution_context_digest"],
            launch_id=data["launch_id"],
            stage=data["stage"],
            attempt=data["attempt"],
            command=tuple(cmd_val),
            exit_code=data["exit_code"],
            outcome=data["outcome"],
            chain_id=data.get("chain_id"),
            compiler_sha256=data.get("compiler_sha256"),
            effective_policy=validate_strict_pairs_map(
                data["effective_policy"],
                "effective_policy",
                allowed_value_types=(str, int, float, bool),
            ),
            teardown_disposition=validate_strict_pairs_map(
                data["teardown_disposition"],
                "teardown_disposition",
                allowed_value_types=(str, int, float, bool),
            ),
            evidence_digests=validate_strict_pairs_map(
                data["evidence_digests"],
                "evidence_digests",
                allowed_value_types=(str,),
                value_validator=require_sha256,
            ),
            timestamp=data["timestamp"],
        )

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["command"] = list(self.command)
        d["effective_policy"] = dict(self.effective_policy)
        d["teardown_disposition"] = dict(self.teardown_disposition)
        d["evidence_digests"] = dict(self.evidence_digests)
        return d

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return sha256_bytes(self.canonical_bytes())

def validate_execution_context_to_manifest(context: ExecutionContext, manifest: ProofManifest) -> None:
    """Validate that authenticated ExecutionContext matches approved ProofManifest and ExecutionSubject."""
    if not isinstance(context, ExecutionContext):
        raise TypeValidationError(f"Expected ExecutionContext, got {type(context).__name__}")
    if not isinstance(manifest, ProofManifest):
        raise TypeValidationError(f"Expected ProofManifest, got {type(manifest).__name__}")

    man_digest = manifest.digest()
    if context.manifest_digest != man_digest:
        raise ReferenceIntegrityError(
            f"ExecutionContext manifest_digest mismatch: expected {man_digest}, got {context.manifest_digest}"
        )

    subj_digest = manifest.subject.digest()
    if context.subject_digest != subj_digest:
        raise ReferenceIntegrityError(
            f"ExecutionContext subject_digest mismatch: expected {subj_digest}, got {context.subject_digest}"
        )

    if context.repository != manifest.subject.repository:
        raise ReferenceIntegrityError(
            f"ExecutionContext repository mismatch: manifest has {manifest.subject.repository!r}, context has {context.repository!r}"
        )
    if context.run_id != manifest.subject.run_id:
        raise ReferenceIntegrityError(
            f"ExecutionContext run_id mismatch: manifest has {manifest.subject.run_id!r}, context has {context.run_id!r}"
        )
    if context.run_attempt != manifest.subject.run_attempt:
        raise ReferenceIntegrityError(
            f"ExecutionContext run_attempt mismatch: manifest has {manifest.subject.run_attempt}, context has {context.run_attempt}"
        )
    if context.job_key != manifest.subject.job_key:
        raise ReferenceIntegrityError(
            f"ExecutionContext job_key mismatch: manifest has {manifest.subject.job_key!r}, context has {context.job_key!r}"
        )


def validate_checkpoint_to_context(
    checkpoint: CheckpointDescriptor,
    context: ExecutionContext,
    manifest: ProofManifest,
) -> None:
    """Validate that CheckpointDescriptor cryptographically binds to manifest and execution context."""
    if not isinstance(checkpoint, CheckpointDescriptor):
        raise TypeValidationError(f"Expected CheckpointDescriptor, got {type(checkpoint).__name__}")
    if not isinstance(context, ExecutionContext):
        raise TypeValidationError(f"Expected ExecutionContext, got {type(context).__name__}")
    if not isinstance(manifest, ProofManifest):
        raise TypeValidationError(f"Expected ProofManifest, got {type(manifest).__name__}")

    man_digest = manifest.digest()
    if checkpoint.manifest_digest != man_digest:
        raise ReferenceIntegrityError(
            f"CheckpointDescriptor manifest_digest mismatch: expected {man_digest}, got {checkpoint.manifest_digest}"
        )

    subj_digest = manifest.subject.digest()
    if checkpoint.subject_digest != subj_digest:
        raise ReferenceIntegrityError(
            f"CheckpointDescriptor subject_digest mismatch: expected {subj_digest}, got {checkpoint.subject_digest}"
        )

    ctx_digest = context.digest()
    if checkpoint.execution_context_digest != ctx_digest:
        raise ReferenceIntegrityError(
            f"CheckpointDescriptor execution_context_digest mismatch: expected {ctx_digest}, got {checkpoint.execution_context_digest}"
        )


# Refusal Policy Enforcements (Spec 3.1)
def enforce_independent_review_refusal() -> None:
    """Unconditionally refuse execution because independent review attestation is not yet integrated."""
    raise ReviewUnauthenticatedError(
        "INDEPENDENT-REVIEW-UNATTESTED: Independent review requires authenticated cryptographic signature "
        "or trusted channel attestation (identity/key/subject). Unsigned Git-stored JSON alone does not "
        "establish reviewer independence; failing closed per security audit."
    )


def enforce_origin_transport_refusal() -> None:
    """Unconditionally refuse execution because unforgeable origin capture transport is not yet qualified."""
    raise StrictHaltRefusal(
        "STRICT-EXECUTION-HALTED: Host controller cannot certify payload-authored "
        "origin_records.json as host-authenticated evidence without unforgeable capture transport "
        "across the process boundary. Halting strict execution per security review."
    )
