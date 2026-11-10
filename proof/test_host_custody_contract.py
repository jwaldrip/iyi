import copy
import unittest

from host_custody_contract import Status, assess


def records():
    common = dict(workflow="workflow/build", checkout="commit123", run=42, attempt=1, boot_id="boot-1")
    artifacts = {role: char * 64 for role, char in (
        ("observer", "a"), ("bpf_object", "b"), ("dependencies", "c"),
        ("recipe", "d"), ("exec_config", "e"))}
    expected = dict(common, unit="observer.service", invocation_id="invocation-1", cgroup="/observer",
                    authority="external/authority", reviewer="reviewer-1", artifacts=artifacts,
                    diagnostic_digest="f" * 64)
    inventory = dict(common, manager_pid=1, workload_uid=1001, observer_uid=1002, collector_uid=1003,
                     hostile_host_user=False, host_user_sudo=True, host_user_docker_control=True,
                     bootstrap_before_hostile=True, root_repo_code_executed=False, strict_eligible=False,
                     load_attempted=False, attach_attempted=False, exec_identity_tested=False)
    protected = dict(common, artifacts=copy.deepcopy(artifacts), fresh_inodes=True, root_private=True,
                     source_bounded_regular_nofollow=True, readback_verified=True, readonly_exposed=True,
                     observer_separate_uid=True)
    terminal = dict(common, unit="observer.service", invocation_id="invocation-1", cgroup="/observer",
                    exec_config_digest="e" * 64, manager_pid=1, main_pid=123, started_ns=10, exited_ns=20,
                    exec_main_code="exited", exec_main_status=0, result="success", restarts=0,
                    diagnostics_complete=True, diagnostic_digest="f" * 64,
                    diagnostic_readback_digest="f" * 64, collector_protected=True, manager_status_present=True)
    return expected, inventory, protected, terminal


class ContractTests(unittest.TestCase):
    def test_spoofed_pass_never_admits_or_attests(self):
        result = assess(*records())
        self.assertEqual(result.status, Status.CONSISTENT_UNATTESTED)
        self.assertFalse(result.runtime_admission)
        self.assertFalse(result.authority_verified)
        self.assertFalse(result.user_authorization_verified)
        self.assertFalse(result.terminal_independently_attested)

    def test_refuses_adversarial_and_inconsistent_claims(self):
        cases = [
            (0, "authority", ""), (0, "reviewer", ""),
            (1, "observer_uid", 1001), (1, "collector_uid", 1002),
            (1, "hostile_host_user", True), (1, "host_user_sudo", None),
            (1, "manager_pid", 2), (1, "strict_eligible", True),
            (1, "load_attempted", True), (1, "attach_attempted", True),
            (1, "exec_identity_tested", True), (1, "root_repo_code_executed", True),
            (1, "bootstrap_before_hostile", False),
            (2, "fresh_inodes", False), (2, "readback_verified", False),
            (3, "manager_pid", 123), (3, "invocation_id", "replayed"),
            (3, "manager_status_present", False), (3, "exec_main_status", 1),
            (3, "exec_main_status", False), (3, "exec_main_code", "killed"),
            (3, "result", "timeout"), (3, "restarts", 1),
            (3, "exited_ns", 10), (3, "diagnostics_complete", False),
            (3, "diagnostic_readback_digest", "0" * 64), (3, "exec_config_digest", "0" * 64),
            (3, "run", 43), (3, "attempt", True), (3, "boot_id", "other-boot"),
        ]
        for index, key, value in cases:
            with self.subTest(index=index, key=key, value=value):
                data = records()
                data[index][key] = value
                self.assertEqual(assess(*data).status, Status.REFUSED)

    def test_hostile_user_with_docker_control_is_refused(self):
        data = records()
        data[1].update(hostile_host_user=True, host_user_sudo=False, host_user_docker_control=True)
        self.assertEqual(assess(*data).status, Status.REFUSED)

    def test_artifact_mutation_and_missing_fields(self):
        for index in range(4):
            with self.subTest(missing_record=index):
                data = records()
                del data[index][next(iter(data[index]))]
                self.assertEqual(assess(*data).status, Status.REFUSED)
        data = records()
        data[2]["artifacts"]["observer"] = "0" * 64
        self.assertEqual(assess(*data).status, Status.REFUSED)
        data = records()
        data[0]["artifacts"]["observer"] = "A" * 64
        self.assertEqual(assess(*data).status, Status.REFUSED)

    def test_unbounded_and_non_plain_inputs_refuse(self):
        for value in (None, [], {"x": object()}, {"x": "x" * 513}, {str(i): i for i in range(65)}):
            with self.subTest(value=type(value).__name__):
                data = list(records())
                data[0] = value
                self.assertEqual(assess(*data).status, Status.REFUSED)
        data = records()
        data[3]["unexpected"] = "green"
        self.assertEqual(assess(*data).status, Status.REFUSED)


def subject_record():
    from host_custody_contract import LIMIT_FIELDS, ARTIFACT_BASENAMES
    limits = {key: 100 for key in LIMIT_FIELDS}
    limits.update(launch_attempts=1, collection_attempts=1)
    record = dict(schema="CustodySubjectV1", repository="owner/repo", recipe_revision="1"*40,
                  source_revision="2"*40, workflow_path=".github/workflows/proof.yml",
                  workflow_blob="3"*40, run=42, attempt=1, job="custody", branch="main",
                  trust_model="trusted-host-isolated-payload-v1", profile="custody-fixture",
                  build_artifact_id="artifact1", limits=limits, strict_eligible=False)
    for key in ("build_manifest_digest", "loader_policy_digest", "libc_identity_digest",
                "loader_config_policy_digest", "collector_source_digest", "collector_config_digest",
                "unit_template_digest", "effective_property_policy_digest", "output_schema_digest",
                "payload_cage_policy_digest"):
        record[key] = "a" * 64
    record["artifacts"] = {role: dict(size=1, sha256="b" * 64, file_type="regular",
                                      mode=0o555 if role == "observer" else 0o444)
                           for role in ARTIFACT_BASENAMES}
    return record


def custody_records():
    from host_custody_contract import subject_digest, snapshot_digest, launch_digest, unit_name
    subject = subject_record()
    artifacts = {}
    for index, (role, approved) in enumerate(subject["artifacts"].items(), 10):
        artifacts[role] = dict(size=approved["size"], sha256=approved["sha256"], device=1, inode=index,
                               uid=0, gid=0, mode=approved["mode"], nlink=1)
    snapshot = dict(subject_digest=subject_digest(subject),
                    directory=dict(device=1, inode=2, uid=0, gid=0, mode=0o700, nlink=2),
                    artifacts=artifacts, utilities=[dict(path="/usr/bin/dd", sha256="f"*64,
                                                        argv=["/usr/bin/dd"], exit_code=0)],
                    all_verified_before_exposure=True, no_retained_writers=True)
    launch = dict(subject_digest=subject_digest(subject), snapshot_digest=snapshot_digest(subject, snapshot),
                  boot_id="boot", manager_owner=":1.0", manager_uid=0, manager_pid=1,
                  unit_name=unit_name(subject), unit_object="/org/freedesktop/systemd1/unit/test",
                  invocation_id="invocation", observer_uid=1001, observer_gid=1001, collector_uid=1002,
                  payload_uid=1003, effective_properties_digest="c"*64, main_pid=200, exec_main_pid=200,
                  cgroup="/system.slice/test", start_monotonic=10,
                  control_descriptor=dict(kind="pipe", direction="collector-to-observer", inherited=True))
    output = dict(device=1, inode=30, uid=1002, gid=1002, mode=0o600, nlink=1, size=1, sha256="d"*64)
    terminal = {k: launch[k] for k in ("subject_digest", "snapshot_digest", "boot_id", "manager_owner",
                                       "unit_name", "unit_object", "invocation_id", "exec_main_pid",
                                       "start_monotonic")}
    terminal.update(launch_digest=launch_digest(subject, snapshot, launch), exit_monotonic=20,
                    exec_main_code=1, exec_main_status=0, result="success", n_restarts=0,
                    outputs=dict(stdout=output, stderr=dict(output, inode=31)),
                    export=dict(identity="artifact", size=2, sha256="e"*64, readback_sha256="e"*64))
    return subject, snapshot, launch, terminal


class V1ContractTests(unittest.TestCase):
    def test_joined_records_and_typed_digest(self):
        from host_custody_contract import validate_terminal, subject_digest
        subject, snapshot, launch, terminal = custody_records()
        validate_terminal(subject, snapshot, launch, terminal)
        self.assertEqual(subject_digest(subject), subject_digest(dict(reversed(list(subject.items())))))

    def test_malformed_subject_and_limits(self):
        from host_custody_contract import validate_subject
        for key, value in (("strict_eligible", True), ("attempt", True), ("branch", ""),
                           ("trust_model", "other"), ("profile", "unknown")):
            subject = subject_record()
            subject[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_subject(subject)
        for key, value in (("staging_temp_bytes", 0), ("export_bytes", True),
                           ("observer_deadline_ms", float("inf")), ("launch_attempts", 2)):
            subject = subject_record()
            subject["limits"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_subject(subject)
        subject = subject_record()
        subject["command"] = "/bin/sh"
        with self.assertRaises(ValueError):
            validate_subject(subject)

    def test_mismatches_and_unsafe_terminal(self):
        from host_custody_contract import validate_terminal
        for index, key, value in ((1, "subject_digest", "0"*64), (2, "manager_pid", 2),
                                  (2, "snapshot_digest", "0"*64), (3, "invocation_id", "other"),
                                  (3, "exec_main_code", 2), (3, "n_restarts", 1),
                                  (3, "exec_main_status", True), (3, "exit_monotonic", 10)):
            data = list(custody_records())
            data[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                validate_terminal(*data)
        data = list(custody_records())
        data[3]["export"]["readback_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            validate_terminal(*data)


if __name__ == "__main__":
    unittest.main()
