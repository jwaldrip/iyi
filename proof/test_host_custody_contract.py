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


if __name__ == "__main__":
    unittest.main()
