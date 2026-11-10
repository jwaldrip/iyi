import copy
import unittest

import host_custody_systemd as systemd
from host_custody_authorization import AuthorizationRefused


class UnitPolicyTests(unittest.TestCase):
    def setUp(self):
        self.name = systemd.unit_name(123, 2, "a" * 64)
        self.properties = systemd.expected_prestart_properties(self.name)

    def test_fixture_policy_and_template(self):
        systemd.validate_prestart(self.name, self.properties)
        text = systemd.render_unit(self.name)
        self.assertIn("DynamicUser=yes\n", text)
        self.assertIn("CapabilityBoundingSet=\n", text)
        self.assertIn("StandardInput=fd:control\n", text)
        self.assertNotIn("sudo", text)

    def test_prestart_rejects_effective_overrides(self):
        changes = {
            "DropInPaths": ["/run/systemd/system/example.service.d/override.conf"],
            "User": "root", "SupplementaryGroups": ["sudo"],
            "AmbientCapabilities": 1, "CapabilityBoundingSet": 1,
            "ExecStartPre": [["/usr/bin/sudo", ["/usr/bin/sudo"], False, 0, 0, 0, 0, 0, 0, 0]],
            "SuccessExitStatus": [[1], []], "ActiveState": "active",
            "MainPID": 43, "NoNewPrivileges": False,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                props = copy.deepcopy(self.properties)
                props[key]["data"] = [value]
                with self.assertRaises(systemd.CustodyRefused):
                    systemd.validate_prestart(self.name, props)
        props = copy.deepcopy(self.properties)
        props["ExecStart"]["data"][0][0][0] = "/bin/sh"
        with self.assertRaises(systemd.CustodyRefused):
            systemd.validate_prestart(self.name, props)

    def test_types_unknown_properties_and_unit_name_are_closed(self):
        for mutate in (lambda p: p["DynamicUser"].update(data=[1]),
                       lambda p: p["MainPID"].update(type="s"),
                       lambda p: p.update(Unexpected={"type": "s", "data": [""]}),
                       lambda p: p.pop("DropInPaths")):
            props = copy.deepcopy(self.properties)
            mutate(props)
            with self.assertRaises(systemd.CustodyRefused):
                systemd.validate_prestart(self.name, props)
        for bad in ("../../evil.service", "x.service", "iyi-custody-0-1-" + "a" * 64 + ".service"):
            with self.assertRaises(systemd.CustodyRefused):
                systemd.render_unit(bad)

    def test_fake_manager_cannot_start_before_validation(self):
        class FakeManager:
            def __init__(self):
                self.validated = False
                self.starts = 0
            def validate(self, name, props):
                systemd.validate_prestart(name, props)
                self.validated = True
            def start(self):
                if not self.validated:
                    raise systemd.CustodyRefused("prestart validation required")
                self.starts += 1
        fake = FakeManager()
        with self.assertRaises(systemd.CustodyRefused):
            fake.start()
        self.assertEqual(fake.starts, 0)
        fake.validate(self.name, self.properties)
        fake.start()
        self.assertEqual(fake.starts, 1)

    def test_production_entry_is_not_a_fake_backend(self):
        with self.assertRaises(AuthorizationRefused):
            systemd.launch({})


if __name__ == "__main__":
    unittest.main()
