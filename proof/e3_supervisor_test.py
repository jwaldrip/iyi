"""Pure sequence fixtures. These tests do not execute or attach to processes."""
import unittest
from dataclasses import replace

from e3_supervisor_fixture import Fixture, Object, Refused


class SupervisorFixtureTest(unittest.TestCase):
    def setUp(self):
        self.obj = Object(mount=7, device=11, inode=13, links=2,
                          regular=True, data=b"native fixture bytes")
        self.fixture = Fixture(max_tasks=4, max_events=32, max_bytes=100,
                               max_descriptors=4)
        self.fixture.add_root("root")

    def bind_and_reset(self):
        self.fixture.bind(self.obj, self.obj)
        self.fixture.timestamp_reset(True)

    def test_lifecycle_is_not_admission(self):
        self.bind_and_reset()
        self.fixture.exec_stop("root", self.obj, successful=True)
        self.fixture.exit("root")
        # The original output name may already have been unlinked. The retained
        # object, not a later lookup of that name, is the fixture input here.
        self.fixture.teardown_sample(replace(self.obj, links=1))
        with self.assertRaisesRegex(Refused, "source attribution"):
            self.fixture.admission()

    def test_descendants_must_all_stop_before_binding(self):
        self.fixture.fork("root", "child", "clone")
        self.fixture.resume("child")
        with self.assertRaises(Refused):
            self.fixture.bind(self.obj, self.obj)
        with self.assertRaises(Refused):
            self.fixture.stop("child")  # a failure cannot be repaired into a pass

    def test_fork_vfork_clone_and_reuse(self):
        for kind in ("fork", "vfork", "clone"):
            child = "child-" + kind
            self.fixture.fork("root", child, kind)
            self.fixture.exit(child)
        with self.assertRaises(Refused):
            self.fixture.fork("root", "child-clone", "clone")

    def test_missing_output_and_inode_substitution_rejected(self):
        for output, ref in ((None, self.obj),
                            (self.obj, replace(self.obj, inode=14)),
                            (self.obj, replace(self.obj, mount=8)),
                            (self.obj, replace(self.obj, data=b"changed"))):
            with self.subTest(output=output, ref=ref):
                f = Fixture(max_tasks=1, max_events=4, max_bytes=100,
                            max_descriptors=2)
                f.add_root("root")
                with self.assertRaises(Refused):
                    f.bind(output, ref)

    def test_link_count_and_file_type(self):
        for obj in (replace(self.obj, links=1), replace(self.obj, regular=False)):
            with self.subTest(obj=obj):
                f = Fixture(max_tasks=1, max_events=4, max_bytes=100,
                            max_descriptors=2)
                f.add_root("root")
                with self.assertRaises(Refused):
                    f.bind(obj, obj)

    def test_exec_not_proven_by_failed_exec_or_same_bytes_other_inode(self):
        for obj, success in ((self.obj, False),
                             (replace(self.obj, inode=14), True)):
            with self.subTest(obj=obj, success=success):
                f = Fixture(max_tasks=1, max_events=8, max_bytes=100,
                            max_descriptors=2)
                f.add_root("root")
                f.bind(self.obj, self.obj)
                f.timestamp_reset(True)
                with self.assertRaises(Refused):
                    f.exec_stop("root", obj, successful=success)

    def test_teardown_requires_exit_and_unchanged_reference(self):
        self.bind_and_reset()
        self.fixture.exec_stop("root", self.obj, successful=True)
        with self.assertRaises(Refused):
            self.fixture.teardown_sample(self.obj)

    def test_changed_reference_after_exit(self):
        self.bind_and_reset()
        self.fixture.exec_stop("root", self.obj, successful=True)
        self.fixture.exit("root")
        with self.assertRaises(Refused):
            self.fixture.teardown_sample(replace(self.obj, data=b"changed"))

    def test_resource_budgets_fail_closed(self):
        for kwargs, action in (
            (dict(max_tasks=1, max_events=8, max_bytes=100, max_descriptors=2),
             lambda f: f.fork("root", "child", "fork")),
            (dict(max_tasks=2, max_events=1, max_bytes=100, max_descriptors=2),
             lambda f: f.resume("root")),
            (dict(max_tasks=2, max_events=8, max_bytes=1, max_descriptors=2),
             lambda f: f.bind(self.obj, self.obj)),
            (dict(max_tasks=2, max_events=8, max_bytes=100, max_descriptors=1),
             lambda f: f.bind(self.obj, self.obj)),
        ):
            with self.subTest(kwargs=kwargs):
                f = Fixture(**kwargs)
                f.add_root("root")
                with self.assertRaises(Refused):
                    action(f)
                with self.assertRaises(Refused):
                    f.admission()


if __name__ == "__main__":
    unittest.main()
