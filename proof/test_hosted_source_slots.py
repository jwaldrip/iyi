import dataclasses
import unittest

from proof.hosted_contracts import (
    ObserverObjectIdentity, ObserverTaskIdentity, ObserverTransactionIdentity,
    ReferenceIntegrityError, StrictHaltRefusal, TypeValidationError,
    canonical_json_bytes, sha256_bytes,
)
from proof.hosted_source_slots import inspect_declared_sites, require_source_callsite_attribution


class SourceSiteTests(unittest.TestCase):
    def setUp(self):
        self.script = b'#!/bin/sh\n"$IYI" build "$@"\n'
        self.script_sha = sha256_bytes(self.script)
        self.census = {
            "census_version": 1, "driver": "example",
            "script": "bench/std_example_exercise.sh", "script_sha256": self.script_sha,
            "sites": [{"lines": [2], "command": "build", "kind": "canonical-own",
                       "contains": ['"$IYI" build "$@"'], "variants": []}],
        }

    def inspect(self, census=None, script=None):
        data = canonical_json_bytes(self.census if census is None else census)
        return inspect_declared_sites(driver="example", script_bytes=self.script if script is None else script,
                                      census_bytes=data, expected_script_sha256=self.script_sha,
                                      expected_census_sha256=sha256_bytes(data))

    def test_site_claim_is_bound_to_both_inputs_but_not_authority(self):
        (site,) = self.inspect()
        self.assertEqual(site.lines, (2,))
        self.assertEqual(site.script_sha256, self.script_sha)
        with self.assertRaises(StrictHaltRefusal):
            require_source_callsite_attribution()

    def test_rejects_source_mismatch_and_duplicate_line(self):
        with self.assertRaises(ReferenceIntegrityError):
            self.inspect(script=b'changed')
        broken = dict(self.census)
        broken["sites"] = [self.census["sites"][0], self.census["sites"][0]]
        with self.assertRaises(ReferenceIntegrityError):
            self.inspect(census=broken)

    def test_rejects_forged_fragments(self):
        broken = dict(self.census)
        broken["sites"] = [dict(self.census["sites"][0], contains=["forged"])]
        with self.assertRaises(ReferenceIntegrityError):
            self.inspect(census=broken)

    def test_rejects_census_digest_mismatch_and_duplicate_json_keys(self):
        data = canonical_json_bytes(self.census)
        with self.assertRaises(ReferenceIntegrityError):
            inspect_declared_sites(driver="example", script_bytes=self.script, census_bytes=data,
                                   expected_script_sha256=self.script_sha, expected_census_sha256="0" * 64)
        data = b'{"driver":"example","driver":"forged"}'
        from proof.hosted_contracts import DuplicateKeyError
        with self.assertRaises(DuplicateKeyError):
            inspect_declared_sites(driver="example", script_bytes=self.script, census_bytes=data,
                                   expected_script_sha256=self.script_sha, expected_census_sha256=sha256_bytes(data))


class ObserverIdentityTests(unittest.TestCase):
    def test_exact_task_and_transaction_identity(self):
        task = ObserverTaskIdentity("launch-1", 2, 2, 3, 4, 5)
        transaction = ObserverTransactionIdentity("launch-1", 1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            task.tid = 7
        self.assertEqual(transaction.supervisor_sequence, 1)
        with self.assertRaises(TypeValidationError):
            ObserverTaskIdentity("launch-1", 2, 2, True, 4, 5)
        with self.assertRaises(TypeValidationError):
            ObserverTransactionIdentity("launch-1", 0)

    def test_object_fields_do_not_establish_custody(self):
        identity = ObserverObjectIdentity(0, 2, 3, 4, 0o100644, 0, "a" * 64)
        self.assertEqual(identity.size, 0)
        with self.assertRaises(TypeValidationError):
            ObserverObjectIdentity(0, 2, 3, 4, 0o100644, 0, "bad")
        with self.assertRaises(TypeValidationError):
            ObserverObjectIdentity(0, 2, 3, 4, 0o040755, 0, "a" * 64)


if __name__ == "__main__":
    unittest.main()
