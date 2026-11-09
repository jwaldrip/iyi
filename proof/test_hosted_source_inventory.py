"""Pure source inventory tests with an in-memory Git-object backend."""
import base64
import dataclasses
import hashlib
import unittest
from unittest.mock import patch

from proof.hosted_contracts import ReferenceIntegrityError, TypeValidationError, canonical_json_bytes, parse_strict_json
from proof.hosted_source_slots import (
    derive_provisional_corpus, derive_provisional_driver_censuses,
    provisional_manifest_bytes,
)


class MockGit:
    OLD = "a" * 40
    PRODUCT = "b" * 40
    WITNESS = "c" * 40

    def __init__(self):
        self.trees = {self.OLD: {}, self.PRODUCT: {}, self.WITNESS: {}}
        self.objects = {}
        self.duplicate_path = None
        self.bad_blob = None
        selector = (b"samples = sorted(glob.glob(os.path.join(repo, 'samples/iyi/*.iyi')))\n"
                    b"bench = sorted(glob.glob(os.path.join(repo, 'bench/std_*_exercise.iyi')))\n"
                    b"programs = samples + bench\n") * 2
        for commit in (self.OLD, self.PRODUCT):
            self.add(commit, "bench/stale_equivalence.sh", selector)
            for i in range(28):
                self.add(commit, f"samples/iyi/sample_{i}.iyi", f"sample-{i}".encode())
            for i in range(114):
                self.add(commit, f"bench/std_program_{i}_exercise.iyi", f"exercise-{i}".encode())
        for name in ("parallel", "unit"):
            self.add(self.PRODUCT, f"bench/std_{name}_exercise.iyi", name.encode())
        self.add(self.PRODUCT, "bench/std_siblings.sh",
                 b'for sibling in "$REPO"/bench/std_*_exercise.sh; do\n')
        names = ["compress", "fuzz", "math"] + [f"fixture_{i}" for i in range(26)]
        for name in names:
            self.add_driver(name)
        for i in range(117 - len(names)):
            self.add(self.PRODUCT, f"bench/std_sibling_{i}_exercise.sh", b"#!/bin/sh\n")

    def add(self, commit, path, data):
        oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        self.objects[oid] = data
        self.trees[commit][path] = oid

    def add_driver(self, name):
        positive = name in ("compress", "math")
        output_name = {"compress": "small.bin", "math": "software/program", "fuzz": "fuzz"}.get(name, "program")
        output = "{WORK}/" + output_name
        token = f'"$WORK/{output_name}"'
        source = (f'"$IYI" build -o {token} "$REPO/bench/std_{name}_exercise.iyi"\n'
                  + f'{token} all\n'
                  + (f'{token} corpus x509\n{token} corpus hpack\n' if name == "fuzz" else ""))
        script = source.encode()
        path = f"bench/std_{name}_exercise.sh"
        self.add(self.PRODUCT, path, script)
        self.add(self.WITNESS, path, script)
        variants = []
        if positive:
            variants.append({"id": f"{name}.positive", "kind": "positive", "first_root": "{WORK}",
                             "vars": {}, "sources": [f"{{REPO}}/bench/std_{name}_exercise.iyi"],
                             "output": output, "darwin": "required", "linux": "required",
                             "requires": ["python3"], "verdict": {"lines": [2], "contains": [token]}})
        census = {"census_version": 1, "driver": name, "script": path,
                  "script_sha256": hashlib.sha256(script).hexdigest(),
                  "sites": [{"lines": [1], "command": "build", "kind": "positive" if positive else "canonical-own",
                             "contains": [source.splitlines()[0]], "variants": variants}],
                  "non_invocations": [], "skips": [{"line": 1, "what": "sentinel"}],
                  "not_skips": [], "pass_sentinel": {"line": 2, "text": "sentinel"},
                  "exec_evidence": [{"site_line": 1, "out_template": output, "name_from_calls": {},
                                     "exec_lines": [2, 3, 4] if name == "fuzz" else [2],
                                     "exec_token": token, "verdict_lines": [2],
                                     "failure_marks": ["failure"], "refs_ok": []}]}
        self.add(self.WITNESS, f"proof/census/{name}.json", canonical_json_bytes(census))

    def __call__(self, repo, *args):
        if args[0] == "rev-parse":
            return (args[2].removesuffix("^{commit}") + "\n").encode()
        if args[0] == "ls-tree":
            tree = self.trees[args[-1]]
            rows = [f"100644 blob {oid}\t{path}".encode() + b"\0" for path, oid in sorted(tree.items())]
            if self.duplicate_path is not None and self.duplicate_path in tree:
                rows.append(f"100644 blob {tree[self.duplicate_path]}\t{self.duplicate_path}".encode() + b"\0")
            return b"".join(rows)
        if args[:2] == ("cat-file", "blob"):
            return b"corrupted" if args[2] == self.bad_blob else self.objects[args[2]]
        raise AssertionError(args)


class ProvisionalInventoryTests(unittest.TestCase):
    def setUp(self):
        self.git = MockGit()
        self.patch = patch("proof.hosted_source_slots._git", side_effect=self.git)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def corpus(self):
        return derive_provisional_corpus(product_repo="fake", original_commit=MockGit.OLD,
                                         product_commit=MockGit.PRODUCT)

    def drivers(self):
        return derive_provisional_driver_censuses(product_repo="fake", product_commit=MockGit.PRODUCT,
                                                  witness_repo="fake", witness_commit=MockGit.WITNESS)

    def test_corpus_preserves_original_and_both_additions(self):
        corpus = self.corpus()
        self.assertEqual((len(corpus.original), len(corpus.additions), len(corpus.siblings)), (142, 2, 117))
        self.assertEqual({item.path for item in corpus.additions},
                         {"bench/std_parallel_exercise.iyi", "bench/std_unit_exercise.iyi"})
        self.assertFalse(corpus.strict_eligible)
        self.assertEqual(len(corpus.original[0].sha256), 64)

    def test_rejects_missing_original_and_wrong_blob(self):
        missing = self.git.trees[MockGit.PRODUCT].pop("samples/iyi/sample_0.iyi")
        with self.assertRaises(ReferenceIntegrityError):
            self.corpus()
        self.git.trees[MockGit.PRODUCT]["samples/iyi/sample_0.iyi"] = missing
        self.git.bad_blob = self.git.trees[MockGit.PRODUCT]["bench/stale_equivalence.sh"]
        with self.assertRaises(ReferenceIntegrityError):
            self.corpus()

    def test_duplicate_tree_entry_rejected(self):
        self.git.duplicate_path = "samples/iyi/sample_0.iyi"
        with self.assertRaises(ReferenceIntegrityError):
            self.corpus()

    def test_direct_sites_preserve_multiple_execs_without_extra_builds(self):
        drivers = {item.driver: item for item in self.drivers()}
        for name in ("compress", "fuzz", "math"):
            self.assertEqual(len(drivers[name].direct_evidence), 1)
            direct = drivers[name].direct_evidence[0]
            self.assertEqual(direct.control_flow_cardinality, "unresolved")
            self.assertEqual(len(direct.exec_lines), 3 if name == "fuzz" else 1)
            self.assertFalse(drivers[name].strict_eligible)
            self.assertEqual(drivers[name].source_callsite_attribution, "unavailable")

    def test_ambiguous_variant_remains_unexpanded(self):
        path = "proof/census/math.json"
        census = parse_strict_json(self.git.objects[self.git.trees[MockGit.WITNESS][path]])
        extra = dict(census["sites"][0]["variants"][0], id="math.second")
        census["sites"][0]["variants"].append(extra)
        self.git.add(MockGit.WITNESS, path, canonical_json_bytes(census))
        math = next(d for d in self.drivers() if d.driver == "math")
        self.assertEqual(math.direct_evidence, ())
        self.assertEqual(math.unexpanded_evidence_indices, (0,))

    def test_named_variant_ambiguity_never_becomes_attribution(self):
        path = "proof/census/math.json"
        script_path = "bench/std_math_exercise.sh"
        script = (b'"$IYI" build -o "$WORK/$name" "$REPO/bench/std_math_exercise.iyi"\n'
                  b'"$WORK/$name"\n'
                  b'build_and_run alpha --release\n')
        for commit in (MockGit.PRODUCT, MockGit.WITNESS):
            self.git.add(commit, script_path, script)
        census = parse_strict_json(self.git.objects[self.git.trees[MockGit.WITNESS][path]])
        census["script_sha256"] = hashlib.sha256(script).hexdigest()
        site = census["sites"][0]
        site["contains"] = [script.decode().splitlines()[0]]
        variant = site["variants"][0]
        variant["output"] = "{WORK}/{name}"
        variant["vars"] = {"name": {"lines": [3], "values": ["alpha"]}}
        site["variants"].append(dict(variant, id="math.second"))
        evidence = census["exec_evidence"][0]
        evidence["out_template"] = "{WORK}/{name}"
        evidence["exec_token"] = '"$WORK/$name"'
        evidence["name_from_calls"] = {"3": "alpha"}
        self.git.add(MockGit.WITNESS, path, canonical_json_bytes(census))
        math = next(d for d in self.drivers() if d.driver == "math")
        self.assertEqual(len(math.evidence_calls), 1)
        call = math.evidence_calls[0]
        self.assertEqual(set(call.candidate_variant_ids), {"math.positive", "math.second"})
        self.assertEqual(call.variant_mapping, "unresolved")
        self.assertEqual(call.control_flow_cardinality, "unresolved")
        self.assertFalse(math.strict_eligible)

    def test_manifest_roundtrips_complete_census_and_enforces_bounds(self):
        corpus, drivers = self.corpus(), self.drivers()
        total = sum(len(d.census_bytes) for d in drivers)
        manifest = parse_strict_json(provisional_manifest_bytes(corpus, drivers, max_census_bytes=total))
        by_driver = {item["driver"]: item for item in manifest["drivers"]}
        for driver in drivers:
            recovered = base64.b64decode(by_driver[driver.driver]["census_bytes_base64"], validate=True)
            self.assertEqual(recovered, driver.census_bytes)
            self.assertEqual(parse_strict_json(recovered)["skips"][0]["what"], "sentinel")
        with self.assertRaises(TypeValidationError):
            provisional_manifest_bytes(corpus, drivers, max_census_bytes=total - 1)
        corrupted = dataclasses.replace(drivers[0], census_bytes=b"changed")
        with self.assertRaises(ReferenceIntegrityError):
            provisional_manifest_bytes(corpus, (corrupted,) + drivers[1:], max_census_bytes=total + 1)


if __name__ == "__main__":
    unittest.main()
