import copy
import hashlib
import tempfile
from pathlib import Path
from unittest.mock import patch
import json
import unittest

from proof.check_remote_strict_evidence import BINDING, check_outage_stage, check_outage_terminal, check_ownership_acks, check_ownership_failure


def encode(value):
    return json.dumps(value).encode()


class OutageOracleTests(unittest.TestCase):
    def test_receipt_sequence_and_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in (("ownership-ready", "ready\n"), ("ownership-flushed", "completed_term_flush\n"),
                                  ("ownership-pids", "child:10\ngrandchild:11\n"), ("term-timing", "10 0 12000000000\n")):
                (root / name).write_text(content)
            scratch = root / "run1" / "a1" / "rg9_work"
            scratch.mkdir(parents=True)
            (scratch / "ownership-scratch").write_text("preserve during ownership uncertainty\n")
            (root / "scratch-path").write_text(str(scratch))
            payload = b"receipt"
            digest = hashlib.sha256(payload).hexdigest()
            entries = []
            for number, (unit, kind) in enumerate((("plan", "plan"), ("pin", "checkpoint"), ("run1", "checkpoint"), ("terminal", "terminal-envelope")), 1):
                request = {key: "context" for key in BINDING}
                request.update(invocation_id="inv", execution_kind="synthetic", request_id=str(number), unit=unit, native_attempt=1,
                               snapshot_sequence=number, snapshot_kind=kind, chain_id=None if number == 1 else "chain",
                               archive_bytes=len(payload), archive_sha256=digest)
                ack = dict(request, verified=True, artifact_id=str(number), downloaded_bytes=len(payload), downloaded_sha256=digest)
                entries.append({"request": request, "ack": ack})
                (root / (str(number) + ".tar")).write_bytes(payload)
            index = {"invocation_id": "inv", "entries": entries, "ownership_recovery": {}}
            def check(data):
                with patch("proof.check_remote_strict_evidence.members", return_value={}), \
                     patch("proof.check_remote_strict_evidence.check_prior_archive"), \
                     patch("proof.check_remote_strict_evidence.check_outage_stage"), \
                     patch("proof.check_remote_strict_evidence.check_outage_terminal"):
                    check_ownership_failure(data, directory, "ownership-run1-outage", directory, {}, "compiler")
            with self.assertRaisesRegex(ValueError, "ownership failure was resolved"):
                check(index)
            mutations = [
                lambda e: e.pop(), lambda e: e.reverse(), lambda e: e.append(copy.deepcopy(e[-1])),
                lambda e: e[3]["request"].update(snapshot_kind="checkpoint"),
                lambda e: e[2]["request"].update(chain_id="other"),
                lambda e: e[2]["request"].update(native_attempt=2),
                lambda e: e[2]["ack"].update(artifact_id="1"),
            ]
            for mutate in mutations:
                changed = copy.deepcopy(index)
                mutate(changed["entries"])
                with self.assertRaises(ValueError) as caught:
                    check(changed)
                self.assertNotIn("ownership failure was resolved", str(caught.exception))
            for position, field, value, message in (
                (3, "snapshot_kind", "checkpoint", "prior receipt snapshot identity invalid"),
                (2, "chain_id", "other", "prior receipt chain identity invalid"),
                (2, "native_attempt", 2, "prior receipt snapshot identity invalid"),
            ):
                changed = copy.deepcopy(index)
                for side in ("request", "ack"):
                    changed["entries"][position][side][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                    check(changed)
            (root / "3.tar").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "payload altered"):
                check(index)

    def test_failure_snapshot_and_negative_controls(self):
        record = {"unit": "run1", "attempt": 1, "disposition": "OWNERSHIP_UNRESOLVED", "ownership_resolved": False,
                  "ownership_result": {"proof_resolved": False, "taint_reasons": ["synthetic permanent census outage"]},
                  "cleanup_performed": False, "reclaimed_bytes": 0}
        rows = [{"type": "stage-intent", "unit": unit} for unit in ("plan", "pin", "run1")] + [record]
        def check(value):
            check_outage_stage({"controller/stage-journal.jsonl": b"\n".join(map(encode, value))}, "run1", ["plan", "pin", "run1"])
        check(rows)
        for field, value in (("disposition", "ACCEPTED"), ("ownership_resolved", True), ("cleanup_performed", True), ("reclaimed_bytes", 1)):
            changed = copy.deepcopy(rows)
            changed[-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)
        for field, value in (("proof_resolved", True), ("taint_reasons", [])):
            changed = copy.deepcopy(rows)
            changed[-1]["ownership_result"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(changed)
        with self.assertRaises(ValueError):
            check(rows + [{"type": "stage-intent", "unit": "run2"}])

    def test_ack_order_and_binding(self):
        journal = [{"event": "registered", "unit": u, "native_attempt": 1, "pid": n} for n, u in enumerate(("plan", "pin", "run1"), 10)]
        acks = []
        for row in journal:
            common = {"protocol_version": 1, "invocation_id": "inv", "unit": row["unit"], "native_attempt": 1, "pid": row["pid"]}
            acks.append(dict(common, event="ownership-register-ack", request_id=row["unit"] + "-register", verified=True))
            verified = row["unit"] != "run1"
            acks.append(dict(common, event="ownership-resolve-ack", request_id=row["unit"] + "-resolve", verified=verified, ownership_result={"proof_resolved": verified}))
        index = {"invocation_id": "inv", "ownership_control_acks": acks, "controller_signal": None}
        check_ownership_acks(index, journal, "ownership-run1-outage")
        mutations = [lambda a: a.pop(), lambda a: a.reverse(), lambda a: a.append(copy.deepcopy(a[-1])),
                     lambda a: a[1].update(pid=999), lambda a: a[-1].update(verified=True),
                     lambda a: a[0].update(verified=False)]
        for mutate in mutations:
            changed = copy.deepcopy(index)
            mutate(changed["ownership_control_acks"])
            with self.assertRaises(ValueError):
                check_ownership_acks(changed, journal, "ownership-run1-outage")
        changed = copy.deepcopy(index)
        resolution = changed["ownership_control_acks"][-1]
        resolution["verified"] = True
        resolution["ownership_result"]["proof_resolved"] = True
        with self.assertRaisesRegex(ValueError, "incorrect ownership resolution"):
            check_ownership_acks(changed, journal, "ownership-run1-outage")

    def test_terminal_failure_controls(self):
        entries = [{"request": {"chain_id": None if i == 0 else "chain"}, "ack": {"id": i}} for i in range(4)]
        record = {"unit": "run1", "attempt": 1, "disposition": "OWNERSHIP_UNRESOLVED", "result_status": "FAIL", "ownership_resolved": False,
                  "ownership_result": {"proof_resolved": False, "taint_reasons": ["synthetic permanent census outage"]}, "cleanup_performed": False, "reclaimed_bytes": 0}
        summary = {"invocation_id": "inv", "chain_id": "chain", "overall_status": "INTERRUPTED_BY_HOSTING_BUDGET", "ownership_resolved": False,
                   "final_checkpoint": None, "records": [{"unit": "plan"}, {"unit": "pin"}, record]}
        terminal = {"invocation_id": "inv", "chain_id": "chain", "status": "INTERRUPTED_BY_HOSTING_BUDGET", "final_checkpoint": None,
                    "checkpoint_receipts": [entry["ack"] for entry in entries[:3]]}
        def check(s, t):
            check_outage_terminal({"controller/strict-controller-summary.json": encode(s), "controller/terminal-envelope.json": encode(t)}, entries, {"invocation_id": "inv"})
        check(summary, terminal)
        for field, value in (("status", "PASS"), ("final_checkpoint", {}), ("checkpoint_receipts", []), ("chain_id", "wrong")):
            changed = copy.deepcopy(terminal)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(summary, changed)
        changed = copy.deepcopy(summary)
        changed["records"][2]["disposition"] = "ACCEPTED"
        with self.assertRaises(ValueError):
            check(changed, terminal)
