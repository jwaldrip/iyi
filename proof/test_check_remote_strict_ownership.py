import copy
import json
import unittest

from proof.check_remote_strict_evidence import check_outage_stage, check_outage_terminal, check_ownership_acks


def encode(value):
    return json.dumps(value).encode()


class OutageOracleTests(unittest.TestCase):
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
