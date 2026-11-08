#!/usr/bin/env python3
"""Independently check exact-ID downloaded synthetic checkpoint payloads."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from proof.remote_strict_fixtures import FAKE_STAGE_EMITTER_SOURCE
from proof.remote_strict_validation import canonical_drivers, revision

COUNTS = {"success": 37, "failed-plan": 1, "failed-pin": 2, "divergence": 6, "cleanup-failure": 4}
BINDING = ("protocol_version", "request_id", "invocation_id", "execution_kind", "repository", "run_id", "run_attempt", "job_id", "job_key", "p_sha", "w_sha", "c_sha", "fixture_sha256", "strict_manifest_sha256", "snapshot_kind", "chain_id", "unit", "native_attempt", "snapshot_sequence", "archive_bytes", "archive_sha256")
CONTEXT = ("invocation_id", "execution_kind", "repository", "run_id", "run_attempt", "job_id", "job_key", "p_sha", "w_sha", "c_sha", "fixture_sha256", "strict_manifest_sha256")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def members(path: Path) -> dict[str, bytes]:
    result = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            name = member.name
            parts = PurePosixPath(name).parts
            require(member.isfile() and not name.startswith("/") and parts and all(p not in (".", "..") for p in parts), "unsafe archive member")
            require(name not in result, "duplicate archive member")
            stream = archive.extractfile(member)
            require(stream is not None, "unreadable archive member")
            data = stream.read()
            require(len(data) == member.size, "short archive member")
            result[name] = data
    manifest = parse_json(result["evidence-manifest.json"])
    require(manifest.get("version") == 1 and isinstance(manifest.get("members"), list), "invalid evidence manifest")
    expected = {name: data for name, data in result.items() if name != "evidence-manifest.json"}
    listed = manifest["members"]
    require(len(listed) == len(expected) and len({item["path"] for item in listed}) == len(listed), "manifest inventory mismatch")
    for item in listed:
        data = expected.get(item["path"])
        require(data is not None and item["bytes"] == len(data) and item["sha256"] == hashlib.sha256(data).hexdigest(), "manifest content mismatch")
    return result


def parse_json(data: bytes):
    return json.loads(data.decode("utf-8"))


def execution_context(args) -> dict[str, str]:
    return {
        "invocation_id": args.invocation_id, "execution_kind": "synthetic",
        "repository": args.repository, "run_id": args.run_id, "run_attempt": args.run_attempt,
        "job_id": args.job_id, "job_key": args.job_key,
        "p_sha": revision(args.p), "w_sha": revision(args.w), "c_sha": revision(args.c),
        "fixture_sha256": hashlib.sha256(FAKE_STAGE_EMITTER_SOURCE.encode("utf-8")).hexdigest(),
        "strict_manifest_sha256": None,
    }


def probe_gone(pid: int) -> bool:
    """Point-probe a recorded descendant. Only a process that no longer exists counts as gone."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def check_prior_archive(archive: dict[str, bytes], request: dict, expected: dict, compiler: str) -> None:
    unit = request["unit"]
    require("controller/stage-journal.jsonl" in archive, "prior receipt journal absent")
    if unit != "terminal":
        require(f"controller-logs/{unit.replace('/', '_')}-a{request['native_attempt']}.log" in archive, "prior receipt stage log absent")
    if unit == "plan":
        require("meta/pin.json" not in archive, "plan receipt carries a pin")
        return
    require("meta/pin.json" in archive, "pin receipt lacks pin.json")
    pin = parse_json(archive["meta/pin.json"])
    require(pin.get("chain_id") == request["chain_id"] and pin.get("p_source_sha") == expected["p_sha"] and pin.get("w_head") == expected["w_sha"], "prior pin source or chain mismatch")
    require(os.path.realpath(str(pin.get("compiler_path", ""))) == os.path.realpath(compiler), "prior pin compiler path mismatch")
    require(pin.get("compiler_sha256") == hashlib.sha256(Path(compiler).read_bytes()).hexdigest(), "prior pin compiler digest mismatch")

def check_outage_stage(archive: dict[str, bytes], unit: str, stages: list[str]) -> None:
    journal = [json.loads(line) for line in archive["controller/stage-journal.jsonl"].splitlines()]
    intents = [row.get("unit") for row in journal if row.get("type") == "stage-intent"]
    require(intents == stages, "failure snapshot contains unexpected stage")
    records = [row for row in journal if row.get("unit") == unit and row.get("disposition") == "OWNERSHIP_UNRESOLVED"]
    require(len(records) == 1, "failure snapshot lacks unresolved stage")
    record = records[0]
    result = record.get("ownership_result") or {}
    require(record.get("attempt") == 1 and record.get("ownership_resolved") is False and result.get("proof_resolved") is False, "failure snapshot falsely resolved")
    require(record.get("cleanup_performed") is False and record.get("reclaimed_bytes") == 0, "failure snapshot cleaned")
    require(any("synthetic permanent census outage" in str(reason) for reason in result.get("taint_reasons", [])), "failure snapshot outage taint missing")


def check_outage_terminal(archive: dict[str, bytes], entries: list, index: dict) -> None:
    summary = parse_json(archive["controller/strict-controller-summary.json"])
    terminal = parse_json(archive["controller/terminal-envelope.json"])
    chain = entries[1]["request"]["chain_id"]
    require(summary.get("invocation_id") == index["invocation_id"] and summary.get("chain_id") == chain, "failure summary identity mismatch")
    require(summary.get("overall_status") == "INTERRUPTED_BY_HOSTING_BUDGET" and summary.get("ownership_resolved") is False and summary.get("final_checkpoint") is None, "failure summary falsely reports completion")
    records = summary.get("records")
    require(isinstance(records, list) and [r.get("unit") for r in records] == ["plan", "pin", "run1"], "unexpected attempted stage")
    run1 = records[2]
    ownership = run1.get("ownership_result") or {}
    require(run1.get("attempt") == 1 and run1.get("disposition") == "OWNERSHIP_UNRESOLVED" and run1.get("result_status") == "FAIL" and run1.get("ownership_resolved") is False and ownership.get("proof_resolved") is False, "run1 was not unresolved")
    require(run1.get("cleanup_performed") is False and run1.get("reclaimed_bytes") == 0, "unresolved run1 was cleaned")
    require(any("synthetic permanent census outage" in str(reason) for reason in ownership.get("taint_reasons", [])), "run1 outage taint missing")
    require(terminal.get("invocation_id") == index["invocation_id"] and terminal.get("chain_id") == chain and terminal.get("status") == "INTERRUPTED_BY_HOSTING_BUDGET" and terminal.get("final_checkpoint") is None, "terminal failure identity or status mismatch")
    require(terminal.get("checkpoint_receipts") == [entry["ack"] for entry in entries[:3]], "terminal checkpoint receipts mismatch")


def check_ownership_acks(index: dict, journal: list, case: str) -> None:
    acks = index["ownership_control_acks"]
    require(isinstance(acks, list) and acks, "ownership control ACKs missing")
    registered: dict[tuple, int] = {}
    for event in journal:
        if event.get("event") == "registered":
            key = (event.get("unit"), event.get("native_attempt"))
            require(key not in registered, "duplicate ownership registration")
            registered[key] = event.get("pid")
    by_event: dict[str, dict[tuple, dict]] = {"ownership-register-ack": {}, "ownership-resolve-ack": {}}
    request_ids: set[str] = set()
    for ack in acks:
        event = ack.get("event")
        require(event in by_event, "unexpected ownership ACK event")
        request_id = ack.get("request_id")
        require(isinstance(request_id, str) and request_id and request_id not in request_ids, "ownership ACK request ID missing or duplicate")
        request_ids.add(request_id)
        require(ack.get("protocol_version") == 1 and ack.get("invocation_id") == index["invocation_id"], "ownership ACK invocation binding mismatch")
        pid, unit, attempt = ack.get("pid"), ack.get("unit"), ack.get("native_attempt")
        require(isinstance(pid, int) and not isinstance(pid, bool) and pid > 1, "ownership ACK PID invalid")
        require(isinstance(unit, str) and isinstance(attempt, int) and not isinstance(attempt, bool) and attempt > 0, "ownership ACK attempt invalid")
        key = (unit, attempt)
        require(key in registered and registered[key] == pid, "ownership ACK has no matching journal registration")
        require(key not in by_event[event], "duplicate ownership ACK for stage")
        by_event[event][key] = ack
    expected_order = []
    for key in registered:
        expected_order.append(("ownership-register-ack", key))
        resolve = by_event["ownership-resolve-ack"].get(key)
        if resolve is None:
            require(index.get("controller_signal") == "SIGKILL", "tainted stage lacks ownership resolve ACK")
            continue
        expected_order.append(("ownership-resolve-ack", key))
        result = resolve.get("ownership_result")
        require(isinstance(result, dict) and isinstance(resolve.get("verified"), bool) and resolve["verified"] is result.get("proof_resolved"), "ownership ACK contradicts result")
        expected_verified = case == "ownership-run1-outage" and key[0] in ("plan", "pin")
        require(resolve["verified"] is expected_verified, "incorrect ownership resolution")
    require([(ack["event"], (ack["unit"], ack["native_attempt"])) for ack in acks] == expected_order, "ownership ACK sequence mismatch")
    require(all(ack.get("verified") is True for ack in by_event["ownership-register-ack"].values()), "ownership registration rejected")


def check_ownership_failure(index: dict, case_data_dir: str | None, case: str, downloads_dir: str | None = None, expected: dict | None = None, compiler: str | None = None) -> dict:
    require(case_data_dir is not None, "missing ownership fixture directory")
    root = Path(case_data_dir)
    require((root / "ownership-ready").read_text() == "ready\n", "ownership fixture not ready")
    require((root / "ownership-flushed").read_text() == "completed_term_flush\n", "12-second termination flush missing")
    lines = (root / "ownership-pids").read_text().splitlines()
    require(len(lines) == 2 and lines[0].startswith("child:") and lines[1].startswith("grandchild:"), "invalid ownership fixture PID list")
    pids = [int(line.split(":", 1)[1]) for line in lines]
    require(all(pid > 1 for pid in pids) and pids[0] != pids[1], "invalid descendant PIDs")
    timings = [line.split() for line in (root / "term-timing").read_text().splitlines()]
    require(any(len(row) == 3 and int(row[0]) == pids[0] and int(row[2]) - int(row[1]) >= 12_000_000_000 for row in timings), "child did not complete its 12-second flush")
    recovery = index["ownership_recovery"]
    entries = index["entries"]
    if case in ("ownership-run1-outage", "ownership-census-outage"):
        units = ["plan", "pin", "run1", "terminal"] if case == "ownership-run1-outage" else ["plan"]
        require([entry["request"]["unit"] for entry in entries] == units, "failure receipts missing or stage advanced")
        require(downloads_dir is not None and expected is not None and compiler is not None, "missing prior receipt context")
        ids = set()
        request_ids = set()
        for sequence, entry in enumerate(entries, 1):
            request, ack = entry["request"], entry["ack"]
            unit = request["unit"]
            require(all(key in request and key in ack and request[key] == ack[key] for key in BINDING), "prior receipt binding mismatch")
            require(request.get("invocation_id") == index["invocation_id"] and request.get("snapshot_sequence") == sequence and ack.get("verified") is True, "invalid prior receipt")
            require(request.get("execution_kind") == "synthetic" and all(request.get(k) == v for k, v in expected.items()), "prior receipt does not match execution context")
            request_id = request.get("request_id")
            require(isinstance(request_id, str) and request_id not in request_ids and ack.get("request_id") == request_id, "prior request ID invalid")
            request_ids.add(request_id)
            expected_kind = {"plan": "plan", "pin": "checkpoint", "run1": "checkpoint", "terminal": "terminal-envelope"}[unit]
            require(request.get("native_attempt") == 1 and request.get("snapshot_kind") == expected_kind, "prior receipt snapshot identity invalid")
            require(request.get("chain_id") == (None if unit == "plan" else entries[1]["request"]["chain_id"]) and (unit == "plan" or request.get("chain_id")), "prior receipt chain identity invalid")
            artifact_id = str(ack.get("artifact_id", ""))
            require(artifact_id.isdecimal() and artifact_id not in ids, "invalid prior artifact ID")
            ids.add(artifact_id)
            payload_path = Path(downloads_dir) / (artifact_id + ".tar")
            payload = payload_path.read_bytes()
            require(len(payload) == request["archive_bytes"] == ack.get("downloaded_bytes") and hashlib.sha256(payload).hexdigest() == request["archive_sha256"] == ack.get("downloaded_sha256"), "prior receipt payload altered")
            archive = members(payload_path)
            check_prior_archive(archive, request, expected, compiler)
            if unit == "terminal":
                check_outage_terminal(archive, entries, index)
            elif (case, unit) in (("ownership-run1-outage", "run1"), ("ownership-census-outage", "plan")):
                check_outage_stage(archive, unit, units[:-1] if case == "ownership-run1-outage" else units)
    else:
        require(entries == [], "unexpected checkpoint after ownership failure")
    if case == "ownership-run1-outage":
        scratch = Path((root / "scratch-path").read_text())
        require(scratch.is_absolute() and scratch.parts[-3:] == ("run1", "a1", "rg9_work") and not scratch.is_symlink() and not (scratch / "ownership-scratch").is_symlink() and (scratch / "ownership-scratch").read_text() == "preserve during ownership uncertainty\n", "run1 scratch was not preserved")
    # A crashed controller cannot persist a failure snapshot.
    require(recovery.get("proof_resolved") is False and recovery.get("taint_reasons"), "ownership failure was resolved")
    require(recovery.get("grace_sec") == 30, "native grace was not preserved")
    controller_signal, controller_exit = index.get("controller_signal"), index.get("exit_code")
    if case == "ownership-crash":
        require(controller_signal == "SIGKILL", "unexpected controller outcome: SIGKILL missing")
    else:
        observed_exit = isinstance(controller_exit, int) and not isinstance(controller_exit, bool) and controller_exit != 0
        require(controller_signal is not None or observed_exit, "unexpected controller outcome: no observed signal or nonzero exit")
    if case == "ownership-crash":
        holder_pid = int((root / "pipe-holder-ready").read_text())
        require(holder_pid > 1 and holder_pid not in pids, "request pipe holder missing")
        lifecycle = index["lifecycle"]
        events = {name: [item for item in lifecycle if item.get("event") == name]
                  for name in ("controller-exit", "recovery-started", "request-eof")}
        require(all(len(items) == 1 for items in events.values()), "missing or repeated lifecycle event")
        require(events["controller-exit"][0].get("signal") == "SIGKILL", "controller SIGKILL missing")
        require(events["controller-exit"][0]["monotonic_ms"] <= events["recovery-started"][0]["monotonic_ms"] < events["request-eof"][0]["monotonic_ms"], "recovery did not start before retained writer EOF")
    journal = index["ownership_journal"]
    require(isinstance(journal, list) and journal and journal[0].get("event") == "active", "active ownership record missing")
    require(journal[0].get("context", {}).get("invocation_id") == index["invocation_id"], "ledger invocation mismatch")
    if case in ("ownership-census-outage", "ownership-run1-outage"):
        require(any("synthetic permanent census outage" in str(reason) for reason in recovery["taint_reasons"]), "census outage taint missing")
    unresolved = [event for event in journal if event.get("event") == "unresolved"]
    require(unresolved, "durable unresolved event missing")
    if case in ("ownership-census-outage", "ownership-run1-outage"):
        require(any("synthetic permanent census outage" in json.dumps(event, sort_keys=True) for event in unresolved), "persisted outage reason missing")
    registrations = [(event.get("unit"), event.get("native_attempt")) for event in journal if event.get("event") == "registered"]
    expected_stages = [("plan", 1), ("pin", 1), ("run1", 1)] if case == "ownership-run1-outage" else [("plan", 1)]
    require(registrations == expected_stages, "unexpected stage launch or native retry")
    committed = {}
    for event in journal:
        kind = event.get("event")
        if kind in ("registered", "observed", "signaled"):
            identity = tuple(event.get(key) for key in ("pid", "birth", "root_pid", "unit", "native_attempt"))
            require(isinstance(identity[0], int) and identity[0] > 1 and isinstance(identity[1], str) and identity[1] and isinstance(identity[2], int) and identity[2] > 1 and isinstance(identity[3], str) and identity[3] and isinstance(identity[4], int) and identity[4] > 0, "invalid journal identity")
            if kind in ("registered", "observed"):
                require(identity[0] not in committed or committed[identity[0]] == identity, "changed committed identity")
                committed[identity[0]] = identity
            else:
                require(committed.get(identity[0]) == identity, "signal lacks prior committed identity")
                require(event.get("signal") in ("SIGTERM", "SIGKILL") and isinstance(event.get("monotonic_ms"), (int, float)), "invalid signal evidence")
    require(all(pid in committed for pid in pids), "descendant identity absent from ownership journal")
    for pid in pids:
        require(any(e.get("event") == "signaled" and e.get("pid") == pid and e.get("signal") == "SIGTERM" for e in journal), "descendant TERM missing")
    stubborn = pids[1]
    terms = [e["monotonic_ms"] for e in journal if e.get("event") == "signaled" and e.get("pid") == stubborn and e.get("signal") == "SIGTERM"]
    kills = [e["monotonic_ms"] for e in journal if e.get("event") == "signaled" and e.get("pid") == stubborn and e.get("signal") == "SIGKILL"]
    require(len(terms) == len(kills) == 1 and kills[0] - terms[0] >= 30000, "stubborn process was not escalated after native grace")
    outcomes = recovery["recovery"]
    require(set(outcomes) == {"terminated", "absent", "replaced", "unverifiable", "survivors"}, "invalid recovery buckets")
    require(not outcomes["replaced"] and not outcomes["unverifiable"] and not outcomes["survivors"], "fixture processes not reclaimed")
    require(set(pids) <= {entry["pid"] for entry in outcomes["terminated"]}, "descendant recovery missing")
    for pid in pids:
        require(probe_gone(pid), "reported descendant still alive after recovery")
    for entry in outcomes["terminated"]:
        require(probe_gone(entry["pid"]), "terminated descendant still alive after recovery")
    for bucket in outcomes.values():
        for entry in bucket:
            require(committed.get(entry["pid"]) == tuple(entry.get(key) for key in ("pid", "birth", "root_pid", "unit", "native_attempt")), "recovery identity not committed")
    check_ownership_acks(index, journal, case)
    return {"case": case, "invocation_id": index["invocation_id"], "execution_kind": "synthetic", "controller_signal": index.get("controller_signal"), "observed_pids": pids, "flush_timings": timings, "prior_receipts": entries, "lifecycle": index.get("lifecycle", []), "ownership_recovery": recovery, "ownership_journal": journal}


def check_quarantine_retry(index: dict, retry: dict, before: bytes, after: bytes) -> None:
    require(bool(before) and before == after, "quarantine ledger changed during refused restart")
    require([json.loads(line) for line in before.splitlines()] == index["ownership_journal"], "ledger differs from recorded journal")
    guard = retry.get("ownership_guard_refusal", {})
    require(retry.get("invocation_id") == "synthetic-restart-attempt" and retry.get("entries") == [], "invalid retry invocation")
    require(guard.get("reason") == "existing-ownership-guard" and guard.get("controller_spawned") is False and guard.get("ledger") == index["ownership_ledger"], "retry was not refused by ownership guard")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True)
    parser.add_argument("--downloads-dir", required=True)
    parser.add_argument("--case", required=True, choices=(*COUNTS, "ownership-crash", "ownership-census-outage", "ownership-run1-outage"))
    parser.add_argument("--w", required=True, help="actual audited W checkout")
    parser.add_argument("--p", required=True, help="actual P checkout")
    parser.add_argument("--c", required=True, help="actual controller checkout")
    parser.add_argument("--compiler", required=True, help="synthetic compiler used by this invocation")
    for name in ("repository", "run-id", "run-attempt", "job-id", "job-key", "invocation-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expected-divergence")
    parser.add_argument("--case-data-dir")
    parser.add_argument("--report")
    args = parser.parse_args()
    index = json.loads(Path(args.index).read_text(encoding="utf-8"))
    if args.case in ("ownership-crash", "ownership-census-outage", "ownership-run1-outage"):
        require(index.get("execution_kind") == "synthetic" and index.get("invocation_id") == args.invocation_id, "ownership context mismatch")
        report = check_ownership_failure(index, args.case_data_dir, args.case, args.downloads_dir, execution_context(args), args.compiler)
        if args.report:
            Path(args.report).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return 0
    entries = index["entries"]
    require(len(entries) == COUNTS[args.case], "unexpected checkpoint count")
    require(index.get("execution_kind") == "synthetic", "wrong execution kind")
    exit_code = index.get("exit_code")
    require(isinstance(exit_code, int) and not isinstance(exit_code, bool), "missing controller exit code")
    require((exit_code == 0) == (args.case == "success"), "unexpected controller outcome")
    drivers = canonical_drivers(args.w) + ["synthetic_exclusion_addition", "synthetic_artifact_addition"]
    expected_units = {
        "success": ["plan", "pin", "run1", "run2"] + ["run3/" + d for d in drivers] + ["final", "terminal"],
        "failed-plan": ["plan"],
        "failed-pin": ["plan", "pin"],
        "divergence": ["plan", "pin", "run1", "run2", "run3/" + drivers[0], "terminal"],
        "cleanup-failure": ["plan", "pin", "run1", "terminal"],
    }[args.case]
    require([entry["request"]["unit"] for entry in entries] == expected_units, "checkpoint order or unit mismatch")
    context = None
    request_ids = set()
    established_chain = None
    ids = set()
    archives = []
    report_entries = []
    for sequence, entry in enumerate(entries, 1):
        request, ack = entry["request"], entry["ack"]
        require(request.get("event") == "persistence-request" and ack.get("event") == "persistence-ack", "wrong event type")
        require(all(key in request and key in ack and request[key] == ack[key] for key in BINDING), "receipt binding mismatch")
        require(request["protocol_version"] == 1 and request["snapshot_sequence"] == sequence, "invalid protocol or sequence")
        require(isinstance(request["request_id"], str) and request["request_id"] and request["request_id"] not in request_ids, "duplicate or empty request ID")
        request_ids.add(request["request_id"])
        require(request["invocation_id"] == index.get("invocation_id") and request["execution_kind"] == "synthetic", "invocation mismatch")
        current_context = tuple(request.get(k) for k in CONTEXT)
        require(all(current_context) and (context is None or current_context == context), "missing or changed context")
        context = current_context
        expected_context = execution_context(args)
        require(all(request.get(k) == v for k, v in expected_context.items()), "request does not match actual execution context")
        for key in ("run_id", "run_attempt", "job_id"):
            require(isinstance(request[key], str) and request[key].isdigit(), "invalid platform identifier")
        for key in ("p_sha", "w_sha", "c_sha"):
            require(re.fullmatch(r"[0-9a-f]{40}", request[key]) is not None, "invalid revision")
        require(re.fullmatch(r"[0-9a-f]{64}", request["fixture_sha256"]) is not None, "invalid emitter digest")
        require(request.get("strict_manifest_sha256") is None, "synthetic strict manifest digest must be null")
        unit, kind, chain = request["unit"], request["snapshot_kind"], request["chain_id"]
        expected_kind = "plan" if unit == "plan" else "prechain-failure" if args.case == "failed-pin" and unit == "pin" else "terminal-envelope" if unit == "terminal" else "checkpoint"
        require(kind == expected_kind, "snapshot kind mismatch")
        require(chain is None if kind in ("plan", "prechain-failure") else isinstance(chain, str) and re.fullmatch(r"[0-9a-f]{32}", chain) is not None, "invalid chain identity")
        if chain is not None:
            require(established_chain is None or established_chain == chain, "chain identity changed")
            established_chain = chain
        artifact_id = str(ack.get("artifact_id", ""))
        require(artifact_id.isdigit() and artifact_id not in ids and ack.get("verified") is True, "missing or duplicate artifact ID")
        ids.add(artifact_id)
        payload = Path(args.downloads_dir) / (artifact_id + ".tar")
        raw = payload.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        require(len(raw) == request["archive_bytes"] == ack.get("downloaded_bytes"), "downloaded byte count mismatch")
        require(digest == request["archive_sha256"] == ack.get("downloaded_sha256"), "downloaded digest mismatch")
        archive = members(payload)
        if "meta/pin.json" in archive:
            pin = parse_json(archive["meta/pin.json"])
            require(pin["chain_id"] == chain and pin["p_source_sha"] == expected_context["p_sha"] and pin["w_head"] == expected_context["w_sha"], "pin source or chain mismatch")
            require(os.path.realpath(pin["compiler_path"]) == os.path.realpath(args.compiler), "pin compiler path mismatch")
            require(pin["compiler_sha256"] == hashlib.sha256(Path(args.compiler).read_bytes()).hexdigest(), "pin compiler digest mismatch")
        archives.append(archive)
        report_entries.append({"request": {k: request[k] for k in BINDING}, "ack": {k: ack[k] for k in (*BINDING, "artifact_id", "downloaded_sha256", "downloaded_bytes", "verified")}, "members": sorted(archive)})
    if args.case == "failed-plan":
        journal = archives[0]["controller/stage-journal.jsonl"]
        records = [json.loads(line) for line in journal.splitlines()]
        require(any(r.get("unit") == "plan" and r.get("raw_exit_code") == 7 for r in records), "failed plan exit missing")
    if args.case == "failed-pin":
        archive = archives[-1]
        require("meta/pin.json" not in archive, "failed pin unexpectedly established")
        require(parse_json(archive["evidence-manifest.json"]).get("pin_state") == "absent", "missing explicit pin absence declaration")
        require("controller/stage-journal.jsonl" in archive, "failed pin journal absent")
        require(any("pin" in n and n.endswith(".log") and b"synthetic pin failed before establishment" in v for n, v in archive.items()), "failed pin log absent")
        records = [json.loads(line) for line in archive["controller/stage-journal.jsonl"].splitlines()]
        require(any(r.get("unit") == "pin" and r.get("raw_exit_code") == 9 for r in records), "failed pin exit missing")
    if args.case == "divergence":
        require(args.expected_divergence is not None, "missing independent divergence bytes")
        expected = Path(args.expected_divergence).read_bytes()
        archive = archives[-2]
        found = [v for n, v in archive.items() if n.endswith("/mods/divergence.bin")]
        require(len(found) == 1 and found[0] == expected and len(expected) >= 32, "divergence bytes missing or altered")
        divergence_sha256 = hashlib.sha256(expected).hexdigest()
        require(not any(re.search(r"^attempt/(?:t|c|bin)/", n) for n in archive), "expendable scratch exported")
        records = [json.loads(line) for line in archive["controller/stage-journal.jsonl"].splitlines()]
        require(any(r.get("unit") == "run3/" + drivers[0] and r.get("raw_exit_code") == 11 for r in records), "divergence exit missing")
    if args.case == "success":
        terminal = archives[-1]
        summary = parse_json(terminal["controller/strict-controller-summary.json"])
        envelope = parse_json(terminal["controller/terminal-envelope.json"])
        require(summary["overall_status"] == envelope["status"] == "NATIVE_COMPLETE_PENDING_TERMINAL", "invalid terminal status")
        require(envelope["invocation_id"] == index["invocation_id"], "terminal invocation mismatch")
        require(envelope["final_checkpoint"] == entries[-2]["ack"], "terminal final receipt mismatch")
        require(envelope["checkpoint_receipts"] == [entry["ack"] for entry in entries[:-1]], "terminal receipt order mismatch")
        require(str(entries[-1]["ack"]["artifact_id"]) not in json.dumps(summary) and str(entries[-1]["ack"]["artifact_id"]) not in json.dumps(envelope), "terminal archive contains its own ID")
        required = parse_json(archives[-2]["meta/run3/required.json"])
        require(required == drivers, "required inventory mismatch")
    if args.case in ("divergence", "cleanup-failure"):
        terminal = archives[-1]
        summary = parse_json(terminal["controller/strict-controller-summary.json"])
        envelope = parse_json(terminal["controller/terminal-envelope.json"])
        require(envelope["status"] == summary["overall_status"] != "PASS", "failure terminal status mismatch")
        require(envelope["checkpoint_receipts"] == [entry["ack"] for entry in entries[:-1]], "failure receipt order mismatch")
        require(envelope["invocation_id"] == index["invocation_id"] and envelope["final_checkpoint"] is None, "invalid failure terminal references")
        require(str(entries[-1]["ack"]["artifact_id"]) not in json.dumps(summary) and str(entries[-1]["ack"]["artifact_id"]) not in json.dumps(envelope), "failure terminal contains its own ID")
        if args.case == "cleanup-failure":
            require(summary["overall_status"] == "CLEANUP_FAILED", "cleanup failure omitted from summary")
            for array in ("records", "units"):
                matches = [r for r in summary[array] if r.get("unit") == "run1"]
                require(len(matches) == 1, "cleanup failure lost attempted unit")
                record = matches[0]
                require(record["raw_exit_code"] == 0 and record["native_status"] == "PASS" and record["disposition"] == "CLEANUP_FAILED", "cleanup failure lost native status")
                require(record["upload_verified"] is True and str(record["artifact_id"]) == str(entries[-2]["ack"]["artifact_id"]), "cleanup failure lost verified receipt")
    if args.report:
        report = {"case": args.case, "invocation_id": index["invocation_id"], "execution_kind": "synthetic", "exit_code": exit_code, "entries": report_entries}
        if args.case == "divergence":
            report["expected_divergence_sha256"] = divergence_sha256
            report["observed_divergence_sha256"] = hashlib.sha256(found[0]).hexdigest()
        Path(args.report).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        print(f"evidence check failed: {exc}", file=sys.stderr)
        sys.exit(1)
