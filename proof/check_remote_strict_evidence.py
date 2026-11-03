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

from remote_strict_fixtures import FAKE_STAGE_EMITTER_SOURCE
from remote_strict_validation import canonical_drivers, revision

COUNTS = {"success": 37, "failed-plan": 1, "failed-pin": 2, "divergence": 6, "cleanup-failure": 4}
BINDING = ("protocol_version", "request_id", "invocation_id", "execution_kind", "repository", "run_id", "run_attempt", "job_id", "job_key", "p_sha", "w_sha", "c_sha", "fixture_sha256", "snapshot_kind", "chain_id", "unit", "native_attempt", "snapshot_sequence", "archive_bytes", "archive_sha256")
CONTEXT = ("invocation_id", "execution_kind", "repository", "run_id", "run_attempt", "job_id", "job_key", "p_sha", "w_sha", "c_sha", "fixture_sha256")


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


def check_ownership_crash(index: dict, case_data_dir: str | None) -> dict:
    require(case_data_dir is not None, "missing crash fixture directory")
    root = Path(case_data_dir)
    require((root / "ownership-ready").read_text() == "ready\n", "crash fixture not ready")
    require((root / "ownership-flushed").read_text() == "completed_term_flush\n", "termination flush missing")
    lines = (root / "ownership-pids").read_text().splitlines()
    require(len(lines) == 2 and lines[0].startswith("child:") and lines[1].startswith("grandchild:"), "invalid crash fixture PID list")
    pids = [int(line.split(":", 1)[1]) for line in lines]
    require(all(pid > 0 for pid in pids) and pids[0] != pids[1], "invalid descendant PIDs")
    recovery = index["ownership_recovery"]
    require(index.get("exit_code") is None and index.get("entries") == [], "crash produced an unexpected checkpoint or exit")
    require(recovery.get("controller_signal") == "SIGKILL" and recovery.get("recovered") is True, "controller recovery missing")
    require(set(recovery["observed_pids"]) >= set(pids), "fixture descendants not observed")
    journal = index["ownership_journal"]
    for pid in pids:
        observations = [(i, e) for i, e in enumerate(journal) if e.get("event") == "observed" and e.get("pid") == pid and e.get("birth")]
        require(observations, "descendant identity absent from ownership journal")
        require(any(e.get("event") == "signaled" and e.get("pid") == pid and e.get("birth") == observed["birth"] and e.get("signal") == "SIGTERM" for i, observed in observations for e in journal[i + 1:]), "descendant not signaled with observed identity")
    registrations = [(i, e) for i, e in enumerate(journal) if e.get("event") == "registered"]
    require(any(any(e.get("event") == "resolved" and e.get("pid") == registered.get("pid") and e.get("unit") == registered.get("unit") and e.get("attempt") == registered.get("attempt") for e in journal[i + 1:]) for i, registered in registrations), "ownership registration unresolved")
    return {"case": "ownership-crash", "invocation_id": index["invocation_id"], "execution_kind": "synthetic", "controller_signal": "SIGKILL", "observed_pids": pids, "termination_flush": True, "recovered": True, "ownership_journal": journal}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True)
    parser.add_argument("--downloads-dir", required=True)
    parser.add_argument("--case", required=True, choices=(*COUNTS, "ownership-crash"))
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
    if args.case == "ownership-crash":
        require(index.get("execution_kind") == "synthetic" and index.get("invocation_id") == args.invocation_id, "crash context mismatch")
        report = check_ownership_crash(index, args.case_data_dir)
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
        expected_context = {
            "invocation_id": args.invocation_id, "execution_kind": "synthetic",
            "repository": args.repository, "run_id": args.run_id, "run_attempt": args.run_attempt,
            "job_id": args.job_id, "job_key": args.job_key,
            "p_sha": revision(args.p), "w_sha": revision(args.w), "c_sha": revision(args.c),
            "fixture_sha256": hashlib.sha256(FAKE_STAGE_EMITTER_SOURCE.encode("utf-8")).hexdigest(),
        }
        require(all(request.get(k) == v for k, v in expected_context.items()), "request does not match actual execution context")
        for key in ("run_id", "run_attempt", "job_id"):
            require(isinstance(request[key], str) and request[key].isdigit(), "invalid platform identifier")
        for key in ("p_sha", "w_sha", "c_sha"):
            require(re.fullmatch(r"[0-9a-f]{40}", request[key]) is not None, "invalid revision")
        require(re.fullmatch(r"[0-9a-f]{64}", request["fixture_sha256"]) is not None, "invalid emitter digest")
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
