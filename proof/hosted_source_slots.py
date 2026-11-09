"""Static census inspection. These claims are not runtime slot attribution.

A checked source line is not evidence that a process followed that callsite.
Strict admission remains refused until a reviewed source-context observer or a
behavior-preserving C-owned execution mechanism exists.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import asdict, dataclass
from collections.abc import Mapping

from proof.hosted_contracts import (
    canonical_json_bytes,
    ReferenceIntegrityError,
    StrictHaltRefusal,
    TypeValidationError,
    parse_strict_json,
    require_ascii_str,
    require_int,
    require_sha256,
    sha256_bytes,
)


@dataclass(frozen=True)
class DeclaredSourceSite:
    driver: str
    script: str
    script_sha256: str
    census_sha256: str
    lines: tuple[int, ...]
    command: str
    kind: str
    variants: tuple[str, ...]


def inspect_declared_sites(*, driver: str, script_bytes: bytes, census_bytes: bytes,
                           expected_script_sha256: str,
                           expected_census_sha256: str) -> tuple[DeclaredSourceSite, ...]:
    """Check declared site text against pinned bytes; do not claim census completeness."""
    require_ascii_str(driver, "driver", r"[a-z0-9_]+")
    require_sha256(expected_script_sha256, "expected_script_sha256")
    require_sha256(expected_census_sha256, "expected_census_sha256")
    if not isinstance(script_bytes, bytes) or not isinstance(census_bytes, bytes):
        raise TypeValidationError("source and census must be bytes")
    if sha256_bytes(script_bytes) != expected_script_sha256:
        raise ReferenceIntegrityError("SCRIPT-DIGEST-MISMATCH")
    if sha256_bytes(census_bytes) != expected_census_sha256:
        raise ReferenceIntegrityError("CENSUS-DIGEST-MISMATCH")
    census = parse_strict_json(census_bytes)
    script = f"bench/std_{driver}_exercise.sh"
    if not isinstance(census, dict) or census.get("census_version") != 1 or type(census.get("census_version")) is not int:
        raise TypeValidationError("INVALID-CENSUS")
    if (census.get("driver") != driver or census.get("script") != script
            or census.get("script_sha256") != expected_script_sha256):
        raise ReferenceIntegrityError("CENSUS-SOURCE-IDENTITY-MISMATCH")
    try:
        source_lines = script_bytes.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise TypeValidationError("INVALID-SCRIPT-UTF8") from exc
    sites = census.get("sites")
    if not isinstance(sites, list):
        raise TypeValidationError("INVALID-CENSUS-SITES")
    out: list[DeclaredSourceSite] = []
    seen: set[int] = set()
    for site in sites:
        if not isinstance(site, dict) or set(site) != {"lines", "command", "kind", "contains", "variants"}:
            raise TypeValidationError("INVALID-CENSUS-SITE")
        lines = site["lines"]
        if not isinstance(lines, list) or not lines:
            raise TypeValidationError("INVALID-SITE-LINES")
        for line in lines:
            require_int(line, "site line", min_val=1)
            if line > len(source_lines) or line in seen:
                raise ReferenceIntegrityError("INVALID-OR-DUPLICATE-SITE-LINE")
            seen.add(line)
        command = require_ascii_str(site["command"], "command", r"[a-z][a-z-]*")
        kind = require_ascii_str(site["kind"], "kind", r"[a-z][a-z-]*")
        fragments = site["contains"]
        if not isinstance(fragments, list) or not fragments or not all(isinstance(x, str) and x for x in fragments):
            raise TypeValidationError("INVALID-SITE-FRAGMENTS")
        source = "\n".join(source_lines[line - 1] for line in lines)
        if any(fragment not in source for fragment in fragments):
            raise ReferenceIntegrityError("SITE-TEXT-MISMATCH")
        variants = site["variants"]
        if not isinstance(variants, list) or any(not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"] for v in variants):
            raise TypeValidationError("INVALID-SITE-VARIANTS")
        ids = tuple(v["id"] for v in variants)
        if len(ids) != len(set(ids)):
            raise ReferenceIntegrityError("DUPLICATE-SITE-VARIANT")
        out.append(DeclaredSourceSite(driver, script, expected_script_sha256,
                                      expected_census_sha256, tuple(lines), command, kind, ids))
    return tuple(out)


def require_source_callsite_attribution() -> None:
    """Do not promote static claims or runtime argv into source provenance."""
    raise StrictHaltRefusal("SOURCE-CALLSITE-OBSERVER-UNAVAILABLE")


@dataclass(frozen=True)
class SourceBlob:
    path: str
    git_blob: str
    sha256: str


@dataclass(frozen=True)
class ProvisionalCorpus:
    """Pinned-tree inventory only. It is not a proof result or approval."""
    original_commit: str
    product_commit: str
    original: tuple[SourceBlob, ...]
    additions: tuple[SourceBlob, ...]
    samples: tuple[SourceBlob, ...]
    exercises: tuple[SourceBlob, ...]
    siblings: tuple[SourceBlob, ...]
    original_selection_script: SourceBlob
    selection_script: SourceBlob
    siblings_script: SourceBlob
    strict_eligible: bool = False

    def __post_init__(self) -> None:
        if self.strict_eligible is not False:
            raise StrictHaltRefusal("PROVISIONAL-CORPUS-NOT-STRICT-ELIGIBLE")


def _git(repo: str, *args: str) -> bytes:
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith("GIT_"):
            del env[key]
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", repo, *args],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ReferenceIntegrityError("GIT-SOURCE-READ-FAILED") from exc


def _tree(repo: str, commit: str) -> dict[str, str]:
    require_ascii_str(commit, "commit", r"[0-9a-f]{40}")
    resolved = _git(repo, "rev-parse", "--verify", commit + "^{commit}").strip()
    if resolved != commit.encode("ascii"):
        raise ReferenceIntegrityError("COMMIT-IDENTITY-MISMATCH")
    rows = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    result: dict[str, str] = {}
    for row in rows:
        if not row:
            continue
        try:
            meta, raw_path = row.split(b"\t", 1)
            mode, kind, oid = meta.split(b" ")
            path = raw_path.decode("utf-8", "strict")
            blob = oid.decode("ascii", "strict")
        except (ValueError, UnicodeError) as exc:
            raise ReferenceIntegrityError("INVALID-GIT-TREE-ENTRY") from exc
        if path in result:
            raise ReferenceIntegrityError("DUPLICATE-GIT-TREE-PATH")
        if kind == b"blob" and mode in (b"100644", b"100755"):
            result[path] = blob
        elif (path.startswith("samples/iyi/") or path.startswith("bench/")
              or path.startswith("proof/census/")):
            raise ReferenceIntegrityError("UNSUPPORTED-GIT-TREE-ENTRY")
    return result


def _blob(repo: str, tree: Mapping[str, str], path: str) -> tuple[SourceBlob, bytes]:
    oid = tree.get(path)
    if oid is None or not re.fullmatch(r"[0-9a-f]{40}", oid):
        raise ReferenceIntegrityError("REQUIRED-SOURCE-BLOB-MISSING")
    data = _git(repo, "cat-file", "blob", oid)
    return SourceBlob(path, oid, sha256_bytes(data)), data


def _selectors(tree: Mapping[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    samples = tuple(sorted(path for path in tree if re.fullmatch(r"samples/iyi/[^/]+\.iyi", path)))
    exercises = tuple(sorted(path for path in tree if re.fullmatch(r"bench/std_[^/]*_exercise\.iyi", path)))
    return samples, exercises


def derive_provisional_corpus(*, product_repo: str, original_commit: str,
                              product_commit: str) -> ProvisionalCorpus:
    """Derive the glob-defined corpus from immutable git trees, never a checkout."""
    original_tree = _tree(product_repo, original_commit)
    product_tree = _tree(product_repo, product_commit)
    old_samples, old_exercises = _selectors(original_tree)
    samples, exercises = _selectors(product_tree)
    old = set(old_samples + old_exercises)
    current = set(samples + exercises)
    additions = current - old
    if (len(old) != 142 or len(samples) != 28 or len(exercises) != 116
            or not old <= current or len(additions) != 2):
        raise ReferenceIntegrityError("CORPUS-IDENTITY-OR-COUNT-MISMATCH")
    sibling_paths = tuple(sorted(path for path in product_tree
                                 if re.fullmatch(r"bench/std_[^/]*_exercise\.sh", path)))
    if len(sibling_paths) != 117:
        raise ReferenceIntegrityError("SIBLING-COUNT-MISMATCH")
    selector, selector_data = _blob(product_repo, product_tree, "bench/stale_equivalence.sh")
    original_selector, original_selector_data = _blob(product_repo, original_tree, "bench/stale_equivalence.sh")
    required_globs = (b"samples = sorted(glob.glob(os.path.join(repo, 'samples/iyi/*.iyi')))",
                      b"bench = sorted(glob.glob(os.path.join(repo, 'bench/std_*_exercise.iyi')))",
                      b"programs = samples + bench")
    if any(selector_data.count(item) != 2 or original_selector_data.count(item) != 2
           for item in required_globs):
        raise ReferenceIntegrityError("UNSUPPORTED-CORPUS-SELECTOR")
    siblings_script, sibling_data = _blob(product_repo, product_tree, "bench/std_siblings.sh")
    if b'for sibling in "$REPO"/bench/std_*_exercise.sh; do' not in sibling_data:
        raise ReferenceIntegrityError("UNSUPPORTED-SIBLING-SELECTOR")
    def records(tree: Mapping[str, str], names: tuple[str, ...]) -> tuple[SourceBlob, ...]:
        return tuple(_blob(product_repo, tree, path)[0] for path in names)
    return ProvisionalCorpus(
        original_commit, product_commit, records(original_tree, tuple(sorted(old))),
        records(product_tree, tuple(sorted(additions))), records(product_tree, samples),
        records(product_tree, exercises), records(product_tree, sibling_paths),
        original_selector, selector, siblings_script,
    )


@dataclass(frozen=True)
class DeclaredEvidenceCall:
    """Static census claim with no authority to identify a runtime invocation."""
    evidence_index: int
    site_line: int
    site_kind: str
    build_source: str
    call_line: int
    name: str
    call_source: str
    output_template: str
    exec_lines: tuple[int, ...]
    exec_token: str
    candidate_variant_ids: tuple[str, ...]
    variant_mapping: str = "unresolved"
    control_flow_cardinality: str = "unresolved"


@dataclass(frozen=True)
class DeclaredEvidenceSite:
    evidence_index: int
    site_line: int
    output_template: str
    exec_lines: tuple[int, ...]
    exec_token: str
    named_call_count: int


@dataclass(frozen=True)
class DeclaredDirectEvidence:
    """Literal build and execution sites, without a runtime cardinality claim."""
    evidence_index: int
    site_line: int
    site_kind: str
    variant_id: str | None
    output_template: str
    build_source: str
    exec_lines: tuple[int, ...]
    exec_sources: tuple[str, ...]
    control_flow_cardinality: str = "unresolved"


@dataclass(frozen=True)
class DeclaredVariant:
    site_line: int
    variant_id: str
    kind: str
    linux: str
    darwin: str
    requires: tuple[str, ...]
    sources: tuple[str, ...]
    first_root: str
    output: str | None
    full_claim_json: bytes


@dataclass(frozen=True)
class ProvisionalDriverCensus:
    driver: str
    product_commit: str
    witness_commit: str
    product_script: SourceBlob
    witness_script: SourceBlob
    census: SourceBlob
    census_bytes: bytes
    sites: tuple[DeclaredSourceSite, ...]
    variants: tuple[DeclaredVariant, ...]
    evidence_sites: tuple[DeclaredEvidenceSite, ...]
    evidence_calls: tuple[DeclaredEvidenceCall, ...]
    direct_evidence: tuple[DeclaredDirectEvidence, ...]
    unexpanded_evidence_indices: tuple[int, ...]
    product_script_matches_witness: bool
    source_callsite_attribution: str = "unavailable"
    strict_eligible: bool = False

    def __post_init__(self) -> None:
        if self.strict_eligible is not False or self.source_callsite_attribution != "unavailable":
            raise StrictHaltRefusal("PROVISIONAL-CENSUS-NOT-STRICT-ELIGIBLE")


def derive_provisional_driver_censuses(
    *, product_repo: str, product_commit: str, witness_repo: str, witness_commit: str,
) -> tuple[ProvisionalDriverCensus, ...]:
    """Inspect pinned declared censuses; dynamic required-driver selection is not implied."""
    product = _tree(product_repo, product_commit)
    witness = _tree(witness_repo, witness_commit)
    paths = sorted(path for path in witness
                   if re.fullmatch(r"proof/census/[a-z0-9_]+\.json", path))
    if len(paths) < 29:
        raise ReferenceIntegrityError("CENSUS-INVENTORY-TOO-SMALL")
    results: list[ProvisionalDriverCensus] = []
    for path in paths:
        driver = path.removeprefix("proof/census/").removesuffix(".json")
        census_ref, census_bytes = _blob(witness_repo, witness, path)
        script_path = f"bench/std_{driver}_exercise.sh"
        w_script, script_bytes = _blob(witness_repo, witness, script_path)
        p_script, _ = _blob(product_repo, product, script_path)
        sites = inspect_declared_sites(
            driver=driver, script_bytes=script_bytes, census_bytes=census_bytes,
            expected_script_sha256=w_script.sha256, expected_census_sha256=census_ref.sha256,
        )
        census = parse_strict_json(census_bytes)
        variants: list[DeclaredVariant] = []
        variant_ids: set[str] = set()
        for raw_site in census["sites"]:
            for variant in raw_site["variants"]:
                keys = {"id", "kind", "first_root", "vars", "sources", "output",
                        "requires", "verdict", "darwin", "linux"}
                if set(variant) != keys:
                    raise TypeValidationError("UNSUPPORTED-VARIANT-SCHEMA")
                variant_id = require_ascii_str(variant["id"], "variant_id", r"[!-~]+")
                if variant_id in variant_ids:
                    raise ReferenceIntegrityError("DUPLICATE-DRIVER-VARIANT")
                variant_ids.add(variant_id)
                kind = require_ascii_str(variant["kind"], "variant kind", r"[a-z][a-z-]*")
                linux, darwin = variant["linux"], variant["darwin"]
                if linux not in ("required", "platform-excluded") or darwin not in ("required", "platform-excluded"):
                    raise TypeValidationError("UNSUPPORTED-VARIANT-CLASSIFICATION")
                requires, sources = variant["requires"], variant["sources"]
                if (not isinstance(requires, list) or not all(isinstance(x, str) and x for x in requires)
                        or not isinstance(sources, list) or not all(isinstance(x, str) and x for x in sources)
                        or not isinstance(variant["vars"], dict) or not isinstance(variant["verdict"], dict)
                        or not isinstance(variant["first_root"], str)
                        or not (variant["output"] is None or isinstance(variant["output"], str))):
                    raise TypeValidationError("INVALID-VARIANT-FIELDS")
                variants.append(DeclaredVariant(
                    raw_site["lines"][0], variant_id, kind, linux, darwin, tuple(requires),
                    tuple(sources), variant["first_root"], variant["output"],
                    canonical_json_bytes(variant),
                ))
        evidence = census.get("exec_evidence")
        if not isinstance(evidence, list):
            raise TypeValidationError("INVALID-EXEC-EVIDENCE")
        lines = script_bytes.decode("utf-8", "strict").splitlines()
        declared_lines = {line for site in sites for line in site.lines}
        seen_lines: set[int] = set()
        calls: list[DeclaredEvidenceCall] = []
        direct: list[DeclaredDirectEvidence] = []
        evidence_sites: list[DeclaredEvidenceSite] = []
        unexpanded: list[int] = []
        for index, item in enumerate(evidence):
            required = {"site_line", "out_template", "name_from_calls", "exec_lines",
                        "exec_token", "verdict_lines", "failure_marks", "refs_ok"}
            if not isinstance(item, dict) or set(item) != required:
                raise TypeValidationError("INVALID-EXEC-EVIDENCE-ENTRY")
            site_line = require_int(item["site_line"], "site_line", min_val=1)
            if site_line not in declared_lines or site_line in seen_lines:
                raise ReferenceIntegrityError("EXEC-SITE-UNDECLARED-OR-DUPLICATE")
            seen_lines.add(site_line)
            output = item["out_template"]
            token = item["exec_token"]
            call_map = item["name_from_calls"]
            exec_lines = item["exec_lines"]
            if (not isinstance(output, str) or not output or not isinstance(token, str) or not token
                    or not isinstance(call_map, dict) or not isinstance(exec_lines, list)
                    or not exec_lines):
                raise TypeValidationError("INVALID-EXEC-EVIDENCE-FIELDS")
            for line in exec_lines:
                require_int(line, "exec_line", min_val=1)
                if line > len(lines) or token not in lines[line - 1]:
                    raise ReferenceIntegrityError("EXEC-LINE-TEXT-MISMATCH")
            evidence_sites.append(DeclaredEvidenceSite(
                index, site_line, output, tuple(exec_lines), token, len(call_map),
            ))
            if not call_map:
                site = next(site for site in sites if site_line in site.lines)
                site_text = "\n".join(lines[number - 1] for number in site.lines)
                literal = re.fullmatch(r'\{WORK\}/([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)', output)
                valid_path = literal is not None and all(
                    component not in (".", "..") for component in literal.group(1).split("/")
                )
                expected_token = f'"$WORK/{literal.group(1)}"' if valid_path else None
                matching_variants = [
                    variant for variant in variants
                    if variant.site_line == site.lines[0] and variant.output == output
                    and variant.kind == "positive"
                    and parse_strict_json(variant.full_claim_json)["vars"] == {}
                ]
                is_own = site.kind == "canonical-own" and not site.variants
                is_positive = site.kind == "positive" and len(matching_variants) == 1
                if (valid_path and token == expected_token and site.command == "build"
                        and re.search(r'(?:^|\s)-o\s+' + re.escape(token) + r'(?=\s|\\|$)', site_text)
                        and (is_own or is_positive)):
                    direct.append(DeclaredDirectEvidence(
                        index, site_line, site.kind,
                        matching_variants[0].variant_id if is_positive else None,
                        output, site_text, tuple(exec_lines),
                        tuple(lines[line - 1] for line in exec_lines),
                    ))
                else:
                    unexpanded.append(index)
            for call, name in call_map.items():
                if not isinstance(call, str) or not re.fullmatch(r"[1-9][0-9]*", call):
                    raise TypeValidationError("INVALID-DECLARED-CALL-LINE")
                call_line = int(call)
                if (call_line > len(lines) or not isinstance(name, str) or not name
                        or name not in lines[call_line - 1]):
                    raise ReferenceIntegrityError("DECLARED-CALL-TEXT-MISMATCH")
                named_site = next(site for site in sites if site_line in site.lines)
                build_source = "\n".join(lines[number - 1] for number in named_site.lines)
                wanted_output = output.replace("{name}", name)
                candidates: list[str] = []
                for variant in variants:
                    if variant.site_line != named_site.lines[0] or variant.kind != "positive":
                        continue
                    claim = parse_strict_json(variant.full_claim_json)
                    variables = claim["vars"]
                    rendered = variant.output
                    if not isinstance(rendered, str):
                        continue
                    if "{name}" in rendered:
                        spec = variables.get("name")
                        if (not isinstance(spec, dict) or not isinstance(spec.get("values"), list)
                                or name not in spec["values"]):
                            continue
                        rendered = rendered.replace("{name}", name)
                    if rendered == wanted_output and not re.search(r"\{(?!WORK\}|REPO\})", rendered):
                        candidates.append(variant.variant_id)
                calls.append(DeclaredEvidenceCall(
                    index, site_line, named_site.kind, build_source, call_line, name,
                    lines[call_line - 1], output, tuple(exec_lines), token, tuple(candidates),
                ))
        results.append(ProvisionalDriverCensus(
            driver, product_commit, witness_commit, p_script, w_script, census_ref, census_bytes,
            sites, tuple(variants), tuple(evidence_sites), tuple(calls), tuple(direct),
            tuple(unexpanded), p_script.sha256 == w_script.sha256,
        ))
    return tuple(results)


def provisional_manifest_bytes(
    corpus: ProvisionalCorpus, drivers: tuple[ProvisionalDriverCensus, ...],
) -> bytes:
    """Serialize a provisional source inventory, not an acceptance or receipt."""
    if not isinstance(corpus, ProvisionalCorpus) or not isinstance(drivers, tuple):
        raise TypeValidationError("INVALID-PROVISIONAL-SOURCE-MANIFEST")
    if not drivers or any(not isinstance(driver, ProvisionalDriverCensus) for driver in drivers):
        raise TypeValidationError("INVALID-PROVISIONAL-DRIVERS")
    if len({driver.driver for driver in drivers}) != len(drivers):
        raise ReferenceIntegrityError("DUPLICATE-PROVISIONAL-DRIVER")
    if any(driver.product_commit != corpus.product_commit for driver in drivers):
        raise ReferenceIntegrityError("PROVISIONAL-PRODUCT-COMMIT-MISMATCH")
    if len({driver.witness_commit for driver in drivers}) != 1:
        raise ReferenceIntegrityError("PROVISIONAL-WITNESS-COMMIT-MISMATCH")
    records = []
    for driver in sorted(drivers, key=lambda item: item.driver):
        variant_records = []
        for variant in driver.variants:
            record = asdict(variant)
            raw = record.pop("full_claim_json")
            record["claim_sha256"] = sha256_bytes(raw)
            record["claim"] = parse_strict_json(raw)
            variant_records.append(record)
        records.append({
            "driver": driver.driver,
            "product_commit": driver.product_commit,
            "witness_commit": driver.witness_commit,
            "product_script": asdict(driver.product_script),
            "witness_script": asdict(driver.witness_script),
            "census": asdict(driver.census),
            "sites": [asdict(site) for site in driver.sites],
            "variants": variant_records,
            "evidence_sites": [asdict(site) for site in driver.evidence_sites],
            "evidence_calls": [asdict(call) for call in driver.evidence_calls],
            "direct_evidence": [asdict(item) for item in driver.direct_evidence],
            "unexpanded_evidence_indices": driver.unexpanded_evidence_indices,
            "product_script_matches_witness": driver.product_script_matches_witness,
            "source_callsite_attribution": driver.source_callsite_attribution,
            "strict_eligible": False,
        })
    return canonical_json_bytes({
        "schema": "iyi-provisional-source-inventory-v1",
        "strict_eligible": False,
        "corpus": asdict(corpus),
        "drivers": records,
    })
