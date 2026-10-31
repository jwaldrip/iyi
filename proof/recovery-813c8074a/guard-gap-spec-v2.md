# Spec v2 (final): one H′ that makes g02, g13, g18 and m14 KILLED (proof/ only)

All four can be fixed in one commit, H′, and no decision is needed from Jason. I edited nothing and ran nothing. Every result below is a prediction for you to verify by running it.

The changes, in short:
- **g13** works the same way as g18. Both existing seeds for that guard are masked, so the fix repairs the seed meant for it in place and adds no new id.
- **m14** has a broken guard pair: its seed's expected value equals what the mutant produces. The fix adds a seed that only passes when the header is recognised, and rebuilds the control so the mutant can't affect it.
- **g02 and g18** are unchanged from v1.

## 1. Goal

At H′, a child of H on a new branch, with E3 rerun on all 43 entries:
- **E3:** 42 KILLED (m01–m05 plus 37 of the 38), and m20 MASKED (decided by E2c).
- **Smoke:** rc 0, `TOTAL seeds_executed=435 seeds_passed=435 seeds_missed=0 seeds_missing=0 controls_executed=85 controls_failed=0 controls_missing=0`, HARNESS PASS.
- **Coverage:** COVERAGE GATE PASS with the ALLOWLIST unchanged.
- **Subsets:** S-ident61 stays at 61. GC goes to 20, GA to 28, GB to 30.
- **Scope:** only `proof/run_proof.py` (2 lines) and `proof/smoke_test.py` change.

## 2. What changed since v1

E3 at H finished with 38 rows: 33 KILLED, g02/g13/g18 SURVIVED, m14 FAIL, m20 MASKED.
- **g13:** v1 listed it as exposed; it is the only GB mutant that survived. The detector the catalog names for it, `amend-b.seed.run-form-not-counted`, can never isolate pk:3729 (see §3).
- **m14:** the H full suite shows two seeds already change under it. The guard's own pair is still built wrong.
- **g02, g18:** same fixes as v1. Names still avoid the `o7.seed.guard-` and `o7.control.guard-` prefixes so S-ident61 stays at 61.

## 3. Findings

**g02 (rp:330):** as in v1.
- All plan seeds refuse at rp:325, before the probe runs.
- `s1.control.plan` checks only that the strings `Probe:` and `atime=` appear.
- `cmd_plan` is the only caller of the probe with no `stat_fn` seam (compare pk:657, rp:1076, rp:1417).

**g18 (pk:2827):** as in v1.
- The only seed sets cookie's sentinel regex to `"IYIVAR"`, which doesn't match cookie's rendered sentinel line.
- With the guard disabled, the fallback branch (pk:2835-2845) emits the same `C5.5-sentinel`.
- The seed checks only that the rule id is present.

**g13 (pk:3729, `for index in []:`).**
- **What it protects:** the loop at pk:3729-3735 flags an own or positive end record that is neither run-executed nor matched by any declared execution evidence ("matches no execution evidence"). This is the only check that catches an own output that was *executed* but not tied to the census's declared execution lines.
- **Why nothing sees it:** every fixture that reaches pk:3729 hands it a record with no `out_ref`. The stat block then flags the same record with the same status, "record N has no out_ref" (pk:3748-3755), and the fixtures compare only the sorted status set.
  - `o5.seed.e2-unmatched-own`: the stray build record has no out_ref (smoke_test.py:8147-8160, base record from `_o5_pair` at 7587).
  - `amend-b.seed.run-form-not-counted`: the stub tampers `run.argv[0]` (11676-11700), and the shim writes `out_ref` only for builds (roundtrip_shim.py:1048-1051).
  - E3 confirms it: under g13, the e2-unmatched-own seed still shows `["NOT-EXECUTED"]` (full_suite stdout, line 784), and the amend-b seed is unchanged (subset log, line 17).
- **Root fix:** give the stray output a real hard-linked copy of `/usr/bin/true` with its atime advanced past its mtime, the same construction `_o5_positive_build_pair` uses at 7597-7638. E3 then passes, the evidence count for "own" stays at 1, so only pk:3729 can fire.
  - **Detector:** `o5.seed.e2-unmatched-own`, already registered (9244-9248) and in `"o5.e2"` (9442-9450).
  - **Paired controls:** `s3.control.ledger` (the seed's base, so they differ by one change) and `o5.control.e2-e3`. Neither has an unmatched record, so g13 can't change them.
- **Not touched:** the O5 ledger case `"run-form-not-counted"` (8428-8431) is unregistered dead code and would be masked the same way. No fixture runs it, so this slice leaves it alone.

**m14 (rp:296, header regex never matches).**
- **What it protects:** a well-formed `-- running sibling: std_X_exercise.sh` header opens X's section, so X's declared skips printed there are captured. A malformed header opens nothing.
- **Why it labels FAIL:**
  - The seed (malformed header, smoke_test.py:13643-13655) expects 0 hits, which is exactly what the mutant produces.
  - The control (good header plus a skip line, expects 1) is the case that depends on recognition, so it FAILs under the mutant.
  - `o7.seed.rp-baseline-census-type` and `o7.seed.rp2-run1-baseline-error` also change under m14. Both need a header match before their "census is not an object" refusal can fire (rp:305-310).
- **Re-pair, or a new seed?**
  - Re-pairing at H would meet the KILLED definition from existing evidence. Spec §7 allows correcting the detector: name `rp-baseline-census-type` as the detector and pair it with its own key's controls, `s5.control.stage-chain` and `s1.control.pin`, both of which PASSed in the m14 full suite. That still leaves the guard's own pair broken, and those two seeds only catch m14 as a side effect.
  - **Root fix for H′:**
    - Seed (a), new `o7.seed.baseline-skip-captured`: good header plus the declared skip, expecting the exact hit. The mutant gives `[]`, so this seed is the detector.
    - Control (c), the existing id `o7.control.guard-m14-baseline-header` rebuilt: good header, no skip line, expects 0. The mutant also gives 0, so it PASSes.
    - Seed (b), the existing malformed-header seed: unchanged, still catches mutants that accept too much.
  - **Label at H′:** KILLED.

## 4. Shared contracts

- **Worktree:** the main agent creates `/Users/jwaldrip/dev/worktrees/iyi-audit-repair-g02-g18-20261031` on branch `proof/audit-repair-g02-g18-20261031`, from H `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd`, after fetching via `/Users/jwaldrip/dev/src/github.com/jwaldrip/iyi`. Never touch W2, and never push to `proof/audit-deadlines-seams-20261030`.
- **New ids:**
  - `o7.seed.plan-probe-unobservable` and `o7.control.plan-probe-observable`, under key `o7.plan-probe`.
  - `o7.seed.validator-sentinel-iyivar`, under key `o7.validator-sentinel-iyivar`, with `s2.control.census-all`.
  - `o7.seed.baseline-skip-captured`, added to the existing key `o7.guard-m14-baseline-header`.
- **Changed in place:** `o5.seed.e2-unmatched-own` (input), `o7.control.guard-m14-baseline-header` (meaning), `o7.seed.pk2-schema-sentinel-iyivar` (input).
- **Stays as it is:** proofkit, shim and legs modules, censuses, the REVIEW_ITEMS literal (R1's 33 keys), imports, harness, ALLOWLIST, O3 inventories.
- **Line count:** `run_proof.py` keeps its line count, so the ALLOWLIST rp:1524-1531 entries and the 10 other rp catalog anchors stay valid.

## 5. Slice for codex-worker (sole writer)

Edit only the two absolute paths below. Do not run git, Python, tests or builds. Do not reformat anything. "H:n" means line n at H.

**Change 1.** In `proof/run_proof.py`, replace two lines:
```python
def cmd_plan(args, *, drivers: Sequence[str] = DRIVERS_29, stat_fn=os.stat) -> int:
```
(H:324)
```python
        probe = probe_atime_observable(probe_dir, stat_fn=stat_fn)
```
(H:330)

**Change 2.** In `proof/smoke_test.py`, insert this right after `_o5_positive_build_pair` ends (H:7638), with two blank lines between top-level definitions:
```python
def _o5_executed_own_build_pair(
    *,
    root: str,
    repo: str,
    work: str,
    name: str,
    invocation: str,
) -> list[dict]:
    out = os.path.join(work, name)
    out_ref = os.path.join(root, f"{name}.ref")
    shutil.copyfile("/usr/bin/true", out)
    os.chmod(out, 0o755)
    os.link(out, out_ref)
    linked = os.stat(out_ref)
    with open(out, "rb") as executable:
        digest = hashlib.sha256(executable.read()).hexdigest()
    os.utime(
        out_ref,
        ns=(linked.st_mtime_ns + 1_000_000_000, linked.st_mtime_ns),
    )
    pair = _o5_pair(
        nonce="nonce-1",
        driver="demo",
        invocation=invocation,
        repo=repo,
        out=out,
        own=True,
        run_form=False,
    )
    end = pair[1]
    end["consumer"]["out_sha256"] = digest
    end["out_ref"] = out_ref
    end["out_ino"] = linked.st_ino
    end["out_mtime_ns"] = linked.st_mtime_ns
    end["atime_set_ns"] = linked.st_mtime_ns - 1_000_000_000
    return pair
```

**Change 3.** Replace the `case == "e2-unmatched-own"` branch (H:8147-8160) with:
```python
        elif case == "e2-unmatched-own":
            records.extend(
                _o5_executed_own_build_pair(
                    root=root,
                    repo=repo,
                    work=work,
                    name="stray",
                    invocation="own-unmatched",
                )
            )
            expected = ("NOT-EXECUTED",)
            detail = (
                "extra own output, executed with passing E3 evidence, "
                "does not match execution evidence"
            )
```

**Change 4.** Replace `_fixture_baseline_header_guard` entirely (H:13621-13656):
```python
def _fixture_baseline_header_guard(case: str) -> Observation:
    if case not in {"malformed", "no-skip", "captured"}:
        raise ValueError(f"unknown baseline header case {case}")
    with tempfile.TemporaryDirectory(prefix="iyi-baseline-header-") as root:
        census_dir = os.path.join(root, "proof", "census")
        os.makedirs(census_dir)
        with open(
            os.path.join(census_dir, "stage.json"),
            "w",
            encoding="utf-8",
        ) as output:
            json.dump(
                {
                    "driver": "stage",
                    "skips": [
                        {
                            "regex": "^fixture platform skipped$",
                            "class": "platform",
                            "what": "fixture platform",
                        }
                    ],
                },
                output,
            )
        header = (
            "-- running sibling std_stage_exercise.sh"
            if case == "malformed"
            else "-- running sibling: std_stage_exercise.sh"
        )
        skip_line = "" if case == "no-skip" else "fixture platform skipped\n"
        hits = stages_mod._baseline_skip_hits(
            root,
            f"{header}\n{skip_line}",
        )
    if case == "captured":
        return Observation(
            expected=[
                {
                    "class": "platform",
                    "driver": "stage",
                    "regex": "^fixture platform skipped$",
                    "what": "fixture platform",
                }
            ],
            got=hits,
            applied=(
                "declared platform skip printed under a well-formed "
                "stage sibling header"
            ),
        )
    return Observation(
        expected=0,
        got=len(hits),
        applied="sibling header colon removed" if case == "malformed" else "",
    )
```

**Change 5.** Replace H:15334 with a single line:
```python
                mutated["pass_sentinel"]["regex"] = f"(?:{mutated['pass_sentinel']['regex']})|IYIVAR"
```

**Change 6.** Insert immediately above `O7_FIXTURES: tuple[Fixture, ...] = (` (H:16485):
```python
def _fixture_plan_probe_guard(seeded: bool) -> Observation:
    stat_paths: list[str] = []

    def plan_stat(path: str) -> object:
        stat_paths.append(path)
        actual = os.stat(path)
        if not seeded:
            return actual
        return SimpleNamespace(
            st_atime_ns=actual.st_mtime_ns - 1_000_000_000,
            st_ino=actual.st_ino,
            st_mtime_ns=actual.st_mtime_ns,
        )

    output = io.StringIO()
    with PinFixture() as fixture:
        try:
            with contextlib.redirect_stdout(output):
                stages_mod.cmd_plan(
                    SimpleNamespace(
                        p=fixture.p,
                        w=fixture.w,
                        compiler=fixture.compiler,
                    ),
                    stat_fn=plan_stat,
                )
        except IdentityError as error:
            reason = error.reason
        else:
            reason = "NO-REFUSAL"
    plan_probe_calls = sum(
        1
        for path in stat_paths
        if os.path.dirname(os.path.dirname(path)) == "/private/tmp"
        and os.path.basename(os.path.dirname(path)).startswith(
            "iyi-plan-atime-"
        )
        and os.path.basename(path).startswith("probe-atime-")
    )
    got: dict[str, object] = {
        "reason": reason,
        "stdout_empty": output.getvalue() == "",
    }
    if not seeded:
        return Observation(
            expected={"reason": "NO-REFUSAL", "stdout_empty": False},
            got=got,
        )
    got["applied"] = bool(stat_paths) and plan_probe_calls == len(stat_paths)
    return Observation(
        expected={
            "applied": True,
            "reason": "EXEC-UNOBSERVABLE",
            "stdout_empty": True,
        },
        got=got,
        applied=(
            "stat_fn=frozen-atime(mtime-1000000000);"
            f"stat_fn_calls={len(stat_paths)};"
            f"plan_probe_calls={plan_probe_calls}"
        ),
    )


def _sentinel_iyivar_regex(census: dict, lines: list[str]) -> str | None:
    sentinel = census.get("pass_sentinel")
    if not isinstance(sentinel, dict):
        return None
    regex = sentinel.get("regex")
    number = sentinel.get("line")
    if (
        not isinstance(regex, str)
        or ".*" not in regex
        or not isinstance(number, int)
        or not 1 <= number <= len(lines)
    ):
        return None
    commands = proofkit_mod._top_level_print_commands(
        _line_text(lines[number - 1])
    )
    rendered = (
        proofkit_mod._render_print_words(commands[0]) if commands else None
    )
    if rendered is None or "IYIVAR" not in rendered:
        return None
    literal = regex.replace(".*", "IYIVAR", 1)
    try:
        matched = re.search(literal, rendered) is not None
    except re.error:
        return None
    return literal if matched else None


def _has_variable_sentinel_wildcard(census: dict, lines: list[str]) -> bool:
    return _sentinel_iyivar_regex(census, lines) is not None


def _mutate_sentinel_to_iyivar(
    census: dict,
    lines: list[str],
    _driver: str,
) -> tuple[str, int]:
    literal = _sentinel_iyivar_regex(census, lines)
    if literal is None:
        return "sentinel-wildcard-missing", 0
    census["pass_sentinel"]["regex"] = literal
    return (
        f"sentinel-{census['pass_sentinel']['line']}-wildcard->IYIVAR;"
        "matches_rendered=true",
        1,
    )


def _fixture_validator_sentinel_iyivar_seed() -> Observation:
    return _isolated_validator_seed(
        "C5.5-sentinel",
        "sentinel wildcard cannot be literal IYIVAR",
        _has_variable_sentinel_wildcard,
        _mutate_sentinel_to_iyivar,
    )
```

**Change 7.** Registrations.
- At H:16804 replace `True` with `"malformed"`. At H:16809 replace `False` with `"no-skip"`.
- Append before the closing `)` of `O7_FIXTURES` (H:17086):
```python
    Fixture(
        "o7.seed.plan-probe-unobservable",
        "seed",
        partial(_fixture_plan_probe_guard, True),
    ),
    Fixture(
        "o7.control.plan-probe-observable",
        "control",
        partial(_fixture_plan_probe_guard, False),
    ),
    Fixture(
        "o7.seed.validator-sentinel-iyivar",
        "seed",
        _fixture_validator_sentinel_iyivar_seed,
    ),
    Fixture(
        "o7.seed.baseline-skip-captured",
        "seed",
        partial(_fixture_baseline_header_guard, "captured"),
    ),
```

**Change 8.** Review items.
- Make the key at H:17332-17335 read:
```python
    "o7.guard-m14-baseline-header": (
        "o7.seed.guard-m14-baseline-header",
        "o7.seed.baseline-skip-captured",
        "o7.control.guard-m14-baseline-header",
    ),
```
- Append before the closing `}` of `O7_REVIEW_ITEMS` (H:17432):
```python
    "o7.plan-probe": (
        "o7.seed.plan-probe-unobservable",
        "o7.control.plan-probe-observable",
    ),
    "o7.validator-sentinel-iyivar": (
        "o7.seed.validator-sentinel-iyivar",
        "s2.control.census-all",
    ),
```

**Worker acceptance (diff shape):**
- `run_proof.py` numstat is `2 2`.
- `smoke_test.py` changes only at the places listed above.
- No new imports.
- No new code assigns to an attribute or calls `setattr` (F11).

## 6. End-to-end check (main agent, fresh clone of H′, private scratch)

1. **Full smoke:** the TOTAL line from §1. Predicted lines:
   - `SEED o7.seed.plan-probe-unobservable expect={"applied":true,"reason":"EXEC-UNOBSERVABLE","stdout_empty":true} got=<same> applied="stat_fn=frozen-atime(mtime-1000000000);stat_fn_calls=4;plan_probe_calls=4"`
   - `CONTROL o7.control.plan-probe-observable PASS`
   - `SEED o7.seed.validator-sentinel-iyivar expect={"control":[],"seed":["C5.5-sentinel"]} got=<same> applied="sentinel-519-wildcard->IYIVAR;matches_rendered=true;driver=acme;count=1;census_changed=true;script_changed=false"`
   - `SEED o5.seed.e2-unmatched-own expect=["NOT-EXECUTED"] got=["NOT-EXECUTED"] applied="serialized_input_changed=true; extra own output, executed with passing E3 evidence, does not match execution evidence"`
   - `SEED o7.seed.baseline-skip-captured expect=[{"class":"platform","driver":"stage","regex":"^fixture platform skipped$","what":"fixture platform"}] got=<same>`
   - Unchanged lines: pk2 (`expect=true got=true`), guard-m14 seed (`expect=0 got=0`), and `CONTROL o7.control.guard-m14-baseline-header PASS`.
2. **Coverage:** `--coverage` gives GATE PASS, with the same `>>>>>>` line sets as at H.
3. **Mutants:** one fresh clone per mutant. Apply once, check `git diff --name-only` shows only the target file, then run `run_fixtures.py --w <clone> <ids>`. The same ids on the unmutated clone must give `RESULT PASS`.

| Mutant | Subset | Predicted RESULT |
|---|---|---|
| g02′ (old line `        probe = probe_atime_observable(probe_dir, stat_fn=stat_fn)\n`, new line unchanged) | plan-probe-unobservable, plan-probe-observable, s1.control.plan | `FAIL ['o7.seed.plan-probe-unobservable'] []` |
| g18 (catalog text verbatim) | validator-sentinel-iyivar, pk2-schema-sentinel-iyivar, s2.control.census-all | `FAIL ['o7.seed.pk2-schema-sentinel-iyivar', 'o7.seed.validator-sentinel-iyivar'] []` |
| g13 (catalog text verbatim) | o5.seed.e2-unmatched-own, s3.control.ledger, o5.control.e2-e3 | `FAIL ['o5.seed.e2-unmatched-own'] []` (got `[]`) |
| m14 (catalog text verbatim) | baseline-skip-captured, guard-m14 seed, guard-m14 control | `FAIL ['o7.seed.baseline-skip-captured'] []` |

4. **Anchors at H′:** the original g02 `old` text occurs 0 times. The other 42 catalog `old` strings occur exactly once each.

## 7. Effect on the audit at H′

| Evidence | At H′ | Reason |
|---|---|---|
| E1 preflight, E4 identity | rerun | the head changed |
| E1 coverage | rerun; acceptance becomes 435/85, same 7 ALLOWLIST entries | the executed ID set is H's plus 4 new ids |
| RV smoke, parent EV smoke, R1 compare.json | rerun both | new ids and changed fixtures |
| Registry (`registration/run/*`, R2 holes check) | rerun | 2 new keys, 1 key extended, 4 new ids |
| R1 mapping | regenerate | the 33 `review.*` keys keep their content; their line range moves |
| R2: F11 scan, dead-symbol screen, `git grep`, settrace location | rerun | they read changed files |
| R2: §8.5 census checks, F10, limits (al:47-50, pk:1176-1177), exec_line/token, readiness-fence review | re-bind by sha256 of each input or cited region | all are byte-identical; cited smoke regions after H:7639 move lines but no edit touches them |
| plan, refusals, layout, o3, manual seeds, Seed 5 leg, fguards, matrix, m01-m05 `.out` | rerun | execution evidence; the reuse rule requires "produced at H" |
| E2a-d | rerun | E2a and E2b cite smoke lines that move; their string-anchored constructions are unchanged |
| **E3** | **rerun all 43** | S-ident61 = 61, GC 20 (+3 new ids), GA 28 (+baseline-skip-captured), GB 30 (+e2-unmatched-own) |

Catalog changes at H′ (only these four entries):

| Entry | Anchor | Detector | Paired controls | Notes |
|---|---|---|---|---|
| g02 | re-anchored (§6) | o7.seed.plan-probe-unobservable | o7.control.plan-probe-observable, s1.control.plan | |
| g13 | unchanged | o5.seed.e2-unmatched-own | s3.control.ledger, o5.control.e2-e3 | |
| g18 | unchanged | o7.seed.validator-sentinel-iyivar | s2.control.census-all | expected collateral: pk2 seed |
| m14 | unchanged | o7.seed.baseline-skip-captured | o7.control.guard-m14-baseline-header | collateral in the full suite only: rp-baseline-census-type, rp2-run1-baseline-error |

## 8. v1's exposure list against the actual E3 results

- **g02's pattern** (no seed reaches the guarded call): no other mutant had it.
- **g18's pattern** (a fixture compares only a signal that a sibling branch also emits):
  - Of the exposed set (m15, m16, g05–g08, g13, g14, g15), only g13 survived. Its masking branch is pk:3748-3755.
  - g09–g12 were safe by construction, as predicted, and were KILLED.
- **m14** was a third shape: a seed that only checks the negative case, plus a control that the mutant itself breaks.
- **Common rule:** a seed discriminates only if its expected value differs from what the mutated code returns. g13, g18 and m14 all broke that rule. g02 was a reachability gap instead.

## 9. Decisions for Jason

None.

## 10. What would prove this spec wrong

Come back with the evidence if any of these happen at H′:
- **g02:** the unmutated seed shows `applied=false`. The seam isn't threaded through.
- **g18:** the seed isn't exactly `["C5.5-sentinel"]`, or `_find_passing_census` raises. My prediction of how acme renders is wrong.
- **g13:** the unmutated seed shows anything other than `["NOT-EXECUTED"]`, or still shows it under g13. The stray record's E3 fields are wrong, or another sibling branch fires; check `verdict.reasons`.
- **m14:** the rebuilt control finds hits, or the hit dict differs from the prediction.
- **Whole suite:** coverage allowlist errors, a carried anchor count other than 1, or a TOTAL other than 435/85.
- **Audit:** the adjudicator rejects g02's re-anchor. No alternative passes F11, so come back instead of relabelling.