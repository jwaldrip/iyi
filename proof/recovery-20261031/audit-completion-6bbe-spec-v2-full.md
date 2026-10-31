# Revised dispatch spec v2: finishing the independent audit at frozen H=6bbe1bf2e

This version fixes all three problems you raised. It also predicts the likely outcome: g02 and g18 probably have no detecting fixture at H, which would make this a NO-GO on two test gaps.

## 0. What changed, and the predicted outcome

1. **Seed 5 keeps the 0.1 s limit.** The `sleep 30` witness is a passive observer. It changes nothing in the stub, the limit, the environment or the call arguments. I tested it inline, writing no files: across 30 bash trials, the observer saw `sleep 30` start 14.5 to 33.9 ms after launch (median 15.7). Every sighting came before a 0.1 s kill of the process group, and every sleeper PID was gone afterwards. There is no 2.0 s run.
2. **No framework.** There are three small files: a receipt wrapper, a verbatim copy of the existing subset runner, and one mutation catalog. There is no heartbeat, stall rule, lock, manifest or kill path. The 20 GiB disk floor is checked before every launch.
3. **Mutants use targeted subsets.** Each mutant has a traced detector and a paired control. Each distinct subset gets one unmutated baseline run. A mutant gets the full default suite only when its named detector does not change. RV's full smoke run stays the baseline for those full-suite runs. Coverage still runs once, in full.
4. **Predicted outcome.** Five read-only scouts traced each mutant from fixture to mutated line. E3 confirms or refutes these two predictions:
   - **g02:** the plan seeds abort before run_proof.py:330, and s1.control.plan checks only that the substrings "Probe:" and "atime=" appear (smoke_test.py:909-924).
   - **g18:** o7.seed.pk2-schema-sentinel-iyivar (smoke_test.py:15332-15335) still gets C5.5-sentinel from the mismatch branch at proofkit.py:2835-2845.

   If their full-suite runs confirm SURVIVED, the verdict is NO-GO on those two gaps. Everything else still runs, so the NO-GO list is complete.

## 1. Bindings

| Name | Value | Access |
|---|---|---|
| H | 6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd | |
| P1 | 626463375298d357ffcb3223059f4d3adce6fb10 | |
| W2 | /Users/jwaldrip/dev/worktrees/iyi-audit-deadlines-seams-20261030 | read-only |
| P | /Users/jwaldrip/dev/worktrees/iyi-stale-integration-repair | read-only |
| RV | /private/tmp/iyi-proof-review-6bbe1bf2e | frozen |
| EV | /private/tmp/iyi-parent-evidence-6bbe1bf2e | read-only |
| AUD | /private/tmp/iyi-proof-audit-3ef29279 | read-only, never imported |
| E | /Users/jwaldrip/dev/worktrees/iyi-stale-recovery-evidence-20261030 | parent is the only writer |
| RV2 | /private/tmp/iyi-proof-complete-6bbe1bf2e | new; absent today |
| PY | /Users/jwaldrip/.cache/iyi-corpus-venv/bin/python3 | |
| HOME | /Users/jwaldrip | |
| PATHPIN | /Users/jwaldrip/.cache/iyi-corpus-venv/bin:/opt/homebrew/opt/curl/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin | |
| Binary manifest | /private/tmp/iyi-parent-evidence-3ef29279-recovered/p1-binaries.json | read-only |

Hashes:
- RV `smoke.log`: aaf53d3a…
- EV `smoke.log`: bf4c0a3a…
- parent `canaries.py`: 51db1867…
- AUD `a_mutants.py`: e35a10f7…
- AUD `b_mutants.py`: 75c0f501…
- E archive `audit-6bbe1bf2e-reported-go-retained.tar.gz`: b6ca8950…

Rules:
- Never list, touch or invoke the locked iyi-stale-plan-clean or iyi-stale-plan-author worktrees.
- Never use the primary checkout as cwd or as an input. Use absolute paths everywhere.
- Every `git status` on W2 or P runs with `GIT_OPTIONAL_LOCKS=0`.
- Every interpreter runs as `PY -B -X pycache_prefix=$RV2/pyc/<unit>`.
- Write only inside RV2, plus fixture and canary scratch under /private/tmp. Delete only your own clone and pycache directories. There is no cleanup authority, so residue is disclosed, never deleted.
- No edits to H, no compiler rebuilds, no product test suites, no full corpus, no model, effort or settings changes.
- Execution units run one at a time.

## 2. Shared files

E1 writes these once. Later slices use them unchanged and cite their sha256.

### `RV2/receipt.py`

Stdlib only. Usage: `$PY -B RV2/receipt.py JOB_DIR CWD [KEY=VALUE ...] -- ARGV...`
1. `os.mkdir(JOB_DIR)`, which fails if the directory exists.
2. If free space on /private/tmp is below 20 GiB, write `refused.json`, exit 3, and launch nothing.
3. Build the environment: `os.environ` with `PATH=PATHPIN`, `HOME=/Users/jwaldrip`, and any `KEY=VALUE` arguments applied. Remove `PYTHONPATH`, `PYTHONHOME`, `PYTHONOPTIMIZE`, `PYTHONINSPECT` and `PYTHONSTARTUP`.
4. Before launching, write `command.json`:
   - argv, cwd, UTC time, `monotonic_ns`, free bytes;
   - values only for PATH, HOME, TMPDIR, LANG, LC_* and any PYTHON*, IYI*, CRYSTAL* or GIT_* names;
   - sha256 of the full sorted environment.
5. Launch with `stdin=DEVNULL`, stdout and stderr to `JOB_DIR/stdout.log` and `JOB_DIR/stderr.log` (opened `O_EXCL`), and `start_new_session=True`. Then write `start.json`: pid, pgid, UTC, `monotonic_ns`.
6. `wait()` with no timeout. No heartbeat, no signal handling, no kills.
7. Write `end.json`: rc, UTC, `monotonic_ns`, elapsed, stdout and stderr byte counts and sha256, free bytes. Append one line to `JOB_DIR/../receipts.jsonl` and fsync it. Exit with the child's rc.

Every JSON file is written by temp file, fsync, `os.replace`, then fsync of the directory. A job without `end.json` is INCOMPLETE, never PASS.

### `RV2/run_fixtures.py`

A byte copy of `AUD/s/run_fixtures.py`; record that the sha256 matches. It runs the named fixtures through H's own Harness and prints the SEED and CONTROL lines, a COUNTS line and a RESULT line. Always call it with `--w <clone>`.

### `RV2/catalog.json`

Build it with `ast.literal_eval` of the top-level `MUTANTS` list in `AUD/s/a_mutants.py` and the `EXTRA` list in `AUD/s/b_mutants.py`. Never import AUD. Then add:
- **x01:** `proof/roundtrip_shim.py`
  - old: `"            os.utime(output, ns=(atime_set_ns, out_mtime_ns))\n"`
  - new: the old text plus the line `"            open(output, \"rb\").read()\n"`
- for every entry: its group, detector, paired control(s) and expected collateral from §3.

Assert that all 43 anchors occur exactly once in `git show H:<rel>`. I measured this: all 43 do.

### Procedure

- **Clone:** one per execution unit, at `RV2/c/<unit>`:
  1. `git clone --no-hardlinks --quiet W2 <dir>`
  2. `git -C <dir> checkout --quiet --detach H`
  3. Assert that HEAD is H and that `status --porcelain=v1 --untracked-files=all --ignored` is empty.
  4. When the unit ends, record porcelain, then remove the clone.
- **Applying a mutation:**
  - the anchor occurs once in the clone file and once in `git show H:rel`;
  - replace it once;
  - `git diff --name-only` must be exactly `[rel]`;
  - save `diff.patch` (`-U0`) and `anchor.json` (counts, line at H, blob, diff sha256).
- **Construction versus outcome:**
  - Expectations go into `expected.json` before each run.
  - A failed precondition (an anchor or patch count other than 1, a failed clone check, a chain that should be PASS and is not) is a construction error. Keep the failed attempt, fix only your own driver, rerun it as `attempt-2`, and disclose both.
  - If preconditions held and the result differs from expectation, record FAIL. Never rerun or relabel it.
- **Mutant labels:**
  - **KILLED:** the named detector changed (a seed whose got no longer equals expect, or a control that FAILs), every paired control PASSed, the same-subset unmutated baseline was green, and the anchor applied once.
  - **MASKED:** m20 only. Accepted only together with an exact E2c result.
  - **SURVIVED:** a complete full-suite run where nothing changed against RV's smoke run.
  - **INCOMPLETE.**

  The only change that counts is the named detector. Other changes are listed as collateral. A nonzero return code alone never counts.

## 3. Subsets and the mutant map

`@N` is a line number in RV's `smoke.log`. File abbreviations, all at H: pk = proofkit.py, rp = run_proof.py, sh = roundtrip_shim.py, al = artifact_legs.py.

**S-ident61** is exactly RV's m01..m06 subset: `prefix:o7.seed.guard-`, `prefix:o7.control.guard-`, `prefix:s1.`. It gets one unmutated baseline run, which gives the reused m01..m05 kills their same-subset baseline.

**GA (27 fixtures):**
- o7.seed.platform-tmp-changed, o7.control.matcher-platform-work, o7.control.guard-m01-python-realpath
- the o7.seed/o7.control guard pairs for m07, m08, m09, m10, m11, m12, m13, m14, m19 and m20
- s5.seed.run1-slow-gate, o7.control.run1
- o7.seed.final-required-rerun, s5.control.stage-chain

| Mutant | Location | Detector | Paired control | Notes |
|---|---|---|---|---|
| m06 | pk:828 | platform-tmp-changed @1144 (PLATFORM-TMP-CHANGED becomes NO-REFUSAL) | matcher-platform-work @1139 (registered) and guard-m01 control @1089 (same check_identity call) | |
| m07 | rp:1032 | guard-m07 @1125 | @1127 | |
| m08 | rp:931 | guard-m08 @1101 | @1103 | |
| m09 | rp:908 | guard-m09 @1129 | @1131 | |
| m10 | rp:1070 | guard-m10 @1105 | @1107 | |
| m11 | rp:1363 | guard-m11 @1109 | @1111 | |
| m12 | rp:1184 | guard-m12 @1113 | @1115 | |
| m13 | rp:1186 | guard-m13 @1117 | @1119 | |
| m14 | rp:296 | guard-m14 @1132 | @1133 | |
| m19 | pk:881 | guard-m19 @1098 | @1099 | |
| m20 | rp:1371 | guard-m20 @1121, predicted unchanged | @1123 | Masked by the required.json mismatch (smoke_test.py:13515-13521; rp:1294-1305). Decided by E2c. |
| g01 | pk:1047 | s5.seed.run1-slow-gate @1158 (`initial_zero` becomes false) | o7.control.run1 @1156 | |
| g04 | rp:1301 | o7.seed.final-required-rerun @1087 (`required_mismatch` becomes false) | s5.control.stage-chain @1138 | |

**GB (29 fixtures):**
- o5.seed.pair-field-drift, o5.seed.record-foreign-nonce, o5.seed.record-foreign-driver, s3.control.ledger
- s3.seed.refusal-not-recorded, s3.control.run, s3.control.refusal
- amend-b.seed.not-executed, amend-b.control.stub-run, amend-b.seed.move-replaced, amend-b.seed.copy-modified, amend-b.seed.run-form-not-counted, amend-b.control.run-form
- o5.seed.unchanged-noncanonical-http, o5.seed.noncanonical-without-ids
- o5.seed.required-no-vars-missing, o5.control.required-no-vars
- o5.seed.value-missing, o5.control.variant-coverage
- o5.seed.positive-no-success, o5.control.positive-success
- o5.seed.e3-inode-changed, o5.seed.e3-atime-not-advanced, o5.seed.e3-sha-changed, o5.control.e2-e3
- o5.seed.e2-count-short, o5.control.e2-repo-template, o5.seed.mixed-own-missing, o5.seed.positive-missing

| Mutant | Location | Detector | Paired control | Expected collateral or note |
|---|---|---|---|---|
| m15 | pk:3491 | pair-field-drift @780 (`["UNFAITHFUL"]` becomes `[]`) | s3.control.ledger @752 | |
| m16 | pk:3320 | record-foreign-nonce @760 (`["STALE"]` becomes `[]`) | @752 | record-foreign-driver @761 |
| m17 | sh:834 | s3.seed.refusal-not-recorded @697 (records 1 becomes 0) | s3.control.run @668 | s3.control.refusal @698 |
| m18 | sh:1060 | amend-b.seed.not-executed @800 (becomes PASS) | amend-b.control.stub-run @808 | |
| x01 | sh:1060 | amend-b.seed.not-executed @800; got must be exactly `{"ledger":"PASS","returncode":0,"status":"PASS"}`, meaning a never-executed output is accepted | stub-run @808, which executes the output | |
| g05 | pk:3402 | unchanged-noncanonical-http @765 (`[]` becomes `["MISCLASSIFIED"]`) | @752 | |
| g06 | pk:3402 | noncanonical-without-ids @764 (`["MISCLASSIFIED"]` becomes `[]`) | @752 | |
| g07 | pk:3519 | required-no-vars-missing @766 (becomes `[]`) | o5.control.required-no-vars @767 | Variants that have variables are still caught by pk:3541. |
| g08 | pk:3541 | value-missing @793 | o5.control.variant-coverage @796 | |
| g09 | pk:3776 | e3-inode-changed @788 | o5.control.e2-e3 @798 | |
| g10 | pk:3788 | e3-atime-not-advanced @789 | @798 | @800, @804 |
| g11 | pk:3812 | e3-sha-changed @790 | @798 | @802 |
| g12 | pk:3762 | e3-atime-not-advanced @789 | @798 | @800, @804 |
| g13 | pk:3729 | amend-b.seed.run-form-not-counted @806 (becomes PASS) | amend-b.control.run-form @810 | |
| g14 | pk:3703 | e2-count-short @782 | o5.control.e2-repo-template @786 | @736, @737 |
| g15 | pk:3556 | positive-no-success @795 | o5.control.positive-success @797 | Wholly missing positives are still caught by pk:3519. |
| g20 | pk:3224 | amend-b.control.run-form @810 FAILs (a control as detector) | stub-run @808 | s3.control.ledger @752 |

**GC (17 fixtures):**
- s1.seed.plan-dirty, s1.seed.plan-stale-compiler, s1.seed.plan-invalid-census, s1.control.plan
- o6.seed.c3-cannot-name, s4.control.row
- o7.seed.validator-env-call-variant, o7.seed.validator-iyivar, o7.seed.validator-platform-guard, o7.seed.pk2-schema-sentinel-iyivar, s2.control.census-all, s1.control.pin
- o7.seed.matcher-platform-two-level, o7.seed.matcher-t-two-level, o7.seed.matcher-outside-both, o7.control.matcher-platform-work, o7.control.matcher-t-work

| Mutant | Location | Detector | Paired control | Expected collateral or note |
|---|---|---|---|---|
| g02 | rp:330 | none predicted | s1.control.plan @40 | Goes to the full-suite run. |
| g03 | al:411 | o6.seed.c3-cannot-name @866 (C3-CANNOT-NAME is lost and STOP becomes FAIL) | s4.control.row @881 | |
| g16 | pk:2498 | validator-env-call-variant @1078 | s2.control.census-all @646 | |
| g17 | pk:2785 | validator-iyivar @1079 | @646 | |
| g18 | pk:2827 | none predicted (@999 is masked) | @646 | Goes to the full-suite run. |
| g19 | pk:2719 | validator-platform-guard @1080 | @646 | |
| g21 | sh:483 | matcher-platform-two-level @1141 (unclassified becomes matched) | matcher-platform-work @1139 | matcher-t-two-level @1142 |
| g22 | sh:476 | matcher-platform-work @1139 FAILs (a control as detector) | matcher-t-work @1140 | |

## 4. Reuse ledger

Reuse requires the RV bytes to match the E archive member, to have been produced at H, to be listed valid by the adjudicator, and to depend on nothing invalid.

**Reused:**
- the before-run `identity.json`
- `layout/*`, `plan/*`, `refusals/*`, `o3/*`
- `smoke/*`: the full baseline, plus receipts @652, @764-767, @866, @662, @676, @886, @1229-1230 and @1088-1144
- `registration/run/*`
- manual seeds 1-4 and the Seed 5 gate leg (`seeds.jsonl` lines 1-8, `seed5-run1_1.times`)
- `fguards`: `fguards.jsonl`, `touch_unread.json`, `demo_misclassified`, `matcher_attacks`, and `demo_final_required` (the F3 Run 1 leg)
- `matrix/**` with corrected labels:
  - "control PASS" means PASS after filtering out NOT-EXERCISED;
  - tls-I is a one-value omission and tls-I2 is the opposite one.
- m01..m05 `.diff` and `.out` files

**Invalid, superseded:**
- `coverage/**`
- `mutants.jsonl`, `mutants_accounting.json`, the generator script
- the m06..m12 `.out` files as kill evidence
- `m20_isolated.json`, `shim_read_out_after_utime.json`
- `canaries/**`
- the Seed 5 driver leg
- `semantic_mapping.json`
- RV's `report.md`

## 5. Slices

**E1. Setup and coverage.** Execution; runs first.
- **Owns:** `RV2/{receipt.py, run_fixtures.py, catalog.json, setup.json, e1/}`.
- **Steps:**
  1. Create RV2 with `mkdir` and no `-p`.
  2. Write the three files and record their sha256 values in `setup.json`.
  3. Preflight and record it:
     - W2 at H and clean, its remote at H, H descending from P1, an empty product diff;
     - P at P1 and clean;
     - ignored-file lists of 13 and 9 with their hashes;
     - the binaries against the manifest;
     - free space, and existing `/private/tmp/iyp-*` entries;
     - no smoke_test, run_proof, roundtrip_shim or artifact_legs process running.
  4. Coverage, once, from a fresh clone, as a single bash call with `timeout: 0`:
     `$PY -B RV2/receipt.py RV2/e1/cov RV2/c/cov -- $PY -B -X pycache_prefix=RV2/pyc/cov proof/smoke_test.py --coverage RV2/e1/cov-out`
     Empty stdout until the run ends is normal: the gate holds the trace child's output in memory (smoke_test.py:18891-18906).
  5. Write `summary.json`:
     - TOTAL, HARNESS and COVERAGE lines;
     - each listing's sha256 and `>>>>>>` lines, compared with the EV listings;
     - executed fixture IDs compared with RV's smoke run;
     - allowlisted lines compared with ALLOWLIST at smoke_test.py:18520-18576.
  6. Write `p10.json`, one row per allowlist entry:
     - its AST location: a top-level `__main__` block, or the shim's `main` or `_exec_real`;
     - its statements, classified as glue, a CLI refusal (usage 1246-1248, `-O` 1524-1530), or forbidden decision code;
     - its fixture's PASS in RV smoke and in the coverage output;
     - its observable text checked against the fixture's assertion lines.
- **Acceptance:**
  - rc 0, exactly `TOTAL ... 432 ... 84 ...` with zeros, HARNESS PASS, COVERAGE GATE PASS;
  - four listings of its own;
  - every missing line inside the 7 allowlisted spans;
  - an ID set equal to RV's;
  - no process left; the clone removed.

**R1. Mapping.** Read-only; runs in parallel with E1; writes `RV2/r1`.
- One row per finding (a sentence or bullet) in review-1f's ranges: 9 (hashlib), 11, 13-29, 31-33, 35-40, 42-57, 59, 62-79, 80, 81, 82-90, 91, 94-96, 97-101, 102-104, 105-106, 108-113, 115-122.
- Row fields:
  - review source and range, and the finding text;
  - fixture ID and asserted behavior, citing the expected literal and the applied change in smoke_test.py;
  - smoke line, expected, observed, applied evidence;
  - control ID, its line, and PASS.
- Account for all 33 `review.*` keys (smoke_test.py:17438-17610).
- A finding a later amendment replaced cites the amendment and the replacement fixture. A finding with no row is listed as UNMAPPED.
- Also write `compare.json`: RV against EV for the smoke and O3 logs, comparing ID sets and expect/got for each ID.
- Copy the inputs in with their sha256. Parse with AST or text only; never import from W2, RV or AUD.

**R2. Static checks and review.** Read-only; runs in parallel with E1; writes `RV2/r2`. Each item gets a receipt with its command or method and output.
- The §8.5 census spot checks.
- F10 label accuracy against the scripts: regex.sh:50, xz.sh:47 and :51, zstd.sh:20-26 and :42.
- An F11 AST scan: no module-attribute assignment or `setattr`; `os.environ` changed only in set/restore pairs.
- `settrace` and `setprofile` appear only at smoke_test.py:18485.
- The limits at artifact_legs.py:47-50 and proofkit.py:1176-1177.
- Both `git -C W2 grep -n build_census H` and `git -C W2 grep -n helper_exec H` exit 1.
- A dead-symbol screen.
- No holes between REVIEW_ITEMS and the registered fixtures.
- Every E1 `exec_line` in all 29 censuses contains its `exec_token`.
- A review of the readiness fence and of run_bounded: smoke_test.py ~990-1250, ~1440-1530, 1700s, 5420s, 13770 and 16250-16450; proofkit.py:1059-1168. For each area (cancellation, no readiness, fatal fallback, owned PID and handler accounting, late signal, error, cleanup) give one verdict: no-defect, defect, or needs-execution, with file:line.
- Disclose RV-era hygiene: `RV/w/proof/__pycache__`, `AUD/s/__pycache__`, and the /private/tmp entries from the RV window with their mtimes. Delete nothing.

**E2. Targeted proofs.** Execution; after E1. Each job gets its own clone and runs through `receipt.py`.

*a. Seed 5 driver leg at the unchanged 0.1 s limit.*
- **Seed job:** inside `with smoke.StageFixture("driver-timeout") as fx`, make exactly the call at smoke_test.py:13929-13956:
  1. assert `fx.stub_difference_count == 2`;
  2. `fx.pin()`, then `fx.write_prerequisites()`;
  3. `cmd_run3(fx.args(), drivers=fx.drivers, driver_limit_sec=_O7_TIMEOUT_DRIVER_LIMIT_SEC, grace_sec=_O7_DRIVER_GRACE_SEC, disk_min_gb=0.0)`;
  4. before teardown, copy `run3/stage/<attempt>/{result.json, driver.times, driver.log}`, the stub script and `stage.json` into the job directory.
- **Witness:** a ctypes thread polling every 0.5 ms, using `/usr/lib/libproc.dylib` (`proc_listchildpids`, `proc_pidpath`) and the `KERN_PROCARGS2` sysctl.
  - The leader is a child of the driver process with argv `["bash","bench/std_stage_exercise.sh"]`.
  - The sleeper is a child of the leader with argv `["sleep","30"]`.
  - Write one fsynced line per sighting to `sampler.jsonl`: time, leader pid, sleeper pid, sleeper pgid, executable.
- **Expected:**
  - rc 1, with status TIMEOUT and `exit` TIMEOUT (the literal at smoke_test.py:14013-14017), and no survivors;
  - `driver.times` has a first line `<t0> 0` and a final line;
  - at least one sleeper with pgid equal to the leader pid, seen before `t0 + 100,000,000` ns;
  - after the call returns, `os.kill(sleeper, 0)` raises ProcessLookupError.
- **Control job:** the same steps with `StageFixture("control")` at `_O7_NORMAL_DRIVER_LIMIT_SEC`, because a 0.1 s limit would also cut the control's real work. Expected: rc 0, PASS, and no sleeper seen.
- **Applied once:**
  - the script diff between control and seed is exactly one added `sleep 30` line;
  - each `census.json` equals `_stage_driver_census("stage", scenario)[1]`, so the census is derived data, not a second change.
- **If the leader is seen but no sleeper appears before the kill:** record UNPROVEN and escalate it as an unmet prerequisite, with `sampler.jsonl` attached. Never change the 0.1 s limit or the stub.

*b. F3 Run 2 leg* (the Run 1 leg is covered by the reused RV demo and fixture @1087).
- **Construction:** wrap `_stage_stub_payloads` in the driver process only. In the `proof/artifact_legs.py` stub's std loop (smoke_test.py:12056-12058), replace `'status':STATUS,'p_nonzero':False})` with `'status':STATUS,'p_nonzero':(index == 1 and os.path.exists('<abs flip>'))})`. The count must be 1.
- **Chain**, run once as `r2-seed` and once as `r2-ctl`:
  1. `StageFixture("control")`;
  2. pin, run1, run2, run3 with the arguments at smoke_test.py:13197-13211;
  3. final₀, which must be rc 0 PASS;
  4. the seed chain only: create the flip file;
  5. run2, whose new attempt must be rc 0 and PASS;
  6. final₁.
- **Expected:**
  - Seed: final₁ rc 1 FAIL, and reasons(seed) minus reasons(ctl) is exactly:
    - `"run3 required.json mismatch: frozen=['stage'], recomputed=['stage', 'fixture_001']"`
    - `"run3/fixture_001 has no attempt"`
    - `"run3/fixture_001 latest attempt is not newer than latest run1/run2"`

    The driver name and order follow rp:752-784.
  - Control: no `required.json mismatch` reason.

*c. m20 isolation.* Four jobs, each a fresh `StageFixture()` followed by `prepare_final_inputs()`. The M jobs use a clone with the catalog's m20 change applied. Keep each `final.json` and the m20 diff, and confirm rp:1371 occurs once at H.

| Job | Clone | Inputs | Expected |
|---|---|---|---|
| H-seed | H | `required.json=[]`, `cmd_final(drivers=())` | rc 1, FAIL, reasons `[]` |
| H-ctl | H | `cmd_final(drivers=fx.drivers)` | rc 0, PASS |
| M-seed | m20 mutant | as H-seed | rc 0, PASS, reasons `[]` |
| M-ctl | m20 mutant | as H-ctl | rc 0, PASS |

*d. Canaries.*
- Copy the parent's `canaries.py` verbatim (its sha must be 51db1867…).
- Run `{PY} -B -X pycache_prefix=... canaries.py {clone} P RV2/e2/canary/out` with `GIT_OPTIONAL_LOCKS=0`.
- Expected: rc 0, the line `C1 PASS <D>`, and the line `C2 {...status PASS}` with its source under the clone.
- From canary root D, copy the small text files (`ledger.jsonl`, `shim.json`, and the shim/out/leg stdout, stderr and exit files) with their sha256. Do not copy binaries.

**E3. Mutants.** Execution; after E2. One driver script of its own, started once with bash `timeout: 0`.
1. **Baselines:** S-ident61, GA, GB and GC, each in a fresh unmutated clone, through `receipt.py` and `run_fixtures.py`. Each must show RESULT PASS, every expect equal to got, and COUNTS of 61, 27, 29 and 17 respectively. A baseline that is not green stops E3.
2. **Order:** GC first, so g02 and g18 give an early signal; then GA; then GB.
3. **Each mutant:**
   1. fresh clone, then apply the mutation;
   2. run its group's subset through `receipt.py` and classify it against that group's baseline;
   3. append one fsynced line to `accounting.jsonl`;
   4. if the named detector did not change (m20 excepted), run the full default suite in the same clone. Confirm porcelain shows only the mutated file first. Classify against RV's smoke run. If anything changed, name the real detector with a traced path. Otherwise label it SURVIVED.
   5. remove the clone.
- **Acceptance:**
  - 38 accounting lines, each with `anchor.json`, `diff.patch` and its receipts;
  - every label follows §2;
  - every baseline green;
  - no process left.

**E4. Identity and assembly.** Runs after everything else.
- **Identity:** `identity-after.json` with the same fields as the E1 preflight, compared with RV's before-run snapshot, E1's preflight and EV's `identity-final.json`.
- **Residue:** RV2-era residue, aggregated from the job receipts.
- **Reuse ledger:** `reuse-ledger.json`, with each reused file's sha256 equal to its archive member.
- **Obligations:** G1-G10 below, each PASS, FAIL or UNPROVEN, with paths.
- **Report files:** `report.md` and `evidence-files.json`, excluding `c/`, `pyc/` and binaries.
- E4 does not issue GO.

**Order:**
1. E1, R1 and R2 in parallel.
2. E2.
3. E3.
4. E4.
5. The parent archives RV2 into E and pushes it.
6. A fresh specialized reviewer.

## 6. Final review: GO only if every item holds

- **G1 Identity.** RV's before-run snapshot, E1's preflight and E4's after-run snapshot agree:
  - W2 at H, clean, with its remote at H;
  - H descends from P1;
  - empty product diff;
  - P at P1 and clean;
  - ignored hashes unchanged (a4cf227e… and 0f82411a…);
  - the four binaries match the manifest;
  - every new `iyp-*` is attributed to a recorded job.
- **G2 Reuse.** The reuse ledger verifies, and R1's comparison shows RV equal to EV.
- **G3 Coverage and P10.** E1's acceptance holds, and `p10.json` puts nothing in forbidden code. CLI refusals are labeled as CLI refusals.
- **G4 Manual seeds.** Seeds 1-4 and the gate leg are from RV. E2a meets every expectation: witness, PID gone, TIMEOUT, `.times`, one change applied, derived census.
- **G5 F-items.**
  - F1, F2, F4, F6, F12 and F13 from RV;
  - F10 accuracy and F11 from R2;
  - F3 from the reused Run 1 leg plus E2b;
  - F7 from the `.times` files plus g01;
  - F9 from `plan.log:11` plus g02.
- **G6 E-probes.** The matrix and the 17 values hold with corrected labels, and g09-g12 are KILLED.
- **G7 Mutants.**
  - m01-m05 are KILLED, using the RV `.out` files plus the S-ident61 baseline;
  - all other mutants are KILLED;
  - m20 is MASKED and E2c is exact;
  - any SURVIVED is a NO-GO finding.
- **G8 Registration.** RV's registration evidence holds, and R2's fence review finds no defect.
- **G9 Mapping.** R1 has no UNMAPPED finding, and all 33 keys are accounted for.
- **G10 Static and process.**
  - every R2 check holds;
  - every receipt is complete;
  - nothing is running;
  - nothing was written outside RV2 and owned scratch;
  - residue is disclosed and nothing was deleted.

On NO-GO, list proven failures separately from UNPROVEN items.

## 7. When to stop and come back to the planner, with evidence

- A group baseline is not green.
- E2a sees the leader but no sleeper at 0.1 s. This is an unmet prerequisite.
- E2c's H-seed reasons are not `[]`.
- The E2b flip cannot keep run2's new attempt at PASS.
- Coverage disagrees with the parent's counts or gate result.
- C1 or C2 fails with the parent's driver at H.
- Any anchor count at H is not 1.
- Free space drops below 20 GiB.
- R2 finds a defect that needs execution. That returns as a possible product defect, not a repair.
- A full-suite run reveals a detector different from the map. That corrects the map and is not a failure.