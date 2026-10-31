# Re-audit plan at H′ = 813c8074a: dispatch-ready

The plan below re-runs the whole audit at H′ and reuses none of the execution evidence from H. Every runtime unit repeats the archived H procedure with literal redirects and saved diffs. Six things in the brief are wrong or no longer true and are corrected in §1. No decisions for Jason are needed. I edited nothing and ran no fixtures. All facts below come from the E archives, read-only git on W3 and W2, `lsof`, `df` and `count-objects`.

## 1. Corrections to the brief, with evidence

1. **The layout check cannot pass unchanged at H′.** In `annotation-layout/artifact_legs_layout_check.py`, C4 at :21 requires smoke_test.py to have the same AST as BASE `451420109…` outside ALLOWLIST. C5 at :23 requires proofkit, run_proof and roundtrip_shim to be byte-identical to BASE. H′ deliberately changes smoke_test.py and run_proof.py, so the predicted result is C4 FAIL and C5 FAIL `['run_proof']`. This plan keeps the checker unchanged and runs it three ways (§4 X2-5). G1d then uses three things: the H check, the C1-C3 results at H′, and a check that H→H′ is exactly the reviewed hunks.
2. **E3 cannot run all 43 mutants by data changes alone.**
   - Driver v4 (`2cce3efb…`) asserts 516/432/84 at :261-262, :298 and :897.
   - It checks m01-m05 against the H archive in Phase 3 (:1003-1094, `PINNED_M01_M05` :60-81).
   - Its `WORKSPACE_RE` (:84) hard-codes `6bbe1bf2e`.
   - The Phase 2 lookup (:620-713) already handles group `S-ident61`, so a small v5 diff is enough (§3.6).
   - v4 also records anchor `"in_h": 1` as a constant (:675) without computing it. The X1 anchor table supplies that evidence.
3. **There are no leases now.** `lsof -n -P -w -a -d cwd` shows no process whose cwd is W3, W2, P or E, so the restoration leases died with the reboot. All four trees are exposed to the reaper that deleted P, W2 and E before. Leases have to be the first step.
4. **Free space is 83.0 GiB, not 123 GiB.** `df -k /private/tmp` shows 87,037,440 KiB available. One clone is about 196 MiB of packs plus a 47 MB tree, and clones are made one after another, so disk is not a limit. The 20 GiB floor is still enforced on every job.
5. **The parent's EV runs at H used W2 itself as cwd and `--w`.** This is recorded in `acceptance-6bbe1bf2e/plan.json` and `plan-isolation.json`. At H′, W3 is the clone source and identity anchor, and it has 0 ignored files. The EV-equivalent runs therefore go in their own fresh clone, `RV3/ev/w`, with EV's exact argv. This is the only change of procedure. It is disclosed and the reviewer adjudicates it.
6. **Several H receipts had gaps, and they are closed at H′ instead of copied:**
   - `touch_unread.json` names no path or head. The only generator is AUD's `s/a_touch_unread.py`, which reads `AUD/w`. At H′ it runs against `RV3/w` with a receipt.
   - In `e1/analyze.py`, the `p10_entries` (:198-418) are hard-coded and never checked against the files, and the EV comparison (:76-117) is reported but not asserted. At H′ a p10 excerpt check is added. The listing comparison points at the H E1 listings, because at H′ there is no second, EV coverage run.

## 2. What can be re-bound and what must be re-run

The reuse rule (spec v2 §4) says: *"Reuse requires the RV bytes to match the E archive member, to have been produced at H, to be listed valid by the adjudicator, and to depend on nothing invalid."* At this audit "H" means H′.

- **Must be re-run:** every execution receipt in E was produced at H, so none can be reused. That covers:
  - both smoke runs, O3, plan, layout, refusals and registration;
  - manual seeds 1-4 and the gate leg, F guards, the matrix and the 17 values, m01-m05;
  - E1 coverage, E2a-E2d and E3;
  - the canaries.
  
  The static outputs (R1h, R2h v2, citations v2, identity) were also derived from the H tree and are regenerated at H′.
- **May be re-bound (instruments and comparison inputs, never evidence), each sha256-equal to its E member and listed in `e4/reuse-ledger.json`:**
  - `receipt.py` v2, `run_fixtures.py` and `canaries.py`;
  - `catalog-H.json`, as the base of the H′ catalog;
  - every driver, orchestrator, generator, method and checker;
  - the review-1f text and the three readiness review texts;
  - H outputs used only as comparison targets: the H RV and EV smoke logs, the H E1 listings, the H R1 and R2 outputs and the H layout logs.
- **One judgement is re-bound:** the six readiness-fence verdicts. This only holds if S3 proves every cited region is byte-identical at H′ and S4 proves no new code reaches the fence. Otherwise that area gets a fresh review.
- **Not used at H′:** J1 and span B. G1 at H′ is closed by before and after snapshots taken at H′.

## 3. Shared contract (put this in every batch `context`)

### 3.1 Bindings

| Name | Value |
|---|---|
| H | `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd` |
| H′ | `813c8074acb2eed99ffeef78ea49e8c7832e4c01` |
| P1 | `626463375298d357ffcb3223059f4d3adce6fb10` |
| BASE | `451420109dfb0bbcdf800e0143c30768c73e3e0b` |
| W3 | `/Users/jwaldrip/dev/worktrees/iyi-audit-repair-g02-g18-20261031`. The only clone source. Read-only. |
| W2 | `/Users/jwaldrip/dev/worktrees/iyi-audit-deadlines-seams-20261030`. At H, read-only, used for identity only. |
| P | `/Users/jwaldrip/dev/worktrees/iyi-stale-integration-repair`. At P1, read-only. Holds the M2 binaries. |
| E | `/Users/jwaldrip/dev/worktrees/iyi-stale-recovery-evidence-20261030`. The parent is the only writer. `E30=E/proof/recovery-20261030`, `E31=E/proof/recovery-20261031`, `E32=E/proof/reaudit-813c8074a` (new). |
| RV3 | `/private/tmp/iyi-proof-complete-813c8074a`, created with `mkdir -m 700` and no `-p` |
| PY, PATHPIN | as in spec v2 §1 |
| M2 | `E31/p1-binaries-m2.json` |

### 3.2 RV3 layout

The layout is fixed because driver v5's `WORKSPACE_RE` depends on `RV3/w` and `RV3/c/e3-*`.
- `RV3/{receipt.py, run_fixtures.py, catalog-H.json, catalog.json, catalog-delta.json, line-map.json, setup.json}`
- `RV3/inputs/`: restored comparison inputs.
- `RV3/tools/<unit>/`: `<name>.orig`, the redirected copy and `<name>.diff` (`diff -u`).
- `RV3/w`: the RV-equivalent clone. `RV3/evidence/{smoke,o3,plan,layout,refusals,registration/run,manual_seeds,fguards,matrix}`: RV-equivalent outputs.
- `RV3/ev/{w,smoke,o3,plan,refusals}`: EV-equivalent.
- `RV3/{x1,e1,e2,e3,r1,r2,cit,s4,e4}`, `RV3/c/<u>` and `RV3/pyc/<u>`.

### 3.3 Rules

- Never touch the locked iyi-stale-plan-clean or iyi-stale-plan-author worktrees. Never use the primary checkout as cwd or input.
- Run git on W2, W3 or P only for reads, always with `GIT_OPTIONAL_LOCKS=0`. No source edits anywhere.
- Every job goes through `$PY -B RV3/receipt.py <job_dir> <cwd> [K=V…] -- <argv>`. The receipt strips `PYTHON*` first and then applies `K=V`, so `PYTHONOPTIMIZE=1` survives. Each child keeps its archived flags: `-B -X pycache_prefix=RV3/pyc/<u>` by default, `-B` only for EV-equivalent runs, `-B -I` for the layout checker.
- Never execute anything in place from E. Copy it to `RV3/tools`, check its sha256, then run the copy.
- The archived RV scripts create their output directories with `exist_ok=True`. The worker asserts each output directory is absent before launch.
- Clone procedure (`RV3/c/<u>`; `RV3/w` and `RV3/ev/w` stay alive through X1 and X2):
  1. `git clone --no-hardlinks --quiet W3 <d>`, then `checkout --quiet --detach H′`.
  2. Assert HEAD == H′ and that `status --porcelain=v1 --untracked-files=all --ignored` is empty.
  3. Assert `ls-files -s` blob ids equal `ls-tree -r H′`.
  4. Record porcelain, including ignored files, before and after every job. Remove only your own clone and pycache directory.
- Runtime units run one at a time. Static units may overlap runtime units, but never E2a.
- Construction error versus outcome follows spec v2 §2. Keep the failed attempt, fix only your own driver, rerun as `attempt-2` and disclose both. Never rerun or relabel a FAIL.
- **Archive protocol (parent, after every unit and before the next runtime unit):**
  1. Token gate: exact token bytes plus `gh[pousr]_[A-Za-z0-9]{36}` and `github_pat_`, match counts only.
  2. `E32/audit-813c8074a-<unit>.tar.gz`, plus a manifest whose members are re-read and byte-compared to RV3.
  3. Commit, push, and confirm with `ls-remote`.
  
  E2c's archive must be rooted at `RV3/e2`, with members `m20-isolation/<rel>`, because v5 at :417-488 compares those exact members. Nothing may exist only in /private/tmp.

### 3.4 Redirect rules

Exact literal substitution, in this order, in every path form it appears. Save `diff -u`. Any other byte change is a construction error.

| Rule | Old | New |
|---|---|---|
| L1 | `/private/tmp/iyi-proof-complete-6bbe1bf2e` | RV3 |
| L2 | `/private/tmp/iyi-proof-review-6bbe1bf2e` | RV3 |
| L3 | `/private/tmp/iyi-parent-evidence-6bbe1bf2e` | `RV3/ev` |
| L4 | `/private/tmp/iyi-proof-audit-3ef29279` | RV3 (touch_unread only, so `AUD/w` becomes `RV3/w`) |
| L5 | W2 path | W3 path |
| L6 | H | H′ |
| L7 | `E31/audit-completion-6bbe-e2c.tar.gz` | `E32/audit-813c8074a-e2c.tar.gz` |
| L8 | `-6bbe1bf2e/` inside v4 `WORKSPACE_RE` at :84 | `-813c8074a/` |
| L9 | `orchestrate_e2c.py:32` `EXPECTED_CATALOG_SHA` | sha256 of `RV3/catalog.json` |
| L10 | Line-number literals | Only through `RV3/line-map.json` in S1, S2 and S3, each checked by cited-span text equality |
| L11 | `e1/analyze.py:12` `EV_COV` | `RV3/inputs/h-e1-cov-out` |

Left verbatim and disclosed:
- `canaries.py`, which must stay at sha `51db1867…`, so its scratch prefix remains `iyi-canary-6bbe1bf2e-`;
- `receipt.py`;
- `run_fixtures.py`, whose `--w` default to AUD is never used because `--w` is always passed.

### 3.5 H′ catalog

Take `catalog-H.json` (`0be27cf2…`) and change only the fields below, keyed by id. Re-dump with the original's json parameters, proven by round-trip equality on the original. Record every field change in `catalog-delta.json`.

- **g02**
  - `old`: `"        probe = probe_atime_observable(probe_dir, stat_fn=stat_fn)\n"`
  - `new`: unchanged: `"        probe = {\"sha256\": \"x\", \"inode\": 0, \"atime_after_exec_ns\": 0}\n"`
  - `detector`: `"o7.seed.plan-probe-unobservable"`
  - `paired_controls`: `["o7.control.plan-probe-observable","s1.control.plan"]`
  - `expected_collateral`: `null`
  - `notes`: `"H': re-anchored to the stat_fn-threaded call; replacement unchanged"`
- **g13**
  - `detector`: `"o5.seed.e2-unmatched-own"`
  - `paired_controls`: `["s3.control.ledger","o5.control.e2-e3"]`
  - `notes`: `"H': repaired seed isolates pk:3729"`
- **g18**
  - `detector`: `"o7.seed.validator-sentinel-iyivar"`
  - `paired_controls`: `["s2.control.census-all"]`
  - `expected_collateral`: `"o7.seed.pk2-schema-sentinel-iyivar"`
  - `notes`: `"H': new validator seed"`
- **m14**
  - `detector`: `"o7.seed.baseline-skip-captured"`
  - `paired_controls`: `["o7.control.guard-m14-baseline-header"]`
  - `expected_collateral`: `"full suite only: o7.seed.rp-baseline-census-type, o7.seed.rp2-run1-baseline-error"`
  - `notes`: `"H': captured-skip seed; control rebuilt (good header, no skip, expects 0)"`
- **m01-m05**
  - `notes`: `"H': executed in E3 (S-ident61)"`

Asserts:
- 43 entries.
- Every H′ `old` occurs exactly once in `git -C W3 show H′:<rel>`.
- H's g02 `old` occurs 0 times at H′.
- Every H `old` occurs once at H.

### 3.6 E3 data and driver v5

**`static_expectations.json` v5** is H's file (`a9878a45…`) with these changes:
- `h` and `w2` changed by L6 and L5.
- Tokens appended:
  - GA: `o7.seed.baseline-skip-captured` (count 28).
  - GB: `o5.seed.e2-unmatched-own` (count 30).
  - GC: `o7.seed.plan-probe-unobservable`, `o7.control.plan-probe-observable`, `o7.seed.validator-sentinel-iyivar` (count 20).
  - S-ident61 unchanged at 61.
- `mutants_execution_order`: H's 38 in H's order (GC, GA, GB), then `m01…m05`.
- `mutants`: the g02, g13, g18 and m14 edits from §3.5. `expected_status` becomes `KILLED` for g02, g13 and g18 and for m01-m05 (previously `REUSED_KILLED`).
- `blob`, `line_at_h` and `notes` on other entries stay untouched. The driver computes the blob at runtime (:667-670), and `line_at_h` is informational.

**Driver v5** is v4 (`2cce3efb…`) with these changes only:
- L2, L5, L6 and L1 at :43-45 and :54. `RV_SMOKE_LOG` becomes `RV3/evidence/smoke/smoke.log`.
- L7 at :57 and L8 at :84.
- `516/432/84` becomes `520/435/85` at :261-262, `432/84` becomes `435/85` at :298, and `516` becomes `520` at :897.
- Delete Phase 3 (:1003-1094) and its now-dead `RV_MUTANTS_DIR` (:55), `M01_M05_TAR_PATH` (:58) and `PINNED_M01_M05` (:60-81).
- The docstring at :25-27 now says m01-m05 run in Phase 2.
- The `38` in the prints at :612, :629, :997 and :1117 becomes `43`.
- Save `driver_v4_to_v5.diff`.

### 3.7 Line map

`line-map.json` is generated from `git -C W3 diff -U0 H H′ -- proof/smoke_test.py`. It is proven by checking that every unchanged H line equals its mapped H′ line.

- **Expected:** 10 hunks and offsets of +0 (≤7638), +38, +39, +58, +180, +200, +201 and +209 (from about 17433).
- **Spot checks:** 13929→13987, 12056→12095, 18485→18694, 18520→18729, 18891→19100, 17438-17610→17647-17819.
- `run_proof.py` is the identity map: 1531 lines both sides, only lines 324 and 330 differ.
- `git diff --numstat H H′` must be exactly `2 2 proof/run_proof.py` and `225 16 proof/smoke_test.py`.

## 4. Evidence classes, units and order

**Order:**
1. Parent pre-step P0.
2. X1, which includes setup.
3. X2, overlapping S2, S3 and S4.
4. Wait for S2, S3 and S4 to finish.
5. E2a, with nothing else running.
6. E2b, overlapping S1.
7. E2c.
8. E2d.
9. E1.
10. E3.
11. E4.
12. Final archive and push.
13. Fresh reviewer.

E1 runs before E3 because coverage is the only check that the code paths the changed fixtures used to reach are still executed.

| Class (G) | Recovered H command | H′ unit and output | Acceptance |
|---|---|---|---|
| RV smoke (G2, G3, G5) | cwd `RV/w`: `env PATH=PATHPIN $PY -B -X pycache_prefix=RV/pyc-default proof/smoke_test.py` (499.1 s, 432/84) | X1, `RV3/evidence/smoke/{job,smoke.log,smoke.json}`, cwd `RV3/w` | rc 0, `TOTAL seeds_executed=435 seeds_passed=435 seeds_missed=0 seeds_missing=0 controls_executed=85 controls_failed=0 controls_missing=0`, `HARNESS PASS`, `HEADER head=H′`, `clean=true`, gap-fix §6.1 lines |
| EV smoke | cwd W2: `env PATH=PATHPIN $PY -B proof/smoke_test.py` (`bf4c0a3a…`) | X1, `RV3/ev/smoke/`, cwd `RV3/ev/w` | same |
| Targeted repair subsets | gap-fix §6.3 | X1, `RV3/x1/` | §5 |
| O3 ×2 | `$PY -B [-X pycache_prefix=RV/pyc-o3] -c "from proof.smoke_test import run_o3_suite; raise SystemExit(run_o3_suite())"`, cwd `RV/w` or W2 | X2, `RV3/evidence/o3/`, `RV3/ev/o3/` | rc 0, `TOTAL … 23 … 6 …`, `HARNESS PASS`. The two logs are byte-equal to each other, as at H (`7a245f6a…` both). Equality with H is reported. |
| Plan + isolation (G5 F9) | RV: `$PY -B RV/w/proof/run_proof.py plan --p P --w RV/w --compiler P/.build/iyi` plus the before/after record (`evidence/plan/plan.json`). EV: cwd W2, `--w W2`. | X2, `RV3/evidence/plan/`, `RV3/ev/plan/` | rc 0. 12 lines, including `W HEAD: H′`, `P SHA: P1`, `BIN SHA` equal to M2's iyi sha256 (`b8afdb5f…`), `Censuses: 29 validated` and a `Probe:` line at 11. P, W3, W2 and clone porcelain and ignored lists are unchanged, and no new `iyp-*`. |
| Layout (G1d) | `$PY -B -I checker --self-test ROOT BASE`, then `checker ROOT BASE H` (all PASS) | X2, `RV3/evidence/layout/` | Self-test byte-equal to H's `selftest.log`. `ROOT=W3 BASE H` byte-equal to H's `layout-check.log`. `ROOT=W3 BASE H′` shows C1-C3 PASS, C4 FAIL, C5 FAIL `['run_proof']`, rc 1, as predicted. `delta_shape.json` PASS. |
| Refusals ×4 | `-O` and `PYTHONOPTIMIZE=1` on `proof/smoke_test.py` | X2, `RV3/evidence/refusals/`, `RV3/ev/refusals/` | rc 2 and exactly one line: `smoke_test.py refuses optimized Python: sys.flags.optimize=1` |
| Registration (G8) | `$PY -B registration-interval-proof.py --source …/proofkit-fixed.py --output …/registration/run --case fixed\|mutant` | X2, `RV3/evidence/registration/run/` (17 files) | fixed.py sha `25aac5d0…`, mutant.py sha `c7ad3de0…`. Fixed: `escaped null`, signal 2, `survivors []`. Mutant: `_BoundedSignal` escapes. `anchor_matches 1`. |
| Manual seeds 1-4 + gate (G4) | `run_manual_seeds.py`, cwd RV | X2, `RV3/evidence/manual_seeds/` | `seeds.jsonl` lines 1-8 semantically equal to H's: forged-pass control 0/PASS and seed 1/FAIL, stale-nonce STALE / rc 125 / rc 0, C5.7-template at 292, E1-exec-token at 73, run1-gate PASS. `seed5-run1_1.times` has t0 and final more than 1e8 ns apart. Line 9 is recorded but unused (E2a governs). |
| F guards (G5) | `run_fguards.py`, `run_demo_final_required.py`, `run_demo_misclassified.py`, `run_matcher_attacks.py`; AUD `a_touch_unread.py` | X2, `RV3/evidence/fguards/` | 8 fguard rows with H's violations. touch_unread verdict PASS with H's three results. Misclassified flags as at H. demo_final rc 1 FAIL with H's reasons. matcher `all_pass` true (15+5). |
| Matrix 70 + 17 values (G6) | `run_ledger_matrix.py`, then `run_file_required_values.py` | X2, `RV3/evidence/matrix/` | 70 rows PASS with the corrected labels, 17 rows pass |
| Seed 5 driver leg (G4, F7) | `orchestrate_e2a.py` (`2b72336a…`) + `e2a_driver.py` (`676ef4b8…`) | E2a, `RV3/e2/seed5/` | as spec v2 E2a |
| F3 Run 2 (F3) | `orchestrate_e2b.py` (`fd451f55…`) + `e2b_driver.py` (`9f1c3aae…`) | E2b, `RV3/e2/f3-run2/` | as spec v2 E2b |
| m20 isolation (G7) | `orchestrate_e2c.py` (`51960711…`) + `e2c_driver.py` (`3456dcc3…`) | E2c, `RV3/e2/m20-isolation/` | 4-job table as at H |
| Canaries C1/C2 | `canaries.py` (`51db1867…`) `<clone> P <out>` | E2d, `RV3/e2/canary/` | rc 0, `C1 PASS <D>`, `C2 {… "status":"PASS" … "p_nonzero": false}` with source under the clone, binaries equal M2 |
| Coverage + P10 (G3) | `$PY -B -X pycache_prefix=… proof/smoke_test.py --coverage <out>` in a clone (3900.6 s); `analyze.py` (`99e9bf1f…`) | E1, `RV3/e1/` | §5 E1 |
| Mutants ×43 (G7) | driver v4 + static (§3.6) | E3, `RV3/e3/` | 42 KILLED + m20 MASKED |
| Mapping (G9, G2) | `build_compare.py`, `generate_final_r1_artifacts.py`, `write_summary_and_report.py` (E30 r1 tar) | S1, `RV3/r1/` | §5 S1 |
| Static checks (G10, G5 F10/F11) | 8 methods + `run_method.py` v2 (`efa22164…`) + `compare.py` v2, `residue_grep.sh` | S2, `RV3/r2/` | §5 S2 |
| Readiness citations (G8) | `check_readiness_citations_v2.py` + 3 texts (`5a1e58f9…`, `ebbf8f40…`, `0db0cb8a…`) | S3, `RV3/cit/` | §5 S3 |
| Non-weakening + delta review (new, G10) | none | S4, `RV3/s4/` | §5 S4 |
| Identity before/after (G1) | `setup.json` preflight, EV `identity-final.json` | X1 step 5, E4, `RV3/setup.json`, `RV3/e4/identity-after.json` | §6 G1 |

**Parent pre-step P0:**
1. Start named persist services `lease-iyi-{W3,W2,P,E}` with cwd at each root and command `exec 9<.git; exec /bin/sleep 2147483647`.
2. Check each with `lsof -n -P -w -a -d cwd -Fn`, which must list `n<root>`.
3. Write `E32/leases.json` with pid, lstart, argv, cwd and the fd 9 target.
4. Archive into E32, with sha256, the gap-fix spec (`agent://PlanGuardGapFix6bbe`, 454 lines) and this plan. Push.

## 5. Worker briefs

Every worker is a task agent on its configured role, effort hi, with no model override. It restates the §3 paths. It runs no git writes in W2, W3 or P and edits no source.

### X1: launch now. Setup, identity-before and the repair gate.

**Target.** Creates RV3 and owns everything X1 writes: `RV3/{receipt.py, run_fixtures.py, catalog-H.json, catalog.json, catalog-delta.json, line-map.json, setup.json, inputs/, x1/, w, ev/w, evidence/smoke/, ev/smoke/}`.

**Steps.**
0. **Preconditions.**
   - `test ! -e RV3`.
   - Free space of at least 20 GiB.
   - `E32/leases.json` PIDs are live and the lsof cwd check passes.
   - No other process has `smoke_test.py`, `run_proof.py`, `roundtrip_shim.py` or `artifact_legs.py` in its argv.
1. `mkdir -m 700 RV3`.
2. **Restore files.** Use `tar -xOzf` into a new file and check sha256 against the full archived value:

   | Restored file | Source | sha256 |
   |---|---|---|
   | `receipt.py` | `E31/audit-completion-6bbe-e1.tar.gz:receipt.py` | `1f6c1647de8f1fa7acb21ebf607b139f6f1331c35b9640f0e7cb822edff83cff` |
   | `run_fixtures.py` | same tar | `1589867359c89dc3306686c00a71b7ec44fdbfcaa565e541201bed5e92e524d1` |
   | `catalog-H.json` | same tar, member `catalog.json` | `0be27cf2864598b110b0aff797063a9ce81c329cc68dca51bf3cf8cb4bee4403` |
   | `inputs/h-rv-smoke.log` | `E30/audit-6bbe1bf2e-reported-go-retained.tar.gz:evidence/smoke/smoke.log` | `aaf53d3ac2aadfaa7257c8e2bb66ae16e3b540c0e3e3d9abeaf170809f5a42bc` |
   | `inputs/h-ev-smoke.log` | `E30/smoke-6bbe1bf2e-pass.log` | `bf4c0a3a861c25b209219d7c96b54abc3ff42a8575d7ef55184cc5789f808641` |
   | `inputs/e3-v4-driver.py` | `E31/audit-completion-6bbe-e3.tar.gz:e3/driver.py` | `2cce3efb…`; read only for the regexes at :83-103 |
   | `inputs/p1-binaries-m2.json` | `E31/p1-binaries-m2.json` | as archived |
3. Write `line-map.json` and its proof (§3.7).
4. Write `catalog.json` and `catalog-delta.json` (§3.5) and the 43-row `x1/anchors.json`.
5. **`setup.json`** records the sha256 of every restored file and the identity-before snapshot:
   - **W3:** HEAD == H′. Porcelain, including untracked, is empty. Ignored list with entries and sha256 (expected empty). `ls-remote origin refs/heads/proof/audit-repair-g02-g18-20261031` == H′. `rev-parse H′^` == H. `merge-base --is-ancestor P1 H′` returns rc 0. `git diff --quiet P1 H′ -- . ':(exclude)proof'` returns rc 0.
   - **W2:** HEAD == H, clean, `ls-remote` == H. Its 9 ignored entries with size, sha256 and the `printf '%s\n'` list hash.
   - **P:** HEAD == P1, clean. Its 13 ignored entries.
   - **The four P binaries:** sha256, size, inode and mtime_ns, each equal to M2.
   - Free bytes. `/private/tmp/{iyp-*,iyi-*}` names and mtimes. The process scan. The leases.
6. **Targeted subsets.** Run these before the expensive smoke runs.
   - Clone `RV3/c/x1-base`. Run 4 baselines with `run_fixtures.py --w <clone> <ids>` through receipt into `x1/base-<m>/`. Each must show `COUNTS fixtures 3`, `RESULT PASS [] []` and expect==got.
   - Then, for each mutant: clone `RV3/c/x1-<m>`.
   - Apply the H′ catalog entry once. The anchor must occur once in the clone file and once in `git show H′:<rel>`.
   - `diff --name-only` must be exactly `[rel]`.
   - Write `diff.patch` (`-U0`), `anchor.json` and `expected.json` before running.
   - Run the same ids. The RESULT line must be exactly:

   | Mutant | ids | RESULT |
   |---|---|---|
   | g02′ | `o7.seed.plan-probe-unobservable o7.control.plan-probe-observable s1.control.plan` | `RESULT FAIL ['o7.seed.plan-probe-unobservable'] []` |
   | g18 | `o7.seed.validator-sentinel-iyivar o7.seed.pk2-schema-sentinel-iyivar s2.control.census-all` | `RESULT FAIL ['o7.seed.pk2-schema-sentinel-iyivar', 'o7.seed.validator-sentinel-iyivar'] []` |
   | g13 | `o5.seed.e2-unmatched-own s3.control.ledger o5.control.e2-e3` | `RESULT FAIL ['o5.seed.e2-unmatched-own'] []`, with the seed's got `[]` |
   | m14 | `o7.seed.baseline-skip-captured o7.seed.guard-m14-baseline-header o7.control.guard-m14-baseline-header` | `RESULT FAIL ['o7.seed.baseline-skip-captured'] []` |
7. **RV-equivalent smoke.**
   - Clone `RV3/w`.
   - Run `$PY -B RV3/receipt.py RV3/evidence/smoke/job RV3/w -- $PY -B -X pycache_prefix=RV3/pyc/rv-smoke proof/smoke_test.py`.
   - `smoke.log` is a byte copy of `job/stdout.log`. `smoke.json` uses RV's fields: rc, expected, seeds_executed, seeds_passed, controls_executed, controls_failed, elapsed_sec, pass.
   - Check the predicted lines at once.
8. **EV-equivalent smoke.**
   - Clone `RV3/ev/w`.
   - Run `$PY -B RV3/receipt.py RV3/ev/smoke/job RV3/ev/w -- $PY -B proof/smoke_test.py`.
   - `smoke.log` is a byte copy of the job's stdout.
9. **`x1/predicted-lines.json`, for both logs.** These are exact string matches, where `<same>` means the got text equals the expect text. Where the gap-fix prediction includes `applied`, the whole line must match. Otherwise the line must start with the predicted text.
   ```
   SEED o7.seed.plan-probe-unobservable expect={"applied":true,"reason":"EXEC-UNOBSERVABLE","stdout_empty":true} got=<same> applied="stat_fn=frozen-atime(mtime-1000000000);stat_fn_calls=4;plan_probe_calls=4"
   CONTROL o7.control.plan-probe-observable PASS
   SEED o7.seed.validator-sentinel-iyivar expect={"control":[],"seed":["C5.5-sentinel"]} got=<same> applied="sentinel-519-wildcard->IYIVAR;matches_rendered=true;driver=acme;count=1;census_changed=true;script_changed=false"
   SEED o5.seed.e2-unmatched-own expect=["NOT-EXECUTED"] got=["NOT-EXECUTED"] applied="serialized_input_changed=true; extra own output, executed with passing E3 evidence, does not match execution evidence"
   SEED o7.seed.baseline-skip-captured expect=[{"class":"platform","driver":"stage","regex":"^fixture platform skipped$","what":"fixture platform"}] got=<same>
   ```
   The following must also hold:
   - pk2 is `expect=true got=true`.
   - The guard-m14 seed is `expect=0 got=0`.
   - `CONTROL o7.control.guard-m14-baseline-header PASS`.
   - The TOTAL line as in the table, `HARNESS PASS`, rc 0, `HEADER head=813c8074acb2eed99ffeef78ea49e8c7832e4c01` and `HEADER clean=true`.
10. **`x1/smoke-delta.json`.** Normalize with v4's regexes (:83-103) plus `RV/w` and `RV3/w` (and `RV3/ev/w`) mapped to `<W>`.
    - **H RV log against H′ RV-equivalent log:** the ID set gains exactly the 3 new seeds and 1 new control. For every common id, expect, got and control status are equal. Applied strings are equal except for `o5.seed.e2-unmatched-own` and `o7.seed.pk2-schema-sentinel-iyivar`, which are listed.
    - **H′ RV-equivalent against H′ EV-equivalent:** equal ID sets and equal expect, got and status.
11. Write `x1/summary.json` as PASS or FAIL with evidence paths. Keep `RV3/w` and `RV3/ev/w` for X2. Remove the `x1-*` clones.

**Acceptance.** Steps 3-10 all as stated. Every job has `end.json`. Porcelain for `RV3/w` and `RV3/ev/w`, including ignored files, is empty before and after.

**Stop.** At the first failed expectation, finish recording that job and write the summary as FAIL. Launch nothing more and return. This is the gap-fix §10 trigger for the planner.

**Non-goals.** No coverage, E2, E3 or static units. No relabelling.

### X2: the other RV and EV classes, in table order, sequential, one receipt each

**Target.** `RV3/evidence/*`, `RV3/ev/{o3,plan,refusals}` and `RV3/tools/x2/`.

**Change.** Restore each script from the archive member named in the table. RV scripts come from `evidence/<class>/` in the reported-go tar. `a_touch_unread.py` comes from `audit-3ef29279-retained.tar.gz:s/`. The checker comes from `E30/annotation-layout/` and the registration script from `E30/registration-451420109/`. Copy, check sha256, apply L2 or L4, save the diff, assert the output directory is absent, and run with cwd `RV3`. The RV runs at H used cwd `RV` and imported from `RV/w`.

Unit-specific points:
- **O3, plan and refusals:** RV-equivalent runs use cwd `RV3/w` with RV's flags. EV-equivalent runs use cwd `RV3/ev/w` with the argv recorded in `E30/acceptance-6bbe1bf2e/{o3,plan,optimized-*}.json`. The plan record keeps RV's `before`/`after` schema for P, W3, W2, the clone and `iyp_roots`.
- **touch_unread:** stdout, or the file the script writes, becomes `fguards/touch_unread.json`, with the receipt recording cwd and clone.
- **Registration:** `proofkit-fixed.py` is a byte copy of `RV3/w/proof/proofkit.py`. `proofkit-mutant.py` is built the same way RV built it. The archived `registration.diff` applied once must give `c7ad3de0…`.
- **Layout:** write `delta_shape.py`, stdlib only and reading via `git -C W3 show`. It checks:
  1. artifact_legs, proofkit and roundtrip_shim are byte-equal between H and H′;
  2. the ALLOWLIST value has the same AST at H and H′;
  3. numstat matches §3.7;
  4. the run_proof hunks are exactly gap-fix Change 1;
  5. the smoke_test hunks are exactly the 10 hunks of the line map, each tagged with its gap-fix Change 2-8.
- At the end: porcelain checks, then remove `RV3/w` and `RV3/ev/w`.

**Acceptance.** The table rows.

**Non-goals.** No E-units and no H-only reuse.

### E2a, then E2b, E2c and E2d: one unit each, after X2, S2, S3 and S4 have returned

**Change.** Restore the orchestrator and driver from `E31/audit-completion-6bbe-e2{a,b,c}.tar.gz` (shas in the table). Apply L1, L5 and L6, plus L9 for E2c. Its line-number asserts at :153 and :176 (`1371`) stay as they are: rp:1371 is identical at H′ and the line count is unchanged. Run each orchestrator as at H.
- **E2a:** nothing else may run, including static units and X jobs. It imports `_stage_driver_census` from W3 because of L5, with `-B` and `dont_write_bytecode`.
- **E2d:** run `$PY -B RV3/receipt.py RV3/e2/canary/job RV3/c/e2d-canary GIT_OPTIONAL_LOCKS=0 -- $PY -B -X pycache_prefix=RV3/pyc/e2d-canary RV3/tools/e2d/canaries.py RV3/c/e2d-canary P RV3/e2/canary/out`. Copy only the small text files, with their sha256.

**Acceptance (identical to H):**
- **E2a seed:** rc 1, TIMEOUT/TIMEOUT. A sleeper with pgid equal to the leader is seen before t0+1e8 ns. Afterwards `ProcessLookupError`. `survivors []`. Exactly one added `sleep 30` line. Censuses equal `_stage_driver_census`.
- **E2a control:** rc 0, PASS, no sleeper.
- **E2b:** final₀ PASS in both. run2 attempt a2 PASS. seed final₁ rc 1. seed − ctl reasons are exactly the 3 spec strings. The control has no `required.json mismatch`.
- **E2c:** h-seed rc 1 FAIL `[]`; h-ctl rc 0 PASS; m-seed rc 0 PASS `[]`; m-ctl rc 0 PASS.
- **E2d:** as in the table. The parent archives E2c rooted at `RV3/e2` before E3.

**Non-goals.** No change to the 0.1 s limit, the stub or the flip construction.

### E1: coverage, after E2d

**Change.**
- Clone `RV3/c/cov`. Run `$PY -B RV3/receipt.py RV3/e1/cov RV3/c/cov -- $PY -B -X pycache_prefix=RV3/pyc/cov proof/smoke_test.py --coverage RV3/e1/cov-out` as one bash call with `timeout: 0`. Empty stdout until the end is normal.
- Restore `inputs/h-e1-cov-out/*.cover` from the e1 tar: `3d13b0f2…`, `769be0b6…`, `6c92b9ca…`, `deabcd84…`.
- Run `analyze.py` with L1, L2, L5 and L11. `RV_SMOKE_LOG` becomes `RV3/evidence/smoke/smoke.log`.
- New: `e1/p10_verify.py` checks that each hard-coded p10 line and code excerpt equals `git show H′:<module>` at that line. It also checks that analyze's `allowlist_spans` equal the ALLOWLIST value parsed by AST from the H′ clone.

**Acceptance:**
- rc 0, the 435/85 TOTAL, `HARNESS PASS` and `COVERAGE GATE PASS`.
- Four listings of its own.
- `summary.json` PASS: `cov_fixture_ids == rv_fixture_ids` (520), and every `>>>>>>` line inside the 7 spans.
- Missing-line sets equal to the H E1 listings (0/6/1/14), which is the gap-fix §6.2 prediction. A difference is reported, and it is a G3 failure only if it falls outside the spans.
- `p10.json`: 7 rows, none forbidden, CLI refusals labelled.
- `p10_verify` all equal.
- No process left. Clone removed.

**Token gate:** archive `cov/command.json` only if the gate reports 0. Otherwise archive a masked copy, as at H.

### E3: all 43 mutants, after E1

**Change.**
- Put v5 (`driver.py`), `driver.py.v4`, `driver_v4_to_v5.diff`, `static_expectations.json` (v5), `static_expectations_H.json` and `static_delta.json` in `RV3/e3/`.
- Launch once: `$PY -B RV3/e3/driver.py`, with no `--resume-baselines` on the first attempt, bash `timeout: 0`, and `driver.pid.json` written.
- Inputs: `RV3/{receipt.py, run_fixtures.py, catalog.json}`, `RV3/evidence/smoke/smoke.log` and `RV3/e2/m20-isolation`, plus its E32 tar.

**Acceptance:**
- Baselines PASS with counts 61, 28, 30 and 20, and every expect==got.
- 43 rows in `accounting.jsonl`, each with `anchor.json`, `diff.patch`, `expected.json` and complete receipts.
- 42 KILLED, m01-m05 among them against the S-ident61 baseline, and m20 MASKED with E2c raw byte-equal.
- Group markers for gc, ga, gb and s-ident61. `inventory.json`. No process left.
- Any SURVIVED, FAIL, INCOMPLETE or UNCLASSIFIED stays exactly as labelled and is a NO-GO finding. A full-suite run, if one happens, classifies against the H′ RV log under the v4 rules.

**Non-goals.** No relabelling. No edits beyond §3.6.

### S1: R1′ mapping and compare, after X2, overlapping E2b and later units

**Change.**
- Restore `build_compare.py`, `generate_final_r1_artifacts.py` and `write_summary_and_report.py` from `E30/audit-completion-6bbe-r1.tar.gz:r1/` and check them against the R1h manifests.
- Apply L1 to inputs and outputs, landing in `RV3/r1`.
- Apply L10:
  - the 158 `smoke_test.py:a-b` literals through the line map (none overlaps a changed hunk);
  - `write_summary_and_report.py:97` span becomes 17647-17819;
  - the smoke-log literals (`1199` and `1138` at :46-47 and :125, `smoke:780` at :169, and in the finding text at generate :261) become the H′ RV log line of the same fixture id.
- The inputs are the four H′ logs, their json, review-1f (`07896050…`) and the H′ `smoke_test.py`, whose blob id must equal `git rev-parse H′:proof/smoke_test.py`.
- New `translation_proof.json`: for every translated citation, the H span text equals the H′ span text, and every smoke-log literal names the same id.

**Acceptance:**
- 102 rows PROVEN, 33 `review.*` keys PROVEN, 0 UNMAPPED, each row's seed and control PASS in the H′ RV log.
- `compare.json`: ID sets equal (520 smoke, 29 O3), and expect, got and status equal.
- H R1 outputs with the translation table applied equal the H′ outputs, except fields read from the H′ logs, which must be equal after the `build_compare` SCRATCH normalization and the `<W>` root.

### S2: R2′ static checks, after X1

**Change.**
- Restore the 8 methods from `E30/…r2-methods.tar.gz` and check them against `method-hash-check.json`.
- Restore `run_method.py` v2 (`efa22164…`), `compare.py` v2 and `residue_grep.sh` from `E31/…r2h-v2.tar.gz`. Clone `RV3/c/r2`.
- Apply the W-root literal from the allowlist note to the `RV3/c/r2` clone path, and L1. Run every method through `run_method.py` with the audit-hook allowlist (reads only from `RV3/c/r2`, the method, the runner, stdlib and own pycache).
- New `translate_targets.py` maps the H outputs (`E30/…r2-initial.tar.gz:r2/*.json`) to `RV3/inputs/h-r2-translated/`. It rewrites smoke_test.py line fields through the map and records every leaf it changes in `translation-log.json`. That log has a reason per leaf, plus `expected-deltas.json`: registry total registered and mapped 516→520 and review items 172→174.
- Run `compare.py` v2 unchanged except for paths against the translated targets.
- Run `git -C W3 grep -n build_census H′` and `… helper_exec H′`.

**Acceptance:**
- Every leaf accounted: COMPARED_EQUAL, TRANSLATED_EQUAL, EXPECTED_DELTA, or the H categories EXPLICIT_EXCLUSION, UNPROVEN_BY_METHOD and DISCLOSED_OBSERVATION. Zero unaccounted.
- Both greps exit 1.
- Semantic invariants:
  - `settrace` and `setprofile` occur only in `_COVERAGE_BOOTSTRAP`, at 18694 and 18703.
  - F11: 0 `setattr` calls; module attribute assignments only `sys` at 43-44; `os.environ` mutations as at H, all in set/restore pairs.
  - The dead-symbol set equal to H by name.
  - Registry: 520 fixtures, 174 items, 0 unmapped or dangling, O3 29.
  - limits, F10, exec tokens and census spot checks byte-equal to H, because their inputs are byte-identical.

A mismatch is a FAIL and a possible product defect (spec v2 §7), not a repair.

### S3: readiness citations v2′, after X1

**Change.**
- Restore `check_readiness_citations_v2.py` and the three texts from the r2h-v2 tar.
- Translate the texts' smoke_test.py citations with L10 (proofkit is identity) and save the diffs.
- Run against a clone `RV3/c/cit` at H′.
- New `regions.json`: sha256 of every cited span at H and at H′.

**Acceptance:**
- All 155 citations resolve at H′, with 10 quotes found in their scoped spans, 23 code annotations, 4 prose labels and 14 non-code labels.
- Every region is byte-identical, so the six no-defect verdicts are re-bound.
- Any non-identical region means stop: that area needs a fresh fence review.

### S4: non-weakening and delta review, after X1

**Target.** `RV3/s4/report.json`, with file:line for every claim, read from H and H′ via `git -C W3 show`.

**Change.**
1. For each fixture changed in place, list the H assertion and the H′ fixture that still makes it. Give id, source line and H′ smoke line.
   - **e2-unmatched-own's old "no out_ref" path (pk:3748-3755):** for example `amend-b.seed.run-form-not-counted`. Prove it is still asserted.
   - **pk2's old regex-mismatch path (pk:2835-2845):** name a fixture whose expected value depends on it.
   - **The m14 control:** its old input (good header plus a skip line) is now `o7.seed.baseline-skip-captured`, with an exact dict instead of a count of 1.
   
   No H′ fixture making an assertion that H made is a weakening finding.
2. Map every H..H′ hunk to gap-fix Changes 1-8. Confirm the new code adds no imports, no attribute assignments, no `setattr`, no `os.environ`, subprocess or timeout use, and no call into the readiness-fence code (run_bounded, the handlers, cancellation).
3. Confirm the three new fixtures discriminate: their expected values differ from what the targeted mutant returns. X1 supplies the runs.

### E4: assembly, after E3

- `identity-after.json` with the same fields as `setup.json`, compared field by field.
- Residue: new `/private/tmp` entries attributed to receipts by time. Nothing is deleted.
- `reuse-ledger.json` (§2).
- The G1-G10 table (§6), each item PASS, FAIL or UNPROVEN with paths.
- `report.md` and `evidence-files.json`, excluding `c/`, `pyc/` and binaries.
- E4 does not issue GO.

## 6. G1-G10 at H′ (E4 cites these)

| G | Holds when | Cites |
|---|---|---|
| G1a source | W3 at H′, clean, ignored 0, remote at H′; H′^ = H; P1 is an ancestor of H′; product diff P1..H′ empty; W2 at H, clean, remote at H; P at P1, clean | `setup.json`, `e4/identity-after.json`, X2 plan records |
| G1b inputs | P's ignored list (13) and the M2 binaries (sha256, size, inode, mtime_ns) equal before and after and equal to `p1-binaries-m2.json`; W2's list of 9 unchanged. No continuity claim against M1, `a4cf227e` or `0f82411a`. | same |
| G1c scratch | every new `iyp-*` and `iyi-*` attributed to a receipt | `e4/residue.json` |
| G1d code shape | `line-map.json` proof; layout check (BASE,H) PASS; layout check (BASE,H′) shows only the predicted C4 and C5 failures; `delta_shape` PASS | `RV3/evidence/layout/*` |
| G2 reuse | the ledger checks out, and R1′ `compare.json` shows RV-equivalent equals EV-equivalent for smoke and O3 | `e4/reuse-ledger.json`, `r1/compare.json` |
| G3 coverage, P10 | E1 acceptance, p10 with nothing forbidden, `p10_verify` | `e1/*` |
| G4 manual seeds | seeds 1-4 and the gate leg at H′; E2a expectations | `evidence/manual_seeds/*`, `e2/seed5/*` |
| G5 F-items | F1, F2, F4, F6, F12 and F13 from H′ smoke lines (looked up by id) and fguards; F8 fguards; F10 and F11 from R2′; F3 = `demo_final_required.json` + `o7.seed.final-required-rerun` + E2b; F7 = `seed5-run1_1.times` + E2a `.times` + g01 KILLED; F9 = `plan.log:11` + g02 KILLED (+ X1 g02′) | as listed |
| G6 E-probes | 70 rows and 17 values with corrected labels; g09-g12 KILLED | `evidence/matrix/*`, `e3/*` |
| G7 mutants | 42 KILLED + m20 MASKED with exact E2c; X1 agrees for g02′, g13, g18 and m14; `x1/anchors.json` shows each anchor once at H′ | `e3/*`, `e2/m20-isolation/*`, `x1/*` |
| G8 registration, fence | registration results as at H; S3 citations resolve and regions are identical; S4 shows no new code reaching the fence | `evidence/registration/run/*`, `cit/*`, `s4/*` |
| G9 mapping | 102 rows PROVEN, 33 keys, 0 UNMAPPED, translation proof | `r1/*` |
| G10 static, process | every S2 check; every receipt has `end.json`; only ledgered lease PIDs survive; writes only in RV3 and owned scratch; residue disclosed; S4 finds no weakening | `r2/*`, `s4/*`, `e4/*` |

## 7. Fresh reviewer brief (independent, read-only)

**Target.** Decide GO or NO-GO for the strict corpus chain at H′. You know nothing of the planner or the workers.

**Inputs.**
- `E32` (pushed), plus `E30` and `E31` for H originals.
- Contracts in E32: the gap-fix spec, this plan, spec v2 full (`E31/…spec-v2-full.md`), the G1 correction and the R2h allowlist.
- Read-only git on W3, W2 and P (`GIT_OPTIONAL_LOCKS=0`), and PY.
- Treat summaries as claims, not proof.

**Do:**
1. Recompute G1-G10 from raw files: stdout logs, `end.json`, `accounting.jsonl`, listings and every redirect `.diff`.
2. Re-derive from raw stdout the TOTAL lines, the four X1 RESULT lines, all 43 E3 labels under the v4 rules, the E2c table and the coverage gate lines.
3. Confirm every `.diff` changes only the literals in §3.4. Confirm `driver_v4_to_v5.diff`, `catalog-delta.json` and `static_delta.json` are exactly §3.5 and §3.6.
4. Adjudicate explicitly:
   - the g02 re-anchor (same `new`, `old` equal to the threaded call);
   - the layout composition;
   - the EV-equivalent cwd change;
   - the re-bound readiness verdicts;
   - each S4 non-weakening claim;
   - the gap closures (touch_unread provenance, `p10_verify`).
5. Run no fixtures, builds or edits. Write only your report.

**GO only if** every G item holds, every adjudication is accepted and no row is SURVIVED, FAIL, INCOMPLETE or UNCLASSIFIED. On NO-GO, list proven failures separately from UNPROVEN items, each with file:line or archive member.

## 8. Risks: what would prove a step wrong

- **X1:** any predicted line, RESULT line or anchor differs, or TOTAL is not 435/85. The repair is wrong; return to the planner for H″. This covers the gap-fix §10 cases: g02 `applied=false`, the g18 render or driver differing, g13 not `["NOT-EXECUTED"]`, m14 control hits.
- **Smoke delta:** an expect, got or status change outside the predicted set means unexpected collateral. Stop.
- **Layout:** C1-C3 FAIL at H′, C5 listing anything besides run_proof, or `delta_shape` finding an unassigned hunk.
- **O3:** the two H′ logs differ, or rc or TOTAL are wrong.
- **E2a:** leader seen but no sleeper inside 0.1 s. That is an unmet prerequisite (spec v2 §7). Never change the limit.
- **E2b or E2c:** outcomes differ from H.
- **E3:** a baseline not green, or any non-KILLED label besides m20.
- **E1:** missing lines outside the 7 spans, or the ID set not equal to the RV log.
- **S1 and S3:** a translated span's text differs. The map is wrong: fix the map, not the product.
- **S2:** an unexplained leaf.
- **S4:** a lost assertion. That is a NO-GO finding, and a new seed means a new head.
- **Environment:**
  - The reaper removes a tree: lease failure, G1 break. Stop.
  - Free space under 20 GiB: receipt exit 3. Stop.
  - A reboot wipes RV3: restore from E32 and resume at the first unit not yet archived.
  - Another session runs `smoke_test` or `run_proof`: re-scan before E2a.

## 9. Measured dominators at H

- E1 coverage: 3900.6 s, the single longest job.
- RV smoke: 499.1 s. EV smoke is comparable.
- E3 at H, receipts summed (3706.5 s):
  - baselines 330.5 s, of which S-ident61 took 178.9 s;
  - 38 subset runs, 1299.9 s;
  - four full-suite runs, 451.7 to 595.2 s each.
  - Attempt-3 wall clock was 57 min 13 s.
- At H′, E3 adds five S-ident61 subset runs (m01-m05) and needs no full-suite run if every detector fires.
- Smaller jobs: canaries 97.8 s; E2b 17.2 s and 20.1 s; E2a 3.5 s and 3.8 s; E2c 2.2 to 4.8 s per job.
- Disk: 83.0 GiB free, measured; clones are about 196 MiB of packs plus a 47 MB tree each, one at a time.