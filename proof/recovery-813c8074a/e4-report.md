# Re-Audit Assembly Report: Unit E4 at H' = `813c8074acb2eed99ffeef78ea49e8c7832e4c01`

**Audit Subject:** `813c8074acb2eed99ffeef78ea49e8c7832e4c01` (repaired head H')
**Frozen Audit Head:** `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd` (H)
**Integration Ref:** `626463375298d357ffcb3223059f4d3adce6fb10` (P1)
**Base Revision:** `451420109dfb0bbcdf800e0143c30768c73e3e0b` (BASE)
**Date:** 2026-11-01 00:50:46Z
**Evidence Directory (RV3):** `/private/tmp/iyi-proof-complete-813c8074a`
**Unit:** E4 (Assembly)

---

## 1. Executive Summary and Scope

Unit E4 performs the final independent assembly and verification of the re-audit conducted at repaired head H' (`813c8074a`). In strict conformance with `local://reaudit-plan-hprime.txt` (§5 'E4' and §6) and related audit contracts (`audit-completion-6bbe-spec-v2-full.txt`, `recovery-g1-correction.txt`, `guard-gap-spec-v2.txt`), E4 evaluates all raw execution artifacts produced across all units (X1, X2, S1, S2, S3, S4, E2a-d, E1, E3).

**Key Findings:**
- **All 10 Audit Gate Categories G1-G10 PASS** when evaluated directly against raw native artifacts.
- **Source & Environment Invariants Hold:** W3 is clean at H', remote at H', parent equals H, P1 ancestor verified, product diff outside proof/ empty. W2 remains clean at H with 9 identical ignored files (hash `0f82411a...`). P remains clean at P1 with 13 identical ignored files. All four M2 binaries in P/.build match `p1-binaries-m2.json` in sha256, size, inode, and mtime_ns before and after.
- **Process & Lease Isolation:** All 4 parent leases (`lease-iyi-W3`, `lease-iyi-W2b`, `lease-iyi-Pb`, `lease-iyi-Eb`) remained alive throughout execution with their exact bound working directory targets. Free space on `/private/tmp` remained above 63.3 GiB (well above the 20 GiB floor).
- **100% Native Receipt Integrity:** All 106 execution receipts across all units have valid `end.json` records with byte-exact matching stdout and stderr stream hashes and 0 receipt errors.
- **Reuse Protocol Strictly Enforced:** All 48 re-bound instruments and comparison targets match their pinned E archive members bit-for-bit. Zero execution evidence from H was reused; all receipts in RV3 were executed freshly at H'.
- **Mutants (G7):** All 43 mutants executed in Phase 2 under driver v5. 42 KILLED + 1 MASKED (m20, verified via raw E2c evidence). Subsets GA (28), GB (30), GC (20), S-ident61 (61) all passed baselines.
- **Coverage Gate (G3):** E1 coverage passed full harness (`435 seeds / 85 controls`), `HARNESS PASS`, `COVERAGE GATE PASS`. Missing line sets across modules are 0 / 6 / 1 / 14, strictly matching H and within the 7 allowlisted spans. P10 analysis verified 7 clean rows with 0 forbidden entries, all verified against H' source.
- **Readiness Fence (G8):** S3 proved all 155 citations resolve at H' with 155/155 cited regions byte-identical between H and H'. S4 proved 0 weakening findings, negative invariants preserved, and zero calls reaching fence routines. The six readiness-fence verdicts are re-bound.

> **Readiness Fence Notice:** Unit E4 does **NOT** issue GO. In accordance with plan §5, E4 compiles evidence, evaluates criteria G1-G10, verifies native invariants, and presents exact findings for the independent fresh reviewer (§7).

---

## 2. G1-G10 Verification Table

| Gate | Name | Status | Citations (Raw Artifacts) | Recomputed Numbers & Artifact Evidence |
|---|---|---|---|---|
| **G1a** | source identity | **PASS** | `setup.json`<br>`e4/identity-after.json`<br>`evidence/plan/plan.json`<br>`ev/plan/plan.json`<br>`ev/plan/plan.log` | **w3_head**: 813c8074acb2eed99ffeef78ea49e8c7832e4c01<br>**w3_clean**: True<br>**w3_ignored**: 0<br>**w3_remote**: 813c8074acb2eed99ffeef78ea49e8c7832e4c01<br>**w3_parent**: 6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd<br>**w2_head**: 6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd<br>**w2_clean**: True<br>**w2_remote**: 6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd<br>**p_head**: 626463375298d357ffcb3223059f4d3adce6fb10<br>**p_clean**: True<br>**rv_plan_rc**: 0<br>**ev_plan_rc**: 0 |
| **G1b** | inputs and M2 binaries | **PASS** | `setup.json`<br>`e4/identity-after.json`<br>`inputs/p1-binaries-m2.json` | **p_ignored_count**: 13<br>**w2_ignored_count**: 9<br>**w2_ignored_hash**: 0f82411aee9ddd7a4bacf1c35bc741fb404d89e9bce26109ca9580e60583ec69<br>**binaries_count**: 4<br>**binaries_all_match**: True |
| **G1c** | scratch attribution | **PASS** | `e4/residue.json` | **total_tmp_entries**: 5<br>**new_entries_count**: 1<br>**deleted_count**: 0<br>**all_new_attributed**: True |
| **G1d** | code shape and layout | **PASS** | `line-map.json`<br>`line-map-proof.json`<br>`evidence/layout/selftest.log`<br>`evidence/layout/layout-check.log`<br>`evidence/layout/layout-check-hprime.log`<br>`evidence/layout/delta_shape.json` | **line_map_proof_status**: PASS<br>**unchanged_lines_checked**: 18968<br>**delta_shape_status**: PASS<br>**delta_numstat**: None<br>**layout_base_h_c1_c5**: ALL_PASS<br>**layout_base_hprime_c1_c5**: C1_PASS, C2_PASS, C3_PASS, C4_FAIL(smoke_test.py), C5_FAIL(['run_proof']) |
| **G2** | reuse ledger and log comparison | **PASS** | `e4/reuse-ledger.json`<br>`r1/compare.json` | **rebound_items_count**: 48<br>**all_matched_archive**: True<br>**execution_evidence_reused**: False<br>**r1_smoke_fixtures**: 520<br>**r1_smoke_seeds_equal**: True<br>**r1_smoke_controls_equal**: True<br>**r1_o3_fixtures**: 29<br>**r1_o3_seeds_equal**: True<br>**r1_o3_controls_equal**: True |
| **G3** | coverage gate and P10 analysis | **PASS** | `e1/cov/stdout.log`<br>`e1/cov/end.json`<br>`e1/cov-out/*.cover`<br>`e1/summary.json`<br>`e1/p10.json`<br>`e1/p10_verify.json` | **cov_rc**: 0<br>**cov_fixtures_executed**: 520<br>**missing_lines**: {"proofkit": 0, "run_proof": 6, "artifact_legs": 1, "roundtrip_shim": 14}<br>**missing_lines_equal_h**: True<br>**p10_rows_count**: 7<br>**p10_verify_status**: PASS |
| **G4** | manual seeds 1-4, gate leg, and E2a | **PASS** | `evidence/manual_seeds/seeds.jsonl`<br>`evidence/manual_seeds/seed5-run1_1.times`<br>`e2/seed5/seed/end.json`<br>`e2/seed5/seed/result.json`<br>`e2/seed5/seed/assertions.json`<br>`e2/seed5/control/end.json`<br>`e2/seed5/control/result.json` | **manual_seeds_rows_verified**: 9<br>**manual_seeds_1_8_all_expected**: True<br>**e2a_seed_rc**: 1<br>**e2a_seed_status**: TIMEOUT<br>**e2a_seed_assertions_verdict**: PASS<br>**e2a_control_rc**: 0<br>**e2a_control_status**: PASS |
| **G5** | F-guards and audit items | **PASS** | `evidence/fguards/fguards.jsonl`<br>`evidence/fguards/touch_unread.json`<br>`evidence/fguards/demo_final_required.json`<br>`evidence/fguards/demo_misclassified.json`<br>`evidence/fguards/matcher_attacks.json`<br>`e2/f3-run2/f3_run2_summary.json`<br>`evidence/plan/plan.log` | **fguards_rows**: 8<br>**fguards_all_passed**: True<br>**touch_unread_verdict**: PASS<br>**demo_final_rc**: 1<br>**matcher_all_pass**: True<br>**e2b_status**: PASS<br>**plan_probe_line**:   Probe:     sha256=511602b8cf083bdff74d43242b71c27484bd63121c07f3b59575d35676e1f6cb inode=2657126588 atime=1793485832287536216 |
| **G6** | matrix 70 and file required values 17 | **PASS** | `evidence/matrix/matrix_results.jsonl`<br>`evidence/matrix/file-required-values/results.json`<br>`e3/accounting.jsonl` | **matrix_rows_count**: 70<br>**matrix_all_pass**: True<br>**required_values_count**: 17<br>**required_values_all_pass**: True<br>**g09_g12_killed**: True |
| **G7** | all 43 mutants (42 KILLED + m20 MASKED) | **PASS** | `e3/accounting.jsonl`<br>`e3/mutants_accounting.json`<br>`e2/m20-isolation/m20_isolation_summary.json`<br>`x1/anchors.json`<br>`x1/summary.json` | **total_mutants**: 43<br>**killed_count**: 42<br>**masked_count**: 1<br>**m20_status**: MASKED<br>**m20_isolation_status**: PASS<br>**x1_anchors_count**: 43<br>**x1_all_anchors_unique_in_h_prime**: True |
| **G8** | registration interval proof and readiness fence | **PASS** | `evidence/registration/run/fixed-observation.json`<br>`evidence/registration/run/mutant-observation.json`<br>`evidence/registration/run/mutation.json`<br>`cit/summary.json`<br>`cit/regions.json`<br>`s4/report.json` | **registration_fixed_escaped**: None<br>**registration_fixed_survivors**: 0<br>**registration_mutant_escaped**: {"signum": 2, "type": "_BoundedSignal"}<br>**registration_anchor_matches**: 1<br>**citations_total**: 155<br>**citations_differing_regions**: 0<br>**citations_quotes_found**: 10<br>**s4_weakening_findings**: 0<br>**s4_negative_invariants**: PASS |
| **G9** | R1 semantic mapping and translation proof | **PASS** | `r1/summary.json`<br>`r1/translation_proof.json`<br>`r1/semantic_mapping.json`<br>`r1/review_keys_accounting.json` | **mapping_rows_proven**: 80<br>**mapping_rows_unmapped**: 0<br>**review_keys_total**: 33<br>**review_keys_proven**: 33<br>**translation_proof_span_text_equal**: True |
| **G10** | static checks and process hygiene | **PASS** | `r2/summary.json`<br>`r2/compare.json`<br>`r2/residue_grep.json`<br>`e4/receipts_audit.json`<br>`e4/identity-after.json`<br>`s4/report.json` | **r2_overall_status**: PASS<br>**r2_total_leaves**: 864<br>**r2_unaccounted_leaves**: 0<br>**r2_leaf_breakdown**: {"COMPARED_EQUAL": 814, "DISCLOSED_OBSERVATION": 3, "EXPECTED_DELTA": 5, "EXPLICIT_EXCLUSION": 11, "TRANSLATED_EQUAL": 23, "UNPROVEN_BY_METHOD": 8}<br>**r2_build_census_hits**: 0<br>**r2_helper_exec_hits**: 0<br>**receipts_total_jobs**: 106<br>**receipts_errors**: 0<br>**leases_all_alive**: True |

---

## 3. Identity Verification (`identity-after.json` vs `setup.json`)

Field-by-field verification between preflight (`setup.json`) and postflight (`identity-after.json`):

- **W3 (Head H'):**
  - HEAD: `813c8074acb2eed99ffeef78ea49e8c7832e4c01` (Match)
  - Clean: `true` (porcelain empty, untracked files empty)
  - Ignored files: `0` (Match)
  - Remote ref `refs/heads/proof/audit-repair-g02-g18-20261031`: `813c8074acb2eed99ffeef78ea49e8c7832e4c01` (Match)
  - Parent `HEAD^`: `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd` (Equal to H)
  - Merge-base ancestor check `P1`: `0` (Success, P1 is ancestor of H')
  - Product diff `P1..H' -- . ':(exclude)proof'`: empty (0 non-proof diffs)
- **W2 (Head H):**
  - HEAD: `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd` (Match)
  - Clean: `true`
  - Remote ref `refs/heads/proof/audit-deadlines-seams-20261030`: `6bbe1bf2e484bc4ec33aa6d58667c43c096cd3bd` (Match)
  - Ignored files count: `9` (Match)
  - Ignored files list SHA256: `0f82411aee9ddd7a4bacf1c35bc741fb404d89e9bce26109ca9580e60583ec69` (Exact match)
  - Ignored files details (sha256, size, inode, mtime_ns): 100% identical
- **P (Head P1):**
  - HEAD: `626463375298d357ffcb3223059f4d3adce6fb10` (Match)
  - Clean: `true`
  - Ignored files count: `13` (Match)
  - Ignored files details (sha256, size, inode, mtime_ns): 100% identical
- **P/.build M2 Binaries:**
  - `iyi`: sha256 `b8afdb5f55b03754b8194978e320cbca3c0816661cadcbd3083f0872a64ca418`, size `50845488`, inode `2647885868`, mtime_ns `1793465861706431758` (Exact match to M2)
  - `crystal`: sha256 `899ca96ee708a87876220b4c3ae16edaa9e7fb539cdf524b36ad919b667fe196`, size `50855032`, inode `2647896620`, mtime_ns `1793465903336266947` (Exact match to M2)
  - `iyi-daemon`: sha256 `8f34ebd2e4664b4c517410d7f18cff890f3d291691695414de8dcb9848c2c5d7`, size `50476536`, inode `2647922971`, mtime_ns `1793465987371679130` (Exact match to M2)
  - `crystal-daemon`: sha256 `96a0caa1e8933aa2fd938a31df48253fcb5de67d92ed8ec07c46615977818e5f`, size `50486016`, inode `2647930075`, mtime_ns `1793466055289032853` (Exact match to M2)
- **Leases:**
  - PID 59434 (`lease-iyi-W3`): alive, cwd `/Users/jwaldrip/dev/worktrees/iyi-audit-repair-g02-g18-20261031`
  - PID 59436 (`lease-iyi-W2b`): alive, cwd `/Users/jwaldrip/dev/worktrees/iyi-audit-deadlines-seams-20261030`
  - PID 59435 (`lease-iyi-Pb`): alive, cwd `/Users/jwaldrip/dev/worktrees/iyi-stale-integration-repair`
  - PID 59437 (`lease-iyi-Eb`): alive, cwd `/Users/jwaldrip/dev/worktrees/iyi-stale-recovery-evidence-20261030`
- **Free Space:**
  - Preflight: 87275515904 bytes (~81.3 GiB)
  - Postflight: 67972976640 bytes (~63.3 GiB)
  - Floor check (>= 20 GiB): `PASS`

---

## 4. Residue and Scratch Audit (`residue.json`)

- **Total `/private/tmp` scratch entries matching `iyi-*` / `iyp-*`:** 5
- **Deleted entries:** 0 (Nothing was deleted)
- **New entries created during H' re-audit:** 1
  - `/private/tmp/iyi-canary-6bbe1bf2e-7er4lzm0`: Created during unit E2d by `canaries.py` (start `2026-10-31T22:44:24Z`, end `2026-10-31T22:45:30Z`). Attributed to `e2/canary/job`. Disclosed per plan §3.4 because `canaries.py` is re-bound verbatim at sha `51db1867...` and retains its hardcoded prefix.
- **Retained historical roots disclosed:**
  - `/private/tmp/iyi-proof-complete-6bbe1bf2e`: Retained audit root from H
  - `/private/tmp/iyi-proof-review-6bbe1bf2e`: Retained review root from H
  - `/private/tmp/iyi-canary-6bbe1bf2e-efmbfx4x`: Retained canary scratch from earlier H run
  - `/private/tmp/iyi-proof-complete-813c8074a`: Active re-audit root at H' (RV3)

---

## 5. Reuse Ledger Summary (`reuse-ledger.json`)

The reuse ledger enforces the strict reuse doctrine of spec v2 §4 and plan §2:
- **Execution Receipts Reused:** `FALSE` (0 execution receipts from H were reused; all receipts in RV3 were executed natively at H').
- **Re-bound Instruments & Comparison Targets:** 48 items registered, **100% verified byte-identical** (`all_matched_archive = true`).
  - `receipt.py` v2 (`1f6c1647...`) from E31
  - `run_fixtures.py` (`15898673...`) from E31
  - `canaries.py` (`51db1867...`) from E30
  - `catalog-H.json` (`0be27cf2...`) from E31
  - `inputs/h-rv-smoke.log` (`aaf53d3a...`) from E30
  - `inputs/h-ev-smoke.log` (`bf4c0a3a...`) from E30
  - `inputs/e3-v4-driver.py` (`2cce3efb...`) from E31
  - `inputs/p1-binaries-m2.json` (`5aa656a4...`) from E31
  - 4 E1 coverage comparison targets (`inputs/h-e1-cov-out/`) from E31
  - 6 E2 orchestrators and drivers from E31 (`audit-completion-6bbe-e2{a,b,c}.tar.gz`)
  - 3 S1 scripts (`build_compare.py`, `generate_final_r1_artifacts.py`, `write_summary_and_report.py`) from E30
  - 3 S2 runner/checker tools (`run_method.py`, `compare.py`, `method_residue_grep.sh`) from E30/E31
  - 8 S2 methods from E30 (`audit-completion-6bbe-r2-methods.tar.gz`)
  - 4 S3 citation checker and review texts from E30/E31
  - `r1/inputs/corpus-proof-review-1f.txt` (`07896050...`) from E30
  - Layout checker `artifact_legs_layout_check.py` (`0187d832...`) from E30
  - Registration interval runner `registration-interval-proof.py` (`168d477c...`) and patch `registration.diff` (`68bdb92e...`) from E30
  - `a_touch_unread.py` (`610ce766...`) from E30
  - 7 X2 generator scripts from E30 (`audit-6bbe1bf2e-reported-go-retained.tar.gz`)
- **Re-bound Judgement:** The six readiness-fence verdicts are re-bound, supported by S3 proof that all 155 cited regions are byte-identical and S4 proof that no new code in H' reaches the fence.

---

## 6. Receipt Verification & Redirect Audit

- **Receipt Audit:**
  - Total job directories audited with `end.json`: 106
  - Total `receipts.jsonl` files: 71
  - Total receipts line entries: 106
  - Verification errors: 0 (0 errors; all stream hashes, byte counts, command.json, start.json, and free bytes >= 20 GiB verified natively).
- **Redirect Diff Audit:**
  - 44 diff files examined across `tools/`, `cit/`, `e3/`, and `evidence/`.
  - Every hunk strictly conforms to plan section 3.4 literal substitutions (L1-L11), catalog delta (§3.5), driver v5 (§3.6), and registration mutant patch.

---

## 7. Disclosures, Deviations, and Attempt Retentions

### 7.1 Deviations from H Procedure (Authorized by Plan)
1. **EV-Equivalent Clone Location (§1.5):** At H, parent EV runs used W2 directly as cwd and `--w`. At H', W3 has 0 ignored files and serves as the clean clone source and identity anchor. EV runs therefore ran inside a dedicated clone `RV3/ev/w` with EV's exact argv.
2. **Layout Check Composition (§1.1):** Layout checker was run unchanged. C4 reported FAIL (smoke_test.py AST changed) and C5 reported FAIL on `['run_proof']`, matching exact predictions. Gate G1d was satisfied via `delta_shape.py` and reviewed hunks.
3. **Mutants Phase 2 Execution (§1.2, §3.6):** All 43 mutants executed in Phase 2 under driver v5 (including m01-m05, which previously used Phase 3 archive reuse at H). Dead Phase 3 was excised.
4. **g02 Re-anchor (§3.5):** Re-anchored to the `stat_fn`-threaded call in `proof/run_proof.py:330` (`probe = probe_atime_observable(probe_dir, stat_fn=stat_fn)`). Replacement string unchanged.

### 7.2 Retained Attempt-1 Failures (Spec v2 §2)
1. **`evidence/refusals-attempt-1`:** Unit X2's initial run of flag-refusal was retained when output paths were corrected to `evidence/refusals/`. Retained attempt-1 contains complete receipt records with rc 2.
2. **`e4/job_build_reuse_ledger` (attempts 1-4):** Assembly driver iterations encountering archive member pathname variations before final verified attempt 5 (`job_build_reuse_ledger_7`). All attempt directories retained with receipts.
3. **`e4/job_compute_g_table` (attempts 1-8):** Assembly script iterations aligning dictionary keys to raw json schemas before final verified attempt 9. All attempt directories retained with receipts.

### 7.3 UNPROVEN_BY_METHOD and DISCLOSED_OBSERVATION Items (S2)
- **UNPROVEN_BY_METHOD (8 items):**
  - `census_spot_checks: checks/autocert_direct/is_direct`: derived from build_fn=='build' and exec_fn=='run_own' (formal predicate unarchived).
  - `census_spot_checks: checks/signal68_vs_regex522/verified`: derived from signal68 has evidence and regex522 has none (formal predicate unarchived).
  - `f11_ast_scan: total_harmful_module_monkeypatches`: 2 sys attribute assignments exist at smoke_test.py:43-44; harmful=0 is unarchived heuristic treating sys as benign.
  - `f11_ast_scan: file_details/proof/<module>/harmful_module_monkeypatches_count` (5 modules).
- **DISCLOSED_OBSERVATION (3 items):**
  - `f11_ast_scan: environ_discipline`: AST proves 41 smoke_test.py mutations and 0 production module mutations. Pairing observation: pre-try mutations at 9828, 10840, 13094, 13096; 5 PATH sites restore unset PATH as empty string.
  - `f11_ast_scan: runner_execution_disclosure`: method_f11_ast_scan.py defines analyze_file without driver loop; runner executes on proof/*.py.
  - `dead_symbol_screen: intent_claim_disclaimed`: intent claim disclaimed; facts: 0 references outside definition at H'; _read_pid has no comment; run_o3_suite docstring does not mention python -c.
  - `trace_profile_hooks: title_note`: title states 'only at 18485'; recomputed data proves hits on line 18694 and 18703 at H' (both inside _COVERAGE_BOOTSTRAP).

### 7.4 Re-bound Judgements
- **Six Readiness-Fence Review Verdicts:** Re-bound under plan §2 based on S3 proof that all 155 cited regions are byte-identical and S4 proof of no code reaching the fence.

---

## 8. Conclusion and Hand-off

Unit E4 has completed full assembly. All raw execution files, receipts, diffs, and environment snapshots have been audited and verified. All gates G1-G10 PASS.

**Deliverables produced under `RV3/e4`:**
- `identity-after.json`: Field-by-field preflight vs postflight environment comparison
- `residue.json`: Comprehensive scratch accounting and attribution of all `/private/tmp` entries
- `reuse-ledger.json`: Complete 48-item instrument/target provenance ledger
- `g_table.json`: The G1-G10 verification table recomputed from raw files
- `evidence-files.json`: Manifest of all non-excluded evidence files in RV3
- `report.md`: This comprehensive assembly report
- `receipts_audit.json`: Native verification results of all 106 execution receipts
- `diffs_verification.json`: Native verification results of all 44 redirect diffs

**Next Step:** Parent archives E4 into `E32/audit-813c8074a-e4.tar.gz`, pushes to remote, and hands off to the independent fresh reviewer (§7) to decide GO / NO-GO.
