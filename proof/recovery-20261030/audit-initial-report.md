# Executable audit: 3ef29279

**Verdict: NO-GO for acceptance on this independent evidence.** The required default suite exited 1. Coverage and several mutation proofs remain incomplete. The failures below establish a verification blocker; they do not by themselves establish a compiler regression.

## Identity and scope

- W: `3ef292791918937218b2785bc2a08cba6458c5c0`; P: `626463375298d357ffcb3223059f4d3adce6fb10`. Both porcelain outputs were empty at the identity check. P is an ancestor of W; the P-to-W diff outside `proof/` was empty. At the initial check, W's remote branch resolved to W HEAD. `logs/pre-state.txt` records the starting state and ignored-file counts (W 9, P 13); the same counts were observed after plan.
- Independently computed P binary SHA-256: `iyi` f5738660a2bccf39efee9acdf00f2474829969907a623d9e0e33e0f920b4ae74; `crystal` 001cf890c9491f6e8f0a4d45a59222f4a4868d97e52a45a4134258bd62fa8d8a; `iyi-daemon` b816b55f94abb4fa55ba3c3d74a5e2c00498d4ba1a986870a61351e20848560f; `crystal-daemon` d366b31ac664c8d6aa177bb69612547a73187fbbf16d01b16000e659bd7f8937. These match the parent's P1-specific `p1-binaries.json`; `iyi --version` printed stamp `626463375`.
- Commands and environment are retained in `ev.sh`: pinned PATH, HOME `/Users/jwaldrip`, `/Users/jwaldrip/.cache/iyi-corpus-venv/bin/python3 -B`, and per-run pycache prefixes. Tests operated on the no-hardlinks clone `w/` or local fixtures, not P or W. No compiler build or full corpus was run. Parent reports C1 cookie and C2 calc canaries passed; that report is not an independent rerun here.

## Required evidence

| Check | Expected | Observed | Evidence |
|---|---|---|---|
| Default smoke | exit 0, 431 seeds and 83 controls | exit 1; 429/431 seeds, 80/83 controls passed | `smoke.rc`, `smoke.txt:1220` |
| Coverage | exit 0, all missing lines allowlisted | First run interrupted; subsequent run started, completion not established at report creation | `coverage.killed-run1.txt`, `coverage.txt`, `cov/` |
| Python `-O` and `PYTHONOPTIMIZE=1` | each exit 2 | both exit 2, refusal printed | `opt-O.rc`, `opt-env.rc`, corresponding `.txt` files |
| O3 suite | exit 0 | exit 0, 23/23 seeds, 6/6 controls | `o3.rc`, `o3.txt:613` |
| Plan against P and cloned W | exit 0, 29 validated, timeout and probe | exit 0, `Censuses: 29 validated`, timeout and atime probe reported | `plan.rc`, `plan.txt:1-12` |
| Plan write boundary | P/W clean, ignored counts unchanged, no new `iyp-*` root | clean and ignored counts unchanged after plan. Before/after temp inventory included an `iyi-o2-pin-*` entry which subsequently disappeared during concurrent fixture activity; it did not establish a plan write. No clean isolated before/after proof of the whole temp namespace is retained. | `iyp-before-plan.txt`, `iyp-after-plan.txt` |

The full smoke failures were `o7.seed.final-required-rerun`, `o7.seed.guard-m10-post-driver-identity`, and controls `o7.control.guard-m08-run3-disk`, `o7.control.guard-m10-post-driver-identity`, `o7.control.guard-m09-run3-census`. Their driver attempts reported TIMEOUT with a 1-second driver limit. `isolated-rerun-of-failed.txt` and three later isolated reruns retain repeated failures. A separate run with a 60-second limit passed and reported driver wall times 1.979 and 2.556 seconds; the first execution of a freshly created output took 0.779 seconds in one sample (`time_stage.txt`). **Inference:** startup/execution latency makes the one-second fixtures sensitive to this environment. The underlying cause of that latency was not established.

## F1 through F13

Locations below are from the reviewed clone. `PASS` denotes the particular observation, not completion of all associated mutation work.

| Item | Current location | Executed check and result |
|---|---|---|
| F1 | `proof/census/regex.json` site 231; `proofkit.py:1938-1985,2472-2478` | Actual regex-shaped noncanonical invocation matched `regex.negative.231` in observed-negative mode, rc 0. Changing the site to canonical-other with no variants yielded `C5.6-env-call-variant`; original validates. PASS, `demo-misclassified.txt:1-13`, `fguards.txt:1`. |
| F2 | `proofkit.py:3373-3384`; HTTP sites 1384/1405 | HTTP-shaped `--no-codegen` call was unchanged without MISCLASSIFIED; a noncanonical passthrough without ids did yield MISCLASSIFIED. PASS, `demo-misclassified.txt:14-39`. The exercised argv has the same shape for both cited sites; site 1405 was not independently invoked separately. |
| F3 | `run_proof.py:1285-1354` | Run1 rerun changed required set from `[stage]` to `[stage, extra]`; final exited 1 for mismatch and stale attempt, and rerun Run3 reported INVALID (`demo_final_required.txt`). Independently, a one-change conditional Run2 stub yielded a passing initial chain and final, then Run2 a2 added `fixture_001` and final exited 1 for mismatch and stale Run3 (`run2-rerun/result.json`; stub before/after retained). PASS for both reruns. |
| F4 | `proofkit.py:3490-3502` | A never-called required negative variant with no vars produced NOT-EXERCISED on a passing stage ledger. PASS, `demo_not_exercised.txt`. |
| F5 | `proofkit.py:827-924`, `run_proof.py` identity, disk and final checks | Old m01 through m06 full-suite mutation diffs and outputs are retained under `mut/`; named guards caught m01 through m06, but the baseline suite had separate timeout failures. m07 through m12 runs were interrupted; m13 through m20 and the new guard batch lack a complete full-suite mutation run. `mutants.jsonl`, `mutants-run.txt`. INCOMPLETE. |
| F6 | `proofkit.py:2759-2766,2800-2807` | Literal `IYIVAR` in the dns skip regex and sentinel produced C5.4-skip-regex and C5.5-sentinel respectively, controls empty. PASS, `fguards.txt:2-3`. |
| F7 | `proofkit.py:1043-1054` | Spawn-time zero sample exists. Manual slow gate passed and driver TIMEOUT with no reported survivors; both `.times` files contain initial and final samples. `seeds/seeds.jsonl:8-9`. The driver seed's retained helper reported two changed fixture files and an incorrect literal sleep-line check; applied-once proof for that seed remains incomplete. |
| F8 | fuzz census exec evidence; `proofkit.py:2374-3006` | Appending line 73 (`fi`) to existing `[76,97,163]` produced exactly E1-exec-token; control had no violation. PASS, `fguards.txt:8`. |
| F9 | `run_proof.py:324-346` | Plan printed the atime probe and 29 validations. PASS for observable, `plan.txt:9-12`; whole-temp namespace proof remains limited as above. |
| F10 | `proof/census/regex.json`, `xz.json`, `zstd.json`; `proofkit.py:2692-2699` | regex 51, xz 48/52 and zstd 43 are tool skips; individually changing each to platform caused C5.4-platform-guard. PASS, `fguards.txt:4-7`. xz 52 and zstd 43 label `what` as `go` despite the printed Python module dependency; label accuracy needs review. |
| F11 | `smoke_test.py:9366-9378,9432-9435,13415-13973,15706-15789` | The original `git_clean`, `git_rev_parse`, `sha256_file`, `shutil.which` and `os.listdir` monkeypatch patterns were not found; coverage-named fixtures remain as separate ids. However `_o6_limits` mutates the `artifact_legs` module globals `BUILD_TIMEOUT` and `RUN_DEFAULT_TIMEOUT` and restores them. The contract at `corpus-proof-codex-repair-contract.txt:114-121` limits test seams to function parameters. This is a remaining seam-discipline discrepancy, not a demonstration that runtime proof fails. |
| F12 | `roundtrip_shim.py:1244-1248`; `smoke_test.py:17340-17369` | `o4.seed.main-usage-refusal` ran a subprocess with no config, rc 125 and usage text; expected and observed matched. PASS, `smoke.txt:652`. |
| F13 | `artifact_legs.py:406-412` | `o6.seed.c3-cannot-name` put marker before 400 trailing bytes and observed STOP/C3-CANNOT-NAME. PASS, `smoke.txt:860`. Tail-only mutant outcome remains pending. |

## Independent manual seeds

`seeds/seeds.jsonl` retains the control and observations. Forged PASS gave final exit 1 with the recompute mismatch; dns `$dir` gave exactly C5.7-template; a changed header nonce gave exactly STALE and shim rc 125 without appending; appending fuzz line 73 gave exactly E1-exec-token. Slow Run1 gate passed and Run3 driver timed out with no recorded survivors; `.times` sidecars are retained. The last seed's recorded changed-file count and sleep-line evidence do not satisfy the requested applied-once proof, so that seed remains incomplete. The timeout does not establish which portion of the driver consumed its bound.

## Ledger, splits and guard mutations

`matrix-results-base2.jsonl` contains 70 scenarios. Its harness reports 69 PASS and one FAIL: `tls-I-positive-absent` removed two positive calls while the harness required a single changed call. Its actual ledger produced NOT-EXECUTED and NOT-EXERCISED; it cannot be counted as the requested single-change seed. Other retained results include own and positive never-run, copy-over and move-over, unmatched and duplicate cases, auxiliary canonical-other and mixed signal cases, and required/excluded file variants. See `matrix-base2.txt` and JSONL for every result; status sets exclude unrelated NOT-EXERCISED reasons for other driver variants and thus are scoped to the stated comparisons.

`touch-unread.txt` shows file:529 classified ENV-BLOCKED both with and without the skip in the baseline. Real matcher checks for required/excluded values and controls are in `matrix-results-base2.jsonl`; broad platform-root attacks are in `spot-matcher_attacks.txt`. For file negative sites 169, 230 and 428, each of the 17 required values was individually removed from a retained control ledger: all 17 produced the corresponding NOT-EXERCISED reason, with no target negative-variant failures in the control. The altered ledgers and results are in `file-required-values/`. Positive site 628's required and excluded cases are in the matrix.

`matrix-mutants.jsonl` retains separate diffs and negative-case outcomes: removing the atime, hash, stat-before-read, unmatched-record, or required-name-count guards changed expected negative results. The move-over matrix alone did not discriminate the inode guard because the independent atime guard also fired. The separate `inode-guard-targeted.txt` shows the inode-change seed passes on base and fails with the inode guard deleted, while the control passes. `matcher-guard-targeted.txt` records targeted nested-root and platform-root mutant failures; `run-form-guard-targeted.txt` records the run-form mutant's failing control. A full mutant-to-negative-case accounting remains incomplete. Mutation results are evidence about the test inputs exercised, not a proof of all guards.

## Allowlist, source checks and mapping

The seven allowlist entries are at `smoke_test.py:17340-17395`: shim `_exec_real` and `main`/entry glue, run_proof entry and optimized refusal, artifact_legs entry. The listed ranges appear within the P10 locations, but coverage completion and every subprocess observable have not been independently verified. Source-grounded census spot checks for autocert direct execution, signal 68, regex 522, four positive sites, fuzz token, dns verdict marks, template syntax and pattern reason citations are in `spot-census_spot.txt`.

`review-map.jsonl` maps registered review keys to fixture executions in `smoke.txt`. All 33 `review.*` keys had at least one executed seed and no listed fixture failure; four additional O7 keys include the timeout failures described above. This key-level mapping has not independently shown every review-1f line range maps to the correct individual executed seed.

## Limits and remaining proof

Coverage must finish and be inspected. Repair and rerun the full default suite until all seeds and controls pass, without suppressing or reclassifying failures. Independently prove the manual timeout seed's exact applied change, all requested old and new guard mutants, and line-by-line review-1f mapping. The report cannot establish that the full corpus, product tests, or deployment passed. Parent-owned canary results and earlier evidence are separate from this audit.
