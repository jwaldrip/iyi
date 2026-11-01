**GO.** Proof tooling at H′ `813c8074acb2eed99ffeef78ea49e8c7832e4c01` is ready to run the strict corpus chain. All of G1-G10 now hold, every adjudication is accepted, and E3 has no SURVIVED, FAIL, INCOMPLETE or UNCLASSIFIED row. I ran nothing except read-only git and Python, and wrote no files.

## 1. Content check, my own checker, all 80 rows of `r1v4/semantic_mapping.json`

- **The three re-cited rows are now specific to their case at H′:**
  - Row 9, `s3.seed.ledger-stale-header`: applied `:7841` is `header["nonce"] = "stale-nonce"`; expected `:7842` is `expected = ("STALE",)`.
  - Rows 13 and 78, `s3.seed.ledger-divergence`: applied `:7862-7873` builds the `_o5_pair(… own=False, consumer_rc=7 …)` record; expected `:7874` is `expected = ("DIVERGENCE",)`.
- **No row fails.** All 80 rows have both citations inside the fixture's call closure. 56 also pass my content-token test outright.
- **The other 24 flags are my checker's false positives.** I cleared each one by reading the cited spans:
  - Rows 9, 13 and 78 above: the applied-change span is the mutation itself, which never contains the expected-value tokens.
  - Validator rows 16-24 and 63: each cites its own mutator (for example `_mutate_duplicate_site` at 2364-2371) plus the shared expected-structure code in `_isolated_validator_seed` (2042-2049).
  - Row 6 is a control and cites its whole function.
  - Rows 3, 7, 10, 11, 14, 37, 48, 59, 69 and 74 cite the expected dict or the mutation code inside the fixture's own function.

## 2. Changes are confined to the three rows

- Archive `613e5798…` (52 members) is byte-equal to native `RV3/r1v4` and `RV3/tools/s1v4`, with no native file left out. E tip `99c695c87` matches the remote and the tree is clean.
- `generate_final_r1_artifacts.py.base.py` equals the v3 generator except for path lines (`r1v3`→`r1v4`, `s1v3`→`s1v4`). From base to final exactly 6 lines change, all of them citation strings.
- `semantic_mapping.json` v3→v4 changes only rows 9, 13 and 78, and only their two citation fields. `write_summary_and_report.py` and `build_compare.py` change only by path.
- All 80 rows are PROVEN with 0 UNMAPPED, and every fixture and control is PASS on its recorded line in the H′ RV smoke log.
- The 33 keys are all proven. `review_keys_accounting.json`, `compare.json` and the inputs are identical to earlier versions.
- All three jobs ran with rc 0, matching stream hashes and cwd `RV3/c/s1v4`.

## 3. Residual non-blocking items, verbatim for disclosure

1. E3 driver v5 differs from v4 beyond §3.6: renames RV2/W2/H to RV3/W3/H_PRIME, removed comments and docstring lines, argparse text, group-marker filename normalised with `.replace('-', '_')`, and an anchor count computed from the clone HEAD (H′) at driver.py:601-608 and :640. accounting.jsonl therefore reports `in_h` as the count at H′ (g02 shows 1); the count at H is in x1/anchors.json (g02 = 0), and x1/g02/anchor.json also records 1. Labels re-derived from raw subset stdout: 42 KILLED, m20 MASKED.
2. tools/cit/check_readiness_citations_v2.py adds constant fields `exists_at_H_prime` (:120) and `all_citations_resolve_at_H_prime` (:426) and edits print text (:446-448); resolution is still enforced by the in-bounds assertion, and all 155 regions were independently recomputed identical.
3. tools/s2/compare.py adds TRANSLATED_EQUAL/EXPECTED_DELTA classification (:47-58, :657-660), conditional check statuses, and rewrites the PATH pairing observation (:615-616) from recomputed set-to-restore lines instead of line-map translations. compare.py never compares leaf values itself; all 864 leaves were independently compared: 837 equal, 5 exact expected deltas, 22 labelled leaves identical to H. preflight, postflight and run_method change only r2h paths to r2.
4. The X2 runner was edited during the run (fguards absence assert removed, jobs skip-if-exists, demo_misclassified assertion moved to `f2_guard`); the pre-edit copy is `s2/tools/x2/x2_runner.py` in the S2 archive. Each job ran once and its outputs equal H's. Refusals attempt-1 (rc 2, refusal on stderr) is retained in `evidence/refusals-attempt-1`.
5. E32/leases.json omits lstart and argv and truncates three cwd fields; full lsof cwd lines are in setup.json and e4/identity-after.json, and PIDs 59434-59437 were alive at review, started 21:54:31Z.
6. W2 holds a tenth ignored file, `proof/__pycache__/smoke_test.cpython-314.pyc`, created 2026-10-31T17:37:40Z before this audit and unchanged since (disclosed in setup.json).
7. mapping_report.md says "Across the 432 seeds" where H′ has 435; this is disclosed in r1v4/translation_proof.json as `report_prose_seed_count_residual`.
8. Report-prose path edits (RV2/r1 to RV3/r1vN) are disclosed in `generator_deviations_disclosure`. S1 v1, v2 and v3 are superseded and retained in E32.
9. E4's diff check reports 28 unmatched hunks: tools/s2/compare.py (24, see item 3), tools/s2/{preflight,postflight,run_method}.py (3, r2h-to-r2 paths), tools/e1/analyze.py (1, plan rule L11). None changes a G result.
10. Plan text errors: E32 is `proof/recovery-813c8074a`; readiness hashes `ebbf8f40`/`0db0cb8a` match no archive member (the H inputs `9b645622`/`de9a3f71` were used); "102 rows" is 80 rows covering 102 finding lines, as at H.
11. A bytecode file written under `RV3/tools/s1v3/__pycache__` by a helper run without `-B` is no longer present and was never archived; `tools/s1v4` and `r1v4` contain no `__pycache__`.
12. R1 citation fields differ from H's accepted R1 for 36 rows: 2 single-line literals translated in S1v2, and 33 plus 3 misdirected H-era citations re-derived in S1v3 and S1v4. Finding-to-fixture mapping, PROVEN status and the 33 keys are unchanged from H.