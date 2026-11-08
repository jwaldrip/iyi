# PR147 Harness Audit Recovery & Scope Assessment

## 1. Executive Summary & Verdict Boundary

- **Verdict:** Scoped GO for harness census adaptation and hosted receipts.
- **Strict Proof GO:** **EXPLICITLY NOT A STRICT GO.** Under no circumstances is this artifact or review to be claimed as a strict PR147 proof GO. No native drivers have executed under the roundtrip shim at product commit P (`180f14f91c829b25362a5ed34b20847f3ac2db77`).
- **Purpose:** Durable preservation of CI run `42429518284` harness audit evidence prior to the 14-day GitHub Actions retention expiry (~2026-11-22).

---

## 2. Pinned Identifiers & Hashes

- **Product Commit (P):** `180f14f91c829b25362a5ed34b20847f3ac2db77`
  - Upstream reference: `iyilang/iyi refs/pull/147/head`
  - Fork reference: `origin plan/native-stale-testing`
  - Tree: `08b41e793910c0e7f7b60ecbc22f281eefc64ff3`
- **Proof Adaptation Commit (W):** `5a3770e96fb12099c4ce9dc3b21895de07dd4cd8`
  - Chain: `W (5a3770e9)` -> `3cdca501` -> `P (180f14f9)`
  - Tree: `8b59efb925b6a71e16f731e8ea36128038b368fe`
  - Census SHA-256 at W:
    - `http`: `924636df86e41b3e5513fe1c5ecfc9b1d6f4142646c262ba94a37f594514baea`
    - `regex`: `3028abe3d5006b5d92ff78df436b7617b8f9e61239c8496ceac50942e5a6fc30`
    - `tls`: `b83d42cb3788ff3f8319f074d20914a84d28472ce5e82b7931f6df23126f5869`
    - `websocket`: `1df9671c618683526ca0d00be92e10eec3357597da04a29a6e1143890538a74e`
  - Script SHA-256 at P:
    - `http`: `220ecf06`
    - `regex`: `638a2017`
    - `tls`: `00d5416c`
    - `websocket`: `dddb8bbe`
- **Controller Commit (C):** `48ffd47caaf45ff9580c35e6f2b0e3c285144bcc`
  - Pinned parameters: `--w-sha 5a3770e9` and `--p1-sha 180f14f9`
- **CI Run:** `42429518284` (Job `128575084391`, Attempt 1, Push event)
  - Run URL: `https://github.com/jwaldrip/iyi/actions/runs/42429518284`
- **CI Artifact:**
  - ID: `13600255503`
  - Name: `remote-harness-audit-evidence`
  - Digest: `sha256:3eb033b6e255cec4cc137d4c6379b1ca97a4c43712ac5171e57a48cf24fb3862`
  - Size: 121,001 bytes
  - Preserved ZIP Archive: `remote-harness-audit-42429518284.zip`
  - Preserved TAR.GZ Archive: `remote-harness-audit-42429518284.tar.gz` (114,039 bytes, sha256 `02f6ebc2a855919fec6297aab79af5298618b4422106bed49e8ba9325b9cb38e`)
  - Member count: 26 files (100% byte-for-byte verified across original `/tmp` and fresh API download)

---

## 3. Genuine Audit Scope & Verified Passes

Evaluated independently by reviewer `agent://ReviewRefreshedProofCensus`:

1. **Census Adaptation (3cdca501 -> 5a3770e9):**
   - Correct and complete C5 mapping of the four changed P drivers (`http`, `regex`, `tls`, `websocket`).
   - Every prior census entry carried over intact; only additions match real new code in P.
   - 29 of 29 censuses validated with 0 schema violations.
2. **Smoke Test Receipts:**
   - 439 unique seeds matching expected output in smoke log (`expect == got`).
   - 85 unique controls passing.
   - Matches expected 439/85 test inventory.
3. **Gate Criteria:**
   - HARNESS PASS and COVERAGE GATE PASS. Every uncovered line verified on allowlist.
4. **Old-Parser Mutation Check:**
   - Under mutation, `o7.control.run1`, `s5.seed.rg9-bare`, and `s5.seed.rg9-bare-141` fail as intended.
   - `s5.seed.rg9-malformed-suffix`, `s5.seed.rg9-extended-suffix`, and `s5.seed.rg9-140` still reject.
   - Restoration hash `518bf900` verified against `proof/run_proof.py`.

---

## 4. Non-Blocking Caveats (P3)

Identified by independent reviewer `agent://ReviewRefreshedProofCensus`:

1. **`check` Listed as `non_invocations` in Regex Census:**
   - `proof/census/regex.json:273-280` categorizes `$IYI check` calls at lines 684 and 749 under `non_invocations`.
   - These are genuine compiler invocations. The roundtrip shim executes them in unchanged mode, and they are exempt from the misclassified-record rule, resulting in zero runtime effect.
   - The census schema command set (`build`, `run`, `doc`, `fmt`) does not define a `check` verb, leaving no alternative valid encoding under current schema rules.
   - The refresh report prose asserting that "check is not an invocation under C5" is technically inaccurate; however, the classification is non-blocking.
2. **`regex.negative.726` Verdict Citations:**
   - `proof/census/regex.json:236-245` cites caught line 737 and status line 741, but omits line 739 ("was not caught") and 727-729 (build failure).
   - This affects only static validation. Sibling fixture `regex.negative.522` already exhibits the identical citation pattern.
3. **Refresh Report Discrepancies:**
   - Minor numerical discrepancies exist between refresh report prose and underlying JSON files:
     - `websocket` sentinel is 1240 (and has no skip at line 228).
     - `tls` sentinel is 3604.
     - `http` sentinel is 4356.
   - The JSON census files are authoritative ground truth over the narrative report.
4. **Summary Label Context:**
   - `delta_audit.census_unchanged: true` in the audit summary refers to the earlier H' to old-W comparison, not to W.

---

## 5. Missing Evidence Precluding Strict Proof GO

Strict GO is explicitly withheld due to the following requirements:

1. **No Runtime Execution of Drivers Under Shim at P:**
   - The regex 12-worker program under `timeout 120` has not executed under the shim.
   - Whether the scratch race reproduces under `-Diyi_observe` within 5x120s is untested.
   - New `http` and `tls` stop/close/parallel mutations and signal traps remain unexercised at runtime.
   - Whether driver runs fit within the 2100s time bound given P's added http workload is unproven.
   - Whether Run 1 or Run 2 introduces drivers lacking a census is unverified.
2. **Commit Signing:**
   - Commits `3cdca501`, `5a3770e9`, and `48ffd47c` are unsigned. Contract S6 requires commits to be signed; prior W and P commits were signed.
3. **Upstream Artifact Expiry:**
   - GitHub Actions artifact retention is 14 days (~2026-11-22).

---

## 6. Credential & Secret Audit

- Generic API credentials / token strings: 0 matches.
- Exact active GitHub token: 0 matches.
- Generic token patterns (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`): 0 matches.
- Private key patterns (`BEGIN ... PRIVATE KEY`): 0 matches.
- AWS credentials / secrets: 0 matches.
- Raw environment dumps: None (sensitive variables `SSH_AUTH_SOCK` and `GIT_CONFIG_KEY_0` verified redacted to `[REDACTED]`).
