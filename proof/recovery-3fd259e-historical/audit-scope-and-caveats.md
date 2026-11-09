# PR147 Prior Proof Audit Recovery (Run 42462457090)

## 1. Executive Summary & Verdict Boundary

- **Verdict:** Historical evidence preservation only.
- **Strict Proof GO:** **EXPLICITLY NOT A GO. NOT A STRICT PROOF GO.**
- **Policy Standard:** This run (42462457090) was executed under the prior RG2 policy which permitted standard library exclusions and did not prove bare 142 without exclusions. The user has since explicitly chosen a strict zero-exclusion policy. Consequently, this audit run stands strictly as historical preservation and does not constitute a proof under current project policy.
- **Purpose:** Durable preservation of CI run `42462457090` hosted audit artifacts and native runner logs on evidence branch `proof/stale-recovery-evidence-20261030` prior to GitHub Actions 14-day retention expiry (~2026-11-22).

---

## 2. Pinned Identifiers & Hashes

- **Product Commit (P):** `3fd259e72465298f291f385df94d5b837017386e`
  - Merge branch 'master' of https://github.com/iyilang/iyi into fix/pr147-upstream-integration
- **Proof Adaptation Commit (W):** `4f02007f07ce5a80f6779432c519f4b7a292b0a7`
  - Ref: `origin/proof/adapted-w-pr147-142corpus-20261108`
- **Controller Commit (C):** `c83c7b6adb97446f1d85e53fc104120f9f5db24e`
  - Ref: `origin/proof/remote-harness-audit-pr147-142corpus-20261108`
  - Fix 142-program audit count report
- **CI Run:** `42462457090` (Job `128674478707`, Attempt 1, Push event)
  - Run URL: `https://github.com/jwaldrip/iyi/actions/runs/42462457090`
- **Original CI Artifact (Retained on GitHub Actions until expiration; removed from Git tip):**
  - ID: `13613220255`
  - Name: `remote-harness-audit-evidence`
  - Digest: `sha256:045f6ea4798b2891c072f0ed9270f2cdadc728cbd9a35cd2460a71755a724a50`
  - Size: 121,205 bytes
  - Original ZIP Archive: `remote-harness-audit-42462457090.zip`
  - Original TAR.GZ Archive: `remote-harness-audit-42462457090.tar.gz` (113,641 bytes, sha256 `9533c4ef561456c9a1ab957c881f3b1673808e3440a6c930f89579c1a9a47eaf`)
  - Original Native Log: `remote-harness-audit-42462457090.log` (80,198 bytes, sha256 `fb0a47cee3335bb81d13fa6742d4bea3dd8912bada80a64d99f852bce2aea26d`)
- **Sanitized Derivative Archive & Log (Preserved on Git branch tip):**
  - Derivative ZIP Archive: `remote-harness-audit-42462457090-derivative.zip` (119,181 bytes, sha256 `898b4a1936b46809167ebb5960285f860936fdc8c126135ef237663b73dc8254`)
  - Derivative TAR.GZ Archive: `remote-harness-audit-42462457090-derivative.tar.gz` (111,739 bytes, sha256 `a0b85b463e044fbe0472ff07529f125996006eade60767cac94a6c6d24aa37c9`)
  - Derivative Native Log: `remote-harness-audit-42462457090-derivative.log` (77,408 bytes, sha256 `1637105a77fe52f360af08bc33151d06c06cc1dda3b668c909208886d36f23d9`)
  - Member count: 26 files (25 non-sensitive proof members 100% byte-for-byte preserved; `environment/machine_fingerprint.json` has `environment_variables` excluded)
  - Omissions: Raw environment variable dump (117 keys, 104 unredacted) in `machine_fingerprint.json` excluded; 6 raw CI step `env:` blocks in native log omitted. Non-sensitive system keys (`platform`, `python`, `tools`, `disk`, `controller_c`) preserved.

---

## 3. Observed Hosted Audit Scope

- **Fixture Census & Validation:**
  - 29 of 29 censuses validated with 0 schema violations.
  - Adapted drivers: `http`, `regex`, `tls`, `websocket`.
- **Smoke Suite Execution:**
  - 441 unique seeds executed and passed.
  - 85 unique controls executed and passed.
  - Total fixtures: 526/526 passed.
  - Exit 0, `HARNESS PASS`.
- **Coverage Gate:**
  - `COVERAGE GATE PASS`. 4 coverage listings generated.
  - Missing lines verified against allowlist.
- **Old-Parser Mutation Check:**
  - Baseline execution passed.
  - Mutated signatures:
    - `o7.control.run1`: failed as intended (gate 1.3 failure).
    - `s5.seed.rg9-bare`: failed as intended (detected old parser acceptance).
    - `s5.seed.rg9-bare-142`: failed as intended (detected old parser acceptance).
    - `s5.seed.rg9-malformed-suffix`: still rejected.
    - `s5.seed.rg9-extended-suffix`: still rejected.
    - `s5.seed.rg9-140`: still rejected.
    - `s5.seed.rg9-141`: still rejected.
    - `s5.seed.rg9-143`: still rejected.
  - Bit-for-bit restoration verified (`b84ff8e75554e1ac79a8ba8140674e400b1ce8e9dd7f6098fad8a3dd19949213`).

---

## 4. Audit Limitations Precluding Strict Proof GO

Strict GO is explicitly withheld due to the following requirements:

1. **Old Exclusion Policy / No Bare 142 Proof:**
   - Run 42462457090 was conducted under the old RG2 policy that allowed standard library exclusions.
   - It did not prove bare 142 without exclusions.
   - User has explicitly established a zero-exclusion policy, which this historical run does not satisfy.
2. **No Native Driver Execution Under Shim at P:**
   - Native drivers have not executed under the roundtrip shim at product commit P (`3fd259e72465298f291f385df94d5b837017386e`).
3. **Historical Status Only:**
   - This evidence is retained purely for provenance and historical record, not for forward integration authorization.

---

## 5. Credential & Secret Audit Summary

- Exact current GitHub token: 0 matches.
- Generic GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`): 0 matches.
- Generic API keys (Google, OpenAI, Anthropic, AWS): 0 matches.
- Private key patterns (`BEGIN ... PRIVATE KEY`): 0 matches.
- Environment variable disclosure audit:
  - Original API artifact: contained raw environment variables in `environment/machine_fingerprint.json` (117 keys, 104 unredacted values, 13 redacted to `[REDACTED]`), and original native runner log contained 6 step `env:` listings. Prior statement claiming `Raw environment disclosure: 0` was inaccurate and has been corrected.
  - Corrective action: Raw-env containing archives and raw log removed from Git branch tip. Replaced with derivative archives and derivative log excluding `environment_variables` from `machine_fingerprint.json` and step `env:` blocks from the runner log.
  - Derivative archive & log scan: Clean across all preserved member bytes, derivative archive binaries, and derivative logs (0 credentials, 0 raw environment dumps).
