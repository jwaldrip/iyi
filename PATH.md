# Remote strict proof operator path

## Identity and authorization

The product revision is `180f14f91c829b25362a5ed34b20847f3ac2db77` (PR #147 head), and the audited native proof revision is `5a3770e96fb12099c4ce9dc3b21895de07dd4cd8` (W). C is the exact controller commit running the hosted workflow, not a label substituted for its checkout. The workflow checks out P and W separately and checks their actual revisions. Synthetic emitters, compilers, reports, and logs live outside those source trees.

Strict dispatch is refused by default before planning, pinning, building, or native execution. Activation requires verified platform checks against the GitHub API:
  - An independent reviewer agent that did not implement the change generates the audit report (`audit.json`, `audit.md`, `census-review.md`) on evidence branch `proof/strict-evidence-<C[:12]>-20261107`.
  - Jason personally approves GitHub protected deployment environment `strict-proof` (ID `26584191206`, required reviewer `jwaldrip` account ID `43164`, `can_admins_bypass: false`, `prevent_self_review: false`, branch policy `proof/strict-lifecycle-repair-20261102`) with the exact comment `iyi-strict-authorization-v2 sha256:<D>` on attempt 1, where D is the SHA-256 digest of the canonical manifest v2 bytes.
  - The strict gate step (`authorize`) runs before any P checkout, toolchain build, or native execution, and independently validates:
    - Run metadata: workflow ID 403985693, path `.github/workflows/remote-strict-proof.yml`, head SHA C, head branch `proof/strict-lifecycle-repair-20261102`, status `in_progress`, attempt `"1"`.
    - Job context: check run ID matches `job.check_run_id`, linked deployment environment `strict-proof`, task `deploy`.
    - Job graph: exactly one completed `prepare-strict-authorization` job, exactly one `strict-chain` job in progress, and all other jobs skipped.
    - Environment configuration and repository branch rules: `can_admins_bypass: false`, reviewer account 43164, deletion / non-fast-forward / update rules active.
    - Source comparisons: PR 147 open at P; compare P...W matches 34 added files under `proof/` with digest `0f4a92668eeba752d74a3d4deab401d6ca023d69ab3e013d92d943bad84fed3c`; compare W...H matches the remote harness audit files.
    - Supervisor bundle digest matching regular files under `dist/`.
    - Preserved harness evidence at commit `83ffe98b` with status PASS.
    - Prior push validation run V: completed, success, attempt 1, 62 artifacts, valid summary and rehearsal reports.
    - Audit evidence commit E: blob IDs, hashes, and canonical `audit.json` with GO verdict.
    - Manifest artifact: single member `manifest.json`, digest matches D.
    - Approval record: exactly one approval by account 43164 with comment `iyi-strict-authorization-v2 sha256:<D>`.
  - If any check fails, `authorize` exits with code 5, and the strict job stops immediately before any compiler build or native execution.
  - Platform limits:
    - GitHub records that account 43164 approved environment 26584191206 on run S attempt 1 with the specified comment; GitHub API does not record who operated the account or which credential was used.
    - Reviewer independence and audit soundness are attested by the human approver based on the review record; the platform does not authenticate reviewer agent identity or model provenance.
    - Steps on a hosted runner share the runner process environment; the gate runs before P checkout and build, and subsequent steps check bundle and tree integrity.

## Hosted validation

Run the `Remote Strict Proof Chain (macOS 15)` workflow at the exact C, using `validation-only`. The hosted job installs the locked Node dependencies, rebuilds the tracked bundle and rejects drift, runs action pin checks against git ls-remote, validates workflow structure, executes the action suite and Python test suites, and exercises five synthetic transaction invocations, four controller refusal controls, and three controller-crash recovery invocations. No P1 compiler is built and no native corpus stage is launched.

The hosted commands for the executable checks are:

```sh
npm --prefix .github/actions/strict-supervisor ci
npm --prefix .github/actions/strict-supervisor run build
git diff --exit-code -- .github/actions/strict-supervisor/dist
npm --prefix .github/actions/strict-supervisor test
python3 -B proof/check_action_pins.py --out "$RUNNER_TEMP/strict-ci/reports/pins-report.json"
python3 -B proof/check_strict_workflow.py --out "$RUNNER_TEMP/strict-ci/reports/structure-report.json"
PYTHONFAULTHANDLER=1 timeout 600s python3 -B -X faulthandler \
  -m unittest discover -s proof -p 'test_remote_strict*.py' -v
python3 -B -m unittest proof.test_strict_authorization proof.test_check_action_pins proof.test_check_strict_workflow -v
```

The success case requires 37 checkpoints: plan, pin, Run1, Run2, 31 synthetic drivers, final, and terminal. The four separate failure cases must return nonzero: failed plan (1 checkpoint), failed pin (2), Run3 divergence (6), and Run1 cleanup failure (4). The three ownership jobs are `ownership-crash`, `ownership-census-outage`, and `ownership-run1-outage`. Each uploads one ownership evidence tar. Crash uploads no checkpoint artifacts; census outage persists one failed plan snapshot; run1 outage persists plan, pin, an unresolved run1 snapshot, and a terminal failure envelope. Persistence of a failure snapshot does not accept the stage.

The four refusal controls verify that `remote_strict_controller --mode strict` exits with code 5, writes summary status `AUTH_REFUSED`, and launches zero stage records when invoked with:
  1. Missing manifest fd (`missing_manifest_fd`)
  2. Manifest digest mismatch on fd 5 (`manifest_digest_mismatch`)
  3. Strict run ID mismatch (`strict_run_id_mismatch`)
  4. Invalid P commit SHA (`invalid_p_sha`)

After synthetic and refusal execution, the workflow verifies the 50 checkpoint artifacts and uploads `remote-strict-validation-evidence`. It generates `rail-validation-summary` and uploads it. The `authorization-rehearsal` job runs `rehearse` and uploads `rail-rehearsal-report`. The `ownership-inventory` job verifies the complete hosted evidence inventory of 62 artifacts.

## Interpretation and recovery

Synthetic success establishes only the exercised controller, ownership, checkpoint count, and readback behavior at that C. It does not establish native-sized transfer performance, post-build disk headroom, oracle availability, or native completion. Feasibility requires separate hosted measurements. Native completion requires every required driver and a verified terminal envelope after the final checkpoint. Do not shorten the required inventory to fit a budget.

If persistence, ownership, a seal, or a readback fails, preserve the recorded receipts and failure state; do not advance or clean up the affected work. A census failure, ambiguous process identity, observer outage, or ancestry gap is unresolved ownership, not evidence that processes are gone. On Darwin the observer reads each identity with one `kern.proc.pid` call and reads the census with one `kern.proc.all` reply, where every row carries pid, ppid, state and a microsecond birth from one process record. A census that fails its self-check (duplicate PID, missing PID 1 or helper row, own ppid or birth mismatch) is an observer failure, and there is no fallback to `ps`. An unowned child is adopted only when its parent has a row in the same reply with the commit timestamp.

An unresolved or incomplete host ownership ledger blocks another strict-proof controller on that host, even if the invocation, attempt, chain, or artifact directory changes. Retain its active record and recovery evidence. Use a fresh isolated hosted runner for a retry; a later successful census does not clear the observation gap.

Recovery may reclaim previously committed process identities while the ownership proof remains unresolved. Each signal requires a fresh birth-identity check. A separate probe and signal are not atomic, and polling cannot guarantee complete containment. Native strict recovery retains the configured 30-second TERM grace. If the supervisor or runner dies, its retained active ledger blocks reuse; the dead supervisor cannot perform recovery. `proof_resolved: true` means every process the observer listed in the tree was identified, tied to its parent by the same read, and reclaimed or seen exited. It does not mean nothing escaped. A process no census lists, a process first listed already exited, and either one's orphans are not taints; they are documented limits.
