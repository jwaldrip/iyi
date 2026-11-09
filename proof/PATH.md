# Remote strict proof operator path

## Identity and authorization

The product revision is `e4e7e5ed543690cafad11d0b5c1452a710b26d54` (upstream PR #147 head on `iyilang/iyi`), and the audited native proof revision is `b932ce0d97775c7061102a13db706f507dc84117` (W). Upstream PR147 already merged that exact W at commit `e4e7e5ed543690cafad11d0b5c1452a710b26d54`. C is the exact reviewed controller commit running the hosted workflow and local launcher, not a label substituted for its checkout.

Trust anchors are strictly separated:
- The upstream product pull request repository is `iyilang/iyi` (PR #147).
- The approval, evidence, and workflow repository is `jwaldrip/iyi` (ID `1340355933`).

Strict dispatch is gated behind a two-job hosted preparation/approval workflow and executed on the selected quiet local Mac. Jason has explicitly selected the audit authority policy:
  - An independent reviewer agent that did not implement the change generates the audit report and supporting receipts as immutable digest-bound evidence E with verdict GO.
  - Jason's manual deployment approval on GitHub protected environment `strict-proof` (ID `26584191206`, required reviewer `jwaldrip` ID `43164`, `can_admins_bypass: false`, `prevent_self_review: false`, branch policy `proof/strict-lifecycle-repair-20261102`) explicitly attests to the exact manifest digest prefix `iyi-strict-authorization-v2 sha256:<D>` on attempt 1.
  - Semantic independence (the review method, evidence, findings, and negative controls verified by an independent reviewer agent) is distinguished from cryptographic human approval (GitHub protected environment approval).
  - No machine-enforced agent signature or model provenance is claimed or trusted from self-attested data; platform authenticity resides solely in Jason's authenticated approval of the manifest digest, which cryptographically binds all evidence.
  - In real execution, without this authenticated deployment approval on environment `strict-proof` and retained independent audit GO artifact, strict mode execution remains strictly and unconditionally refused across all execution layers (workflow step, Node supervisor, and Python controller) with exit code 5.

## Hosted preparation and gate workflow

The hosted workflow `Remote Strict Proof Chain (macOS 15)` (`.github/workflows/remote-strict-proof.yml`) implements a two-job approval run for `strict-chain` mode:

```text
prepare-strict-authorization
    |
    v
strict-chain
environment: strict-proof
```

1. `prepare-strict-authorization`:
   - Triggered via `workflow_dispatch` with inputs: `mode: strict-chain`, `v_run_id`, `v_artifacts`, `review_path`, `review_sha256`, `review_verdict`.
   - Validates the real qualifying validation run V (`v_run_id` and `v_artifacts`) and independent review E (`review_path`, `review_sha256`, `review_verdict == "GO"`) BEFORE generating or uploading the manifest.
   - Authenticates V run status via GitHub API (`status == "completed"`, `conclusion == "success"`, attempt 1 jobs all successful, non-empty unexpired artifacts).
   - Verifies that independent review file E exists in the repository, has verdict "GO", and matches its SHA-256 digest.
   - Fail-closed gate: If any validation or review check fails, preparation fails immediately with nonzero exit code. Because `strict-chain` depends on `prepare-strict-authorization` (`needs: prepare-strict-authorization`), the downstream protected job `strict-chain` is skipped and its environment `strict-proof` deployment gate NEVER opens before validation and reviewed E are verified.
   - Invokes `proof/strict_authorization.py prepare` to generate the canonical manifest `manifest.json`.
   - Computes manifest digest `D = sha256(canonical_manifest_bytes)` from the exact `manifest.json` bytes.
   - Uploads only `manifest.json` as the immutable manifest artifact `strict-proof-manifest-<run_id>-<run_attempt>`.
   - Exposes exact numeric `artifact_id` and manifest digest `D` via authenticated job outputs.

2. `strict-chain`:
   - Protected by GitHub environment `strict-proof` (ID `26584191206`).
   - GitHub holds the job in pending deployment until Jason personally reviews the deployment and submits the exact comment:
     `iyi-strict-authorization-v2 sha256:<D>` on attempt 1.
   - On release, downloads the exact manifest package artifact by ID via GitHub REST API (token-free redirect following via `proof/github_artifact.py`).
   - Verifies outer archive integrity, rejects directories and duplicate members, asserts that the archive contains exactly one file `manifest.json`, and verifies that its member SHA-256 matches D.
   - Invokes `proof/strict_authorization.py check` to authenticate deployment approval, reviewer ID `43164`, environment ID `26584191206`, attempt 1, matching C/P/W revisions, passing V run, and independent review GO against GitHub's authoritative API.
   - Publishes the diagnostic authorization receipt artifact `strict-authorization-receipt-<run_id>-<run_attempt>` and finishes.
   - Authority boundary: The receipt’s `AUTHORIZED` label grants nothing to the local launcher. Local execution re-reads GitHub authoritative data directly.
   - No P build or native stage is launched hosted; the backend is explicitly `local-quiet-darwin`.

## Local quiet backend execution

Native strict proof runs locally on the selected quiet Mac using the checked launcher:

```sh
python3 -B "$C_DIR/proof/strict_authorization.py" run-native \
  --manifest "$MANIFEST_PATH" \
  --p "$P_DIR" \
  --w "$W_DIR" \
  --compiler "$BIN" \
  --report-dir "$R"
```

The checked launcher:
1. Independently reads and verifies the actual GitHub run, job, deployment, and approval records using the shared verifier. It does not trust the hosted receipt's PASS label.
2. Creates an exclusive, durable host-local claim `(s_run_id, D)` with atomic creation and fsync in private application state to prevent double-spending the approval on duplicate chains.
3. Enforces fail-closed exit code 5 before any native stage if authorization is missing, invalid, or replayed.
4. Delegates execution to the Node supervisor (local backend) to enforce lifecycle safeguards:
   - Process ownership registration via Darwin kernel observer before releasing subprocess gates.
   - Interrupted-process tracking, kernel birth verification, and quarantine.
   - Per-stage sealing and Git checkpoint persistence to the checkpoint store with remote readback verification.
   - Preservation-before-cleanup boundaries.
5. Routes through controller native preflight to W's native CLI (`plan`, `pin`, `run1`, `run2`, `run3`, `final`), requiring 142 evaluated, 142 passed, zero excluded across RG2 and RG2a.

Current status: The interface is wired fail-closed and ready for live execution once qualifying V validation and reviewed E evidence are supplied and Jason's approval is entered on GitHub. No live approval has been executed, no native proof has been launched, and the PR147 proof is not claimed verified.

## Hosted validation

Run the `Remote Strict Proof Chain (macOS 15)` workflow at the exact C, using `validation-only`. The hosted job installs the locked Node dependencies, rebuilds the tracked bundle and rejects drift, runs the action suite and full remote-strict Python test discovery, and then loads the committed action for five synthetic transaction invocations and a controller-crash recovery invocation. No P1 compiler is built and no native corpus stage is launched.

The hosted commands for the executable checks are:

```sh
npm --prefix .github/actions/strict-supervisor ci
npm --prefix .github/actions/strict-supervisor run build
git diff --exit-code -- .github/actions/strict-supervisor/dist
npm --prefix .github/actions/strict-supervisor test
PYTHONFAULTHANDLER=1 timeout 600s python3 -B -X faulthandler \
  -m unittest discover -s proof -p 'test_remote_strict*.py' -v
```

The success case requires 37 checkpoints: plan, pin, Run1, Run2, 31 synthetic drivers, final, and terminal. The four separate failure cases must return nonzero: failed plan (1 checkpoint), failed pin (2), Run3 divergence (6), and Run1 cleanup failure (4). The three ownership jobs are `ownership-crash`, `ownership-census-outage`, and `ownership-run1-outage`. Each uploads one ownership evidence tar. Crash uploads no checkpoint artifacts; census outage persists one failed plan snapshot; run1 outage persists plan, pin, an unresolved run1 snapshot, and a terminal failure envelope. Persistence of a failure snapshot does not accept the stage. The workflow checks original action outcomes, downloads the 50 checkpoint artifacts of the five synthetic cases by exact ID, and runs the independent evidence checker on their inner tar payloads and ownership recovery. The validation job requires exactly 52 artifact IDs: those 50 checkpoints, the supervisor bundle, and the sealed export. The inventory job requires 60 artifacts: those 52, three ownership evidence tars, and five ownership outage snapshots. An interrupted or incomplete job is not a pass.

During the job, the checker receives the actual P, W, C and synthetic compiler paths, platform job identity, and per-invocation receipt index. It downloads each artifact as `DIR/<artifact_id>.tar`; the divergence case compares bytes with a separately generated fixture outside the source trees. The sealed reports retain the checked bindings, IDs, hashes, sizes, member names, and divergence hashes, not the ephemeral index or fixture file. A later reviewer can download the artifacts by ID and independently check their contents against those retained hashes. The action's ACK alone is not an independent expected-value oracle.

## Interpretation and recovery

Synthetic success establishes only the exercised controller, ownership, checkpoint count, and readback behavior at that C. It does not establish native-sized transfer performance, post-build disk headroom, oracle availability, or native completion. Feasibility requires separate hosted measurements. Native completion requires every required driver and a verified terminal envelope after the final checkpoint. Do not shorten the required inventory to fit a budget.

If persistence, ownership, a seal, or a readback fails, preserve the recorded receipts and failure state; do not advance or clean up the affected work. A census failure, ambiguous process identity, observer outage, or ancestry gap is unresolved ownership, not evidence that processes are gone. On Darwin the observer reads each identity with one `kern.proc.pid` call and reads the census with one `kern.proc.all` reply, where every row carries pid, ppid, state and a microsecond birth from one process record. A census that fails its self-check (duplicate PID, missing PID 1 or helper row, own ppid or birth mismatch) is an observer failure, and there is no fallback to `ps`. An unowned child is adopted only when its parent has a row in the same reply with the committed birth, the child is born after that parent, and either the child's row precedes the parent's or the child was born before the call started. Otherwise the observer records `ambiguous ancestry` and skips the child. A zombie row first seen is never adopted. Polling still cannot establish the absence of a process born and reaped between two censuses, or of anything it orphaned, and that gap is not claimed. Never kill by guessed PID or process name, and never retry in place while ownership remains unresolved.

An unresolved or incomplete host ownership ledger blocks another strict-proof controller on that host, even if the invocation, attempt, chain, or artifact directory changes. Retain its active record and recovery evidence. Use a fresh isolated hosted runner for a retry; a later successful census does not clear the observation gap.

Recovery may reclaim previously committed process identities while the ownership proof remains unresolved. Each signal requires a fresh birth-identity check. A separate probe and signal are not atomic, and polling cannot guarantee complete containment. Native strict recovery retains the configured 30-second TERM grace. If the supervisor or runner dies, its retained active ledger blocks reuse; the dead supervisor cannot perform recovery. `proof_resolved: true` means every process the observer listed in the tree was identified, tied to its parent by the same read, and reclaimed or seen exited. It does not mean nothing escaped. A process no census lists, a process first listed already exited, and either one's orphans are not taints; they are documented limits.
