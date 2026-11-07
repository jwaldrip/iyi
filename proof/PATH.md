# Remote strict proof operator path

## Identity and authorization

The product revision is `180f14f91c829b25362a5ed34b20847f3ac2db77` (PR #147 head), and the audited native proof revision is `b932ce0d97775c7061102a13db706f507dc84117` (W). C is the exact controller commit running the hosted workflow, not a label substituted for its checkout. The workflow checks out P and W separately and checks their actual revisions. Synthetic emitters, compilers, reports, and logs live outside those source trees.

Strict dispatch is unconditionally refused before planning, pinning, building, or native execution. Jason has explicitly selected the audit authority policy:
  - An independent reviewer agent that did not implement the change generates the audit report and supporting receipts as immutable digest-bound evidence.
  - Jason's manual deployment approval on GitHub protected environment `strict-proof` (ID `26584191206`, required reviewer `jwaldrip` ID `43164`, `can_admins_bypass: false`, `prevent_self_review: false`, branch policy `proof/strict-lifecycle-repair-20261102`) explicitly attests to the exact manifest digest prefix `iyi-strict-authorization-v1 sha256:<digest>` on attempt 1.
  - Semantic independence (the review method, evidence, findings, and negative controls verified by an independent reviewer agent) is distinguished from cryptographic human approval (GitHub protected environment approval).
  - No machine-enforced agent signature or model provenance is claimed or trusted from self-attested data; the platform authenticity resides solely in Jason's authenticated approval of the manifest digest, which cryptographically binds all evidence.
  - In real execution, without this authenticated deployment approval on environment `strict-proof` and retained independent audit GO artifact, strict mode execution remains strictly and unconditionally refused across all execution layers (workflow step, Node supervisor, and Python controller) with exit code 5.

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
