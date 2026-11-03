# Remote strict proof operator path

## Identity and authorization

The product revision is `626463375298d357ffcb3223059f4d3adce6fb10` (P1), and the audited native proof revision is `b932ce0d97775c7061102a13db706f507dc84117` (W). C is the exact controller commit running the hosted workflow, not a label substituted for its checkout. The workflow checks out P1 and W separately and checks their actual revisions. Synthetic emitters, compilers, reports, and logs live outside those source trees.

Strict dispatch is refused before a build or native stage. Jason selected a protected GitHub environment with himself as reviewer and self-approval permitted; the manifest-bound approval verifier is a separate integration and is not yet in this workflow. A green synthetic run is not authorization. Strict execution requires an authenticated GO bound to the repository, P/W/C, validation workflow, run and attempt, validation evidence digest, and independent audit digest. Any C change requires a new validation and independent review for that C.

## Hosted validation

Run the `Remote Strict Proof Chain (macOS 15)` workflow at the exact C, using `validation-only`. The hosted job installs the locked Node dependencies, rebuilds the tracked bundle and rejects drift, runs the action suite and full remote-strict Python test discovery, and then loads the committed action for five synthetic invocations. No P1 compiler is built and no native corpus stage is launched.

The hosted commands for the executable checks are:

```sh
npm --prefix .github/actions/strict-supervisor ci
npm --prefix .github/actions/strict-supervisor run build
git diff --exit-code -- .github/actions/strict-supervisor/dist
npm --prefix .github/actions/strict-supervisor test
PYTHONFAULTHANDLER=1 timeout 600s python3 -B -X faulthandler \
  -m unittest discover -s proof -p 'test_remote_strict*.py' -v
```

The success case requires 37 checkpoints: plan, pin, Run1, Run2, 31 synthetic drivers, final, and terminal. The four separate failure cases must return nonzero: failed plan (1 checkpoint), failed pin (2), Run3 divergence (6), and Run1 cleanup failure (4). The workflow checks their original action outcomes, downloads the 50 checkpoint artifacts by exact ID, and runs the independent evidence checker on their inner tar payloads. It then exports one sealed tar containing only the five checked reports and requires an exact inventory of 51 artifact IDs. An interrupted or incomplete job is not a pass.

During the job, the checker receives the actual P, W, C and synthetic compiler paths, platform job identity, and per-invocation receipt index. It downloads each artifact as `DIR/<artifact_id>.tar`; the divergence case compares bytes with a separately generated fixture outside the source trees. The sealed reports retain the checked bindings, IDs, hashes, sizes, member names, and divergence hashes, not the ephemeral index or fixture file. A later reviewer can download the artifacts by ID and independently check their contents against those retained hashes. The action's ACK alone is not an independent expected-value oracle.

## Interpretation and recovery

Synthetic success establishes only the exercised controller, ownership, checkpoint count, and readback behavior at that C. It does not establish native-sized transfer performance, post-build disk headroom, oracle availability, or native completion. Feasibility requires separate hosted measurements. Native completion requires every required driver and a verified terminal envelope after the final checkpoint. Do not shorten the required inventory to fit a budget.

If persistence, ownership, a seal, or a readback fails, preserve the recorded receipts and failure state; do not advance or clean up the affected work. A census failure, ambiguous process identity, observer outage, or ancestry gap is unresolved ownership, not evidence that processes are gone. The observer continues from identified reparented processes, but polling cannot establish the absence of entirely unobserved fast fork/reparent activity. Never kill by guessed PID or process name, and never retry in place while ownership remains unresolved.
