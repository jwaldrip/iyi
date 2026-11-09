# Controller-held Linux F_RDLCK Inode Read Lease Feasibility Diagnostic

## 1. Scope and Authority

This diagnostic qualifies controller-held Linux `F_RDLCK` read leases as a fail-closed inode custody mechanism on synthetic owned fixtures under ephemeral GitHub-hosted Ubuntu (`ubuntu-24.04`).

This is a **non-strict feasibility diagnostic only**:
- Schema: `iyi-kernel-feasibility-v1`
- Unconditionally:
  * `strict_eligible: false`
  * `cage_qualified: false`
  * `exec_identity_tested: false`
  * `native_fd_launch_tested: true`
- This diagnostic never produces `GO`, `QUALIFIED`, or strict-proof receipts.
- Passing synthetic controls does not authorize strict execution and does not replace the requirement for independent security review and exact-digest approval.

## 2. Background and Mechanism

Hosted Linux runs on the default GitHub Actions runner image demonstrated that `/dev/root` is formatted without the ext4 `verity` superblock feature flag, returning `EOPNOTSUPP` upon `FS_IOC_ENABLE_VERITY`. Root filesystem tuning (`tune2fs -O verity`), unverified loopback devices, and local VMs are prohibited under repository safety policy.

Linux file leases (`fcntl(fd, F_SETLEASE, F_RDLCK)`) provide a kernel-enforced, fail-closed custody alternative:
- **Acquisition Check**: `F_SETLEASE(F_RDLCK)` checks for active open writers (`inode_is_open_for_write`) and shared writable memory mappings (`mapping_writably_mapped`), rejecting acquisition with `EAGAIN`/`EWOULDBLOCK` if any write reference exists.
- **Revocable Custody**: Once acquired, any subsequent conflicting write-open (`O_WRONLY`, `O_RDWR`, `O_TRUNC`) or pathname truncation initiates a kernel lease break, transitioning `F_GETLEASE` away from `F_RDLCK` to `F_UNLCK`.
- **Fail-Closed Policy**: A transaction is accepted only if its read lease remained unbroken (`F_GETLEASE == F_RDLCK`) on the same held open file description from capture through final collection. Any break notification permanently taints custody.

## 3. Actor Model, Confinement, and IPC Architecture

All actors execute as direct children of the single-threaded unprivileged controller P under the same ordinary nonroot UID:
- **P (Controller)**: Owns evidence/report descriptors and IPC channels; manages child lifecycles via `pidfd`s; never holds a custody lease descriptor.
- **H (Holder)**: Owns the read-only open file description, acquires `F_RDLCK`, configures real-time lease break signals via `signalfd`, streams verified bytes, and latches `TAINTED` on any break.
- **A (Requester)**: Executes conflicting nonblocking opens, blocking truncations, or raw libc `mmap` controls. Never receives H's descriptors.
- **E (Executor)**: Launches a separately opened executable descriptor via `execveat(fd, "", ..., AT_EMPTY_PATH)`.
- **S (Sentinel)**: Verifies that an unrelated owned sentinel fixture remains byte-identical throughout.

### Process & Descriptor Confinement
- Every child actor starts under a private startup barrier pipe, sets `PR_SET_PDEATHSIG(SIGKILL)`, and closes all file descriptors $\ge 3$ except its own socket and explicitly allowed descriptors.
- P obtains the child's `pidfd` via `pidfd_open` before releasing the barrier.
- Inter-process signaling uses `pidfd_send_signal(pidfd, sig, NULL, 0)` exclusively. No process groups or numeric PID signaling.
- Child reaping uses `waitid(P_PIDFD, pidfd, &siginfo, WEXITED)`.
- IPC uses private `AF_UNIX` `SOCK_SEQPACKET` socket pairs per actor with discrete, bounded frames (max 4096 bytes).

### Real-Time Signal Handling
- H blocks `SIGIO` and `SIGRTMIN+1` via `pthread_sigmask`.
- H creates a dedicated non-blocking `signalfd4` for the signal mask.
- H configures `F_SETSIG` to `SIGRTMIN+1` and `F_SETOWN_EX` to its own thread ID (`F_OWNER_TID`).
- Any lease break signal from the kernel is decoded from the 128-byte `signalfd_siginfo` structure, triggering immediate `TAINTED` custody transition.

## 4. The 14 Mandatory Observable Controls

Every qualification run must observe and report all 14 mandatory controls with concrete observed measurements:

1. `genuine_lifecycle`: Single acquisition of `F_RDLCK` on the original owned ELF inode, hardlink creation to `out.ref` (same dev/ino, link count $\ge 2$), atime lowering preserving mtime, native binary execution via E, post-launch metadata sampling, original alias unlinking, and byte capture under the unbroken lease.
2. `existing_writer`: Conflicting open writable FD in independent actor A blocks `F_SETLEASE(F_RDLCK)` in H with exact `EAGAIN`/`EWOULDBLOCK`; paired positive acquisition succeeds after A closes.
3. `fd_closed_shared_mmap`: Raw libc `MAP_SHARED|PROT_WRITE` mapping with closed FD in independent actor A blocks `F_SETLEASE(F_RDLCK)` with `EAGAIN`/`EWOULDBLOCK`; paired positive acquisition succeeds after `munmap`.
4. `nonblocking_break`: Conflicting `O_WRONLY|O_NONBLOCK` open in A fails with `EAGAIN`/`EWOULDBLOCK` and transitions H lease state to `F_UNLCK` via break signal.
5. `forced_blocking_open_and_restore`: Pathname mutation initiates lease break; subsequent byte restoration still fails custody validation (`F_GETLEASE == F_UNLCK`).
6. `pathname_truncate_forced`: Pathname truncation initiates lease break on held descriptor in H.
7. `cancelled_requester_sticky`: Requester cancellation via `pidfd_send_signal(SIGTERM)` leaves lease state as `F_UNLCK`, preventing restoration of valid custody despite unchanged bytes.
8. `read_utime_without_exec`: Reads and timestamp modifications without native execution fail the native execution obligation.
9. `failed_native_exec`: Execution of an invalid ELF fixture via `execveat` fails with exact `ENOEXEC` and fails closed.
10. `same_bytes_different_inode_launch`: Executing a different inode with identical bytes is rejected by the descriptor-to-inode custody binding.
11. `reference_substitution`: Substituting `out.ref` with a different inode fails custody validation.
12. `holder_death`: Termination of secondary H via `pidfd_send_signal(SIGKILL)` releases lease and permanently rejects custody, while genuine H and S remain unaffected.
13. `racing_open_acquire`: Concurrent open and lease acquisition resolves without an accepted overlapping writer.
14. `owned_sentinel_untouched`: Sentinel fixture remains byte-identical throughout execution.

## 5. Total Acceptance Predicate

Acceptance requires:
- All 14 control records present with status `PASS`.
- Genuine lifecycle custody state is `CAPTURED`.
- Sentinel fixture bytes confirmed identical.
- Zero extra, missing, or malformed control records.
- Diagnostic artifacts and retained fixture (`out.ref`) preserved in the exact upload directory.
- All child actors cleanly reaped via their owned `pidfd`s.
