#ifndef E3_SUPERVISOR_TRACE_H
#define E3_SUPERVISOR_TRACE_H

#include <stdint.h>
#include <sys/types.h>

/* Experimental kernel primitives. They do not authorize hostile execution:
 * clone escape, same-UID protection, byte stability and source attribution
 * remain unqualified. Only the C-owned child and ptrace-reported descendants
 * enter this table. No API accepts an arbitrary caller-supplied PID.
 */
#define E3_TRACE_MAX 128U

enum e3_trace_state { E3_UNUSED, E3_RUNNING, E3_STOPPED, E3_EXITED };
struct e3_trace_task {
  pid_t pid;
  enum e3_trace_state state;
  int status;
};
struct e3_trace {
  struct e3_trace_task tasks[E3_TRACE_MAX];
  unsigned count, budget;
  int barrier_fd;
  int poisoned;
};

/* Creates only a trusted stub, never a payload. The child closes all inherited
 * descriptors except its private launch barrier before blocking.  All calls
 * must originate on the same supervisor thread. Timeout is in milliseconds.
 * On failure, the caller must still invoke e3_trace_teardown on the returned
 * object; a failure to reap is itself a hard failure of the enclosing attempt.
 */
int e3_trace_start(struct e3_trace *trace, unsigned task_budget,
                   unsigned timeout_ms);
/* Polls owned tasks only. Returns 1 with index of the stopped/exited task,
 * 0 if none became ready by the deadline, -1 on failure. The caller holds a
 * stop until it explicitly resumes the matching index.
 */
int e3_trace_poll(struct e3_trace *trace, unsigned timeout_ms, unsigned *index);
/* Resume a known stopped task in syscall-stop mode; never injects a signal. */
int e3_trace_resume(struct e3_trace *trace, unsigned index);
/* Open /proc/<owned-task>/exe only at its synchronous exec event stop.
 * The descriptor is not a substitute for writer exclusion or a BPF join. */
int e3_trace_open_exec(struct e3_trace *trace, unsigned index);
struct e3_syscall_stop {
  uint8_t operation; /* 1 entry, 2 exit */
  uint32_t arch;
  uint64_t instruction_pointer, stack_pointer;
  uint64_t number, args[6];
  int64_t result;
  uint8_t is_error;
};
/* Kernel syscall-stop information, never source-callsite attribution.
 * Pointer arguments and shared memory remain untrusted and mutable. */
int e3_trace_syscall_info(struct e3_trace *trace, unsigned index,
                          struct e3_syscall_stop *out);
/* Releases the trusted stub to exit. It does not execute any command. */
int e3_trace_release_stub(struct e3_trace *trace);
/* Interrupt/terminate only tasks in the owned table, and reap by deadline.
 * Returns failure if any task cannot be proven reaped. No success receipt.
 */
int e3_trace_teardown(struct e3_trace *trace, unsigned timeout_ms);

#endif
