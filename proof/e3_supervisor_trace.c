#define _GNU_SOURCE
#include "e3_supervisor_trace.h"
#include <errno.h>
#include <stdlib.h>

#ifdef __linux__
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int bad(struct e3_trace *t, int error) {
  if (t)
    t->poisoned = 1;
  errno = error;
  return -1;
}
static int deadline(unsigned ms, struct timespec *end) {
  if (!ms || ms > 60000 || clock_gettime(CLOCK_MONOTONIC, end))
    return -1;
  end->tv_sec += ms / 1000;
  end->tv_nsec += (long)(ms % 1000) * 1000000L;
  if (end->tv_nsec >= 1000000000L) {
    end->tv_nsec -= 1000000000L;
    end->tv_sec++;
  }
  return 0;
}
static int expired(const struct timespec *end) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now))
    return -1;
  return now.tv_sec > end->tv_sec ||
         (now.tv_sec == end->tv_sec && now.tv_nsec >= end->tv_nsec);
}
static int known(const struct e3_trace *t, pid_t pid) {
  for (unsigned i = 0; i < t->count; i++)
    if (t->tasks[i].pid == pid && t->tasks[i].state != E3_EXITED)
      return 1;
  return 0;
}
static void stub(int read_fd) {
  /* This stub contains no payload path or arguments and cannot exec. */
  if (read_fd != 3 && dup3(read_fd, 3, O_CLOEXEC) < 0)
    _exit(127);
  if (read_fd == 3 && fcntl(3, F_SETFD, FD_CLOEXEC) < 0)
    _exit(127);
  if (syscall(SYS_close_range, 4U, ~0U, 0U) < 0)
    _exit(127);
  close(0);
  close(1);
  close(2);
  char byte;
  /* EOF releases the stub to exit, never to run hostile instructions. */
  (void)read(3, &byte, 1);
  _exit(0);
}
static long options(void) {
  return PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
         PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD |
         PTRACE_O_EXITKILL;
}
int e3_trace_start(struct e3_trace *t, unsigned budget, unsigned timeout) {
  int p[2];
  struct timespec end;
  if (!t) {
    errno = EINVAL;
    return -1;
  }
  memset(t, 0, sizeof(*t));
  t->barrier_fd = -1;
  if (!budget || budget >= E3_TRACE_MAX || deadline(timeout, &end))
    return bad(t, EINVAL);
  t->budget = budget;
  if (pipe2(p, O_CLOEXEC))
    return bad(t, errno);
  pid_t pid = fork();
  if (pid < 0) {
    int e = errno;
    close(p[0]);
    close(p[1]);
    return bad(t, e);
  }
  if (!pid)
    stub(p[0]);
  close(p[0]);
  t->barrier_fd = p[1];
  t->tasks[0].pid = pid;
  t->tasks[0].state = E3_RUNNING;
  t->count = 1;
  /* Failure leaves the child in the owned table for bounded teardown. */
  if (ptrace(PTRACE_SEIZE, pid, 0, options()))
    return bad(t, errno);
  t->tasks[0].traced = 1;
  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0))
    return bad(t, errno);
  for (;;) {
    int status;
    pid_t got = waitpid(pid, &status, __WALL | WNOHANG);
    if (got == pid) {
      t->tasks[0].status = status;
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        t->tasks[0].state = E3_EXITED;
        return bad(t, EPROTO);
      }
      if (WIFSTOPPED(status))
        t->tasks[0].state = E3_STOPPED;
      if (!WIFSTOPPED(status) || ((unsigned)status >> 16) != PTRACE_EVENT_STOP)
        return bad(t, EPROTO);
      return 0;
    }
    if (got < 0 && errno != EINTR)
      return bad(t, errno);
    int done = expired(&end);
    if (done != 0)
      return bad(t, done < 0 ? errno : ETIMEDOUT);
    struct timespec pause = {.tv_nsec = 1000000L};
    (void)nanosleep(&pause, 0);
  }
}
static int capture(struct e3_trace *t, unsigned i, int status, int strict) {
  struct e3_trace_task *task = &t->tasks[i];
  task->status = status;
  if (WIFEXITED(status) || WIFSIGNALED(status)) {
    task->state = E3_EXITED;
    return 0;
  }
  if (!WIFSTOPPED(status))
    return bad(t, EPROTO);
  task->state = E3_STOPPED;
  unsigned event = (unsigned)status >> 16;
  if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
      event == PTRACE_EVENT_CLONE) {
    unsigned long child = 0;
    if (ptrace(PTRACE_GETEVENTMSG, task->pid, 0, &child) || !child ||
        (pid_t)child <= 0 || (unsigned long)(pid_t)child != child ||
        known(t, (pid_t)child) || t->count >= E3_TRACE_MAX)
      return bad(t, EPROTO);
    /* One reserved overflow slot permits teardown even when the configured
     * task budget is exceeded. No additional task may be resumed then. */
    t->tasks[t->count].pid = (pid_t)child;
    t->tasks[t->count].state = E3_RUNNING;
    t->tasks[t->count].traced = 1;
    t->count++;
    if (strict && t->count > t->budget)
      return bad(t, EOVERFLOW);
  } else if (event == PTRACE_EVENT_EXEC) {
    unsigned long former = 0;
    if (ptrace(PTRACE_GETEVENTMSG, task->pid, 0, &former) ||
        (former && former != (unsigned long)task->pid))
      return bad(t, ENOTSUP);
  } else if (strict && event == PTRACE_EVENT_STOP &&
             WSTOPSIG(status) != SIGTRAP) {
    /* Do not suppress or reinterpret a job-control/group stop. */
    return bad(t, ENOTSUP);
  } else if (strict && event != PTRACE_EVENT_EXIT &&
             event != PTRACE_EVENT_STOP &&
             !(event == 0 && WSTOPSIG(status) == (SIGTRAP | 0x80))) {
    /* Signal delivery and group-stop forwarding are not yet qualified. */
    return bad(t, ENOTSUP);
  }
  return 0;
}
static int collect(struct e3_trace *t, const struct timespec *end,
                   unsigned *index, int strict) {
  for (;;) {
    for (unsigned i = 0; i < t->count; i++) {
      if (t->tasks[i].state != E3_RUNNING)
        continue;
      int status;
      pid_t got = waitpid(t->tasks[i].pid, &status, __WALL | WNOHANG);
      if (got == t->tasks[i].pid) {
        int r = capture(t, i, status, strict);
        *index = i;
        return r ? -1 : 1;
      }
      if (got < 0 && errno != EINTR)
        return bad(t, errno);
    }
    int done = expired(end);
    if (done < 0)
      return bad(t, errno);
    if (done)
      return 0;
    struct timespec pause = {.tv_nsec = 1000000L};
    (void)nanosleep(&pause, 0);
  }
}
int e3_trace_poll(struct e3_trace *t, unsigned timeout, unsigned *index) {
  struct timespec end;
  if (!t || !index || t->poisoned || deadline(timeout, &end))
    return bad(t, EINVAL);
  return collect(t, &end, index, 1);
}
int e3_trace_resume(struct e3_trace *t, unsigned i) {
  if (!t || t->poisoned || i >= t->count || t->tasks[i].state != E3_STOPPED)
    return bad(t, EINVAL);
  /* Until pointer-safe clone3 mediation and thread lifecycle are qualified,
   * reject every clone/clone3 entry before execution, including CLONE_UNTRACED.
   * x32 and other architectures are refused rather than misclassified. */
  int status = t->tasks[i].status;
  if (((unsigned)status >> 16) == 0 && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
    struct e3_syscall_stop info;
    if (e3_trace_syscall_info(t, i, &info))
      return -1;
    if (info.arch != UINT32_C(0xc000003e))
      return bad(t, ENOTSUP);
    if (info.operation == 1 &&
        (info.number >= UINT64_C(0x40000000) || info.number == UINT64_C(56) ||
         info.number == UINT64_C(435)))
      return bad(t, ENOTSUP);
  }
  if (ptrace(PTRACE_SYSCALL, t->tasks[i].pid, 0, 0))
    return bad(t, errno);
  t->tasks[i].state = E3_RUNNING;
  return 0;
}
int e3_trace_open_exec(struct e3_trace *t, unsigned i) {
  struct stat st;
  char path[64];
  if (!t || t->poisoned || i >= t->count || t->tasks[i].state != E3_STOPPED ||
      ((unsigned)t->tasks[i].status >> 16) != PTRACE_EVENT_EXEC)
    return bad(t, EINVAL);
  int n = snprintf(path, sizeof(path), "/proc/%ld/exe", (long)t->tasks[i].pid);
  if (n <= 0 || (size_t)n >= sizeof(path))
    return bad(t, EOVERFLOW);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return bad(t, errno);
  if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
    close(fd);
    return bad(t, EPROTO);
  }
  return fd;
}

/* Linux's PTRACE_GET_SYSCALL_INFO wire layout, deliberately local so older
 * libc headers can still compile. Returned bytes are kernel data, not proof
 * of stable pointer contents or a source callsite. */
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
struct kernel_syscall_info {
  uint8_t op, pad[3];
  uint32_t arch;
  uint64_t ip, sp;
  union {
    struct {
      uint64_t number, args[6];
    } entry;
    struct {
      int64_t result;
      uint8_t is_error;
    } exit;
  } u;
};
int e3_trace_syscall_info(struct e3_trace *t, unsigned i,
                          struct e3_syscall_stop *out) {
  struct kernel_syscall_info info = {0};
  if (!t || !out || t->poisoned || i >= t->count ||
      t->tasks[i].state != E3_STOPPED ||
      ((unsigned)t->tasks[i].status >> 16) != 0 ||
      WSTOPSIG(t->tasks[i].status) != (SIGTRAP | 0x80))
    return bad(t, EINVAL);
  long size = ptrace(PTRACE_GET_SYSCALL_INFO, t->tasks[i].pid,
                     (void *)(uintptr_t)sizeof(info), &info);
  if (size < 0)
    return bad(t, errno);
  size_t required =
      info.op == 1   ? offsetof(struct kernel_syscall_info, u.entry.args) +
                           sizeof(info.u.entry.args)
      : info.op == 2 ? offsetof(struct kernel_syscall_info, u.exit.is_error) + 1
                     : 0;
  if (!required || (size_t)size < required)
    return bad(t, EPROTO);
  memset(out, 0, sizeof(*out));
  out->operation = info.op;
  out->arch = info.arch;
  out->instruction_pointer = info.ip;
  out->stack_pointer = info.sp;
  if (info.op == 1) {
    out->number = info.u.entry.number;
    memcpy(out->args, info.u.entry.args, sizeof(out->args));
  } else {
    out->result = info.u.exit.result;
    out->is_error = info.u.exit.is_error;
    if (out->is_error > 1)
      return bad(t, EPROTO);
  }
  return 0;
}
int e3_trace_release_stub(struct e3_trace *t) {
  if (!t || t->poisoned || t->barrier_fd < 0)
    return bad(t, EINVAL);
  if (close(t->barrier_fd)) {
    t->barrier_fd = -1;
    return bad(t, errno);
  }
  t->barrier_fd = -1;
  return 0;
}
int e3_trace_teardown(struct e3_trace *t, unsigned timeout) {
  struct timespec end;
  unsigned char attempted_interrupt[E3_TRACE_MAX] = {0};
  unsigned char attempted_kill[E3_TRACE_MAX] = {0};
  unsigned char lost[E3_TRACE_MAX] = {0};
  int first_error = 0;
  if (!t || deadline(timeout, &end))
    return bad(t, EINVAL);
  if (t->barrier_fd >= 0) {
    if (close(t->barrier_fd))
      first_error = errno;
    t->barrier_fd = -1;
  }
  for (;;) {
    unsigned active = 0;
    for (unsigned i = 0; i < t->count; i++) {
      struct e3_trace_task *task = &t->tasks[i];
      if (task->state == E3_EXITED || task->state == E3_UNUSED || lost[i])
        continue;
      active++;
      if (task->state == E3_STOPPED && !attempted_kill[i]) {
        attempted_kill[i] = 1;
        if (!task->traced) {
          if (!first_error)
            first_error = EPROTO;
        } else if (ptrace(PTRACE_KILL, task->pid, 0, 0)) {
          if (errno != ESRCH && !first_error)
            first_error = errno;
        } else {
          task->state = E3_RUNNING;
          attempted_interrupt[i] = 1;
        }
      } else if (task->state == E3_RUNNING && task->traced &&
                 !attempted_interrupt[i]) {
        attempted_interrupt[i] = 1;
        if (ptrace(PTRACE_INTERRUPT, task->pid, 0, 0) && errno != ESRCH &&
            !first_error)
          first_error = errno;
      }
      /* Poll every owned task even if another one's operation failed.
       * A wait error never proves that the task was reaped. */
      int status;
      pid_t got = waitpid(task->pid, &status, __WALL | WNOHANG);
      if (got == task->pid) {
        if (capture(t, i, status, 0) && !first_error)
          first_error = errno;
        attempted_interrupt[i] = 0;
        attempted_kill[i] = 0;
      } else if (got < 0 && errno != EINTR) {
        if (!first_error)
          first_error = errno;
        lost[i] = 1; /* do not act again on an identity no longer owned */
      }
    }
    if (!active)
      return first_error ? bad(t, first_error) : 0;
    int done = expired(&end);
    if (done != 0) {
      if (!first_error)
        first_error = done < 0 ? errno : ETIMEDOUT;
      return bad(t, first_error);
    }
    struct timespec pause = {.tv_nsec = 1000000L};
    (void)nanosleep(&pause, 0);
  }
}
#else
int e3_trace_start(struct e3_trace *t, unsigned b, unsigned ms) {
  (void)t;
  (void)b;
  (void)ms;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_poll(struct e3_trace *t, unsigned ms, unsigned *i) {
  (void)t;
  (void)ms;
  (void)i;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_resume(struct e3_trace *t, unsigned i) {
  (void)t;
  (void)i;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_open_exec(struct e3_trace *t, unsigned i) {
  (void)t;
  (void)i;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_syscall_info(struct e3_trace *t, unsigned i,
                          struct e3_syscall_stop *out) {
  (void)t;
  (void)i;
  (void)out;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_release_stub(struct e3_trace *t) {
  (void)t;
  errno = ENOTSUP;
  return -1;
}
int e3_trace_teardown(struct e3_trace *t, unsigned ms) {
  (void)t;
  (void)ms;
  errno = ENOTSUP;
  return -1;
}
#endif
void e3_trace_teardown_or_exit(struct e3_trace *t, unsigned timeout) {
  if (e3_trace_teardown(t, timeout))
    _Exit(125);
}
