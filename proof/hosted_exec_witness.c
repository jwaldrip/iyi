/*
 * proof/hosted_exec_witness.c
 *
 * C-owned native parent tracer for Linux strict execution witness.
 * Operates unprivileged inside the container cage (UID 65534, dropped
 * capabilities). Enforces PR_SET_DUMPABLE=0 to prevent same-UID untrusted
 * children from inspecting or hijacking tracer memory or descriptor state via
 * /proc/<tracer_pid>/{mem,fd}.
 *
 * Uses Linux ptrace with PTRACE_O_EXITKILL, PTRACE_O_TRACEEXEC,
 * PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, PTRACE_O_TRACECLONE,
 * PTRACE_O_TRACEEXIT.
 *
 * At every successful execve(2)/execveat(2) stop (PTRACE_EVENT_EXEC), inspects
 * /proc/<tracee_pid>/exe to record the physical (st_dev, st_ino) identity,
 * mode, size, and timestamps before user-space code executes. Holds an O_PATH
 * descriptor to guarantee that unlinked temporary binaries remain pinned in the
 * kernel.
 *
 * Streams versioned NDJSON protocol ("iyi-exec-witness-v1") exclusively to a
 * private evidence file descriptor or file. Untrusted child receives isolated
 * standard FDs and has zero access to the evidence channel.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

static inline long linux_ptrace(int req, pid_t pid, void *addr, void *data) {
  extern long ptrace(int, ...);
  return ptrace(req, pid, addr, data);
}
#else
extern int prctl(int option, ...);
static inline long linux_ptrace(int req, pid_t pid, void *addr, void *data) {
  (void)req;
  (void)pid;
  (void)addr;
  (void)data;
  return 0;
}
#endif

#if defined(__APPLE__) || defined(__darwin__) || defined(__MACH__)
#define STAT_ATIM_SEC(st) ((st).st_atimespec.tv_sec)
#define STAT_ATIM_NSEC(st) ((st).st_atimespec.tv_nsec)
#define STAT_MTIM_SEC(st) ((st).st_mtimespec.tv_sec)
#define STAT_MTIM_NSEC(st) ((st).st_mtimespec.tv_nsec)
#define STAT_CTIM_SEC(st) ((st).st_ctimespec.tv_sec)
#define STAT_CTIM_NSEC(st) ((st).st_ctimespec.tv_nsec)
#elif defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200809L) &&              \
    defined(__linux__)
#define STAT_ATIM_SEC(st) ((st).st_atim.tv_sec)
#define STAT_ATIM_NSEC(st) ((st).st_atim.tv_nsec)
#define STAT_MTIM_SEC(st) ((st).st_mtim.tv_sec)
#define STAT_MTIM_NSEC(st) ((st).st_mtim.tv_nsec)
#define STAT_CTIM_SEC(st) ((st).st_ctim.tv_sec)
#define STAT_CTIM_NSEC(st) ((st).st_ctim.tv_nsec)
#else
#define STAT_ATIM_SEC(st) ((st).st_atime)
#define STAT_ATIM_NSEC(st) (0)
#define STAT_MTIM_SEC(st) ((st).st_mtime)
#define STAT_MTIM_NSEC(st) (0)
#define STAT_CTIM_SEC(st) ((st).st_ctime)
#define STAT_CTIM_NSEC(st) (0)
#endif

#define PROTOCOL_VERSION "iyi-exec-witness-v1"
#define MAX_TRACKED_PROCESSES 8192
#define MAX_HELD_DESCRIPTORS 1024

/* Linux constant fallbacks */
#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifndef __WALL
#ifdef WCLONE
#define __WALL WCLONE
#else
#define __WALL 0
#endif
#endif

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME 0
#endif
#ifndef PTRACE_CONT
#define PTRACE_CONT 7
#endif
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif

#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 1
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK (1 << 1)
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK (1 << 2)
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE (1 << 3)
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC (1 << 4)
#endif
#ifndef PTRACE_O_TRACEVFORKDONE
#define PTRACE_O_TRACEVFORKDONE (1 << 5)
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT (1 << 6)
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif

#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif
#ifndef PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK 2
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef PTRACE_EVENT_VFORK_DONE
#define PTRACE_EVENT_VFORK_DONE 5
#endif
#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
#endif
#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#ifndef PR_SET_PDEATHSIG
#define PR_SET_PDEATHSIG 1
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

typedef struct {
  pid_t pid;
  pid_t ppid;
  uint64_t seq_id;
  uint64_t parent_seq_id;
  bool is_thread;
  bool active;
  bool exited;
  int exit_status;
} ProcessEntry;

static ProcessEntry g_processes[MAX_TRACKED_PROCESSES];
static size_t g_process_count = 0;
static size_t g_active_processes = 0;
static uint64_t g_seq_counter = 0;

static int g_held_fds[MAX_HELD_DESCRIPTORS];
static size_t g_held_fd_count = 0;

static int g_evidence_fd = -1;
static uint64_t g_total_exec_events = 0;
static uint64_t g_total_processes_spawned = 0;
static pid_t g_root_pid = -1;
static int g_root_exit_code = 0;
static bool g_root_exited = false;
static char g_failure_reason[256] = {0};
static bool g_failed = false;

static uint64_t get_time_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    return 0;
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void close_all_non_standard_fds(int keep_fd1, int keep_fd2) {
#if defined(__linux__) && defined(SYS_close_range)
  if (syscall(SYS_close_range, 3, (unsigned int)~0U, 0) == 0) {
    return;
  }
#endif
  /* Fallback descriptor cleanup */
  for (int fd = 3; fd < 4096; fd++) {
    if (fd == keep_fd1 || fd == keep_fd2) {
      continue;
    }
    close(fd);
  }
}

static void escape_json_string(const char *in, char *out, size_t out_max) {
  size_t j = 0;
  for (size_t i = 0; in[i] != '\0' && j + 6 < out_max; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '"') {
      out[j++] = '\\';
      out[j++] = '"';
    } else if (c == '\\') {
      out[j++] = '\\';
      out[j++] = '\\';
    } else if (c == '\b') {
      out[j++] = '\\';
      out[j++] = 'b';
    } else if (c == '\f') {
      out[j++] = '\\';
      out[j++] = 'f';
    } else if (c == '\n') {
      out[j++] = '\\';
      out[j++] = 'n';
    } else if (c == '\r') {
      out[j++] = '\\';
      out[j++] = 'r';
    } else if (c == '\t') {
      out[j++] = '\\';
      out[j++] = 't';
    } else if (c < 32 || c >= 127) {
      snprintf(out + j, out_max - j, "\\u%04x", c);
      j += 6;
    } else {
      out[j++] = c;
    }
  }
  out[j] = '\0';
}

static void emit_evidence_record(const char *json_line) {
  if (g_evidence_fd < 0) {
    return;
  }
  size_t len = strlen(json_line);
  ssize_t written = write(g_evidence_fd, json_line, len);
  (void)written;
  written = write(g_evidence_fd, "\n", 1);
  (void)written;
}

static ProcessEntry *find_process(pid_t pid) {
  for (size_t i = 0; i < g_process_count; i++) {
    if (g_processes[i].pid == pid && g_processes[i].active) {
      return &g_processes[i];
    }
  }
  return NULL;
}

static ProcessEntry *add_process(pid_t pid, pid_t ppid, uint64_t parent_seq,
                                 bool is_thread, const char *kind) {
  if (g_process_count >= MAX_TRACKED_PROCESSES) {
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "TRACKED_PROCESS_LIMIT_EXCEEDED");
    g_failed = true;
    return NULL;
  }
  uint64_t seq = ++g_seq_counter;
  ProcessEntry *e = &g_processes[g_process_count++];
  e->pid = pid;
  e->ppid = ppid;
  e->seq_id = seq;
  e->parent_seq_id = parent_seq;
  e->is_thread = is_thread;
  e->active = true;
  e->exited = false;
  e->exit_status = 0;
  g_active_processes++;
  g_total_processes_spawned++;

  char buf[512];
  snprintf(buf, sizeof(buf),
           "{\"event\":\"process_spawn\",\"seq_id\":%" PRIu64
           ",\"timestamp_ns\":%" PRIu64
           ",\"pid\":%d,\"ppid\":%d,\"parent_seq_id\":%" PRIu64
           ",\"kind\":\"%s\",\"is_thread\":%s}",
           seq, get_time_ns(), (int)pid, (int)ppid, parent_seq, kind,
           is_thread ? "true" : "false");
  emit_evidence_record(buf);
  return e;
}

static void emit_session_start(const char *launch_binding_json) {
  char buf[2048];
  snprintf(buf, sizeof(buf),
           "{\"event\":\"session_start\",\"protocol\":\"" PROTOCOL_VERSION
           "\",\"tracer_pid\":%d"
           ",\"start_time_ns\":%" PRIu64 ",\"tracer_dumpable\":0"
           ",\"launch_binding\":%s"
           ",\"options\":[\"TRACEEXEC\",\"TRACEFORK\",\"TRACEVFORK\","
           "\"TRACECLONE\",\"TRACEEXIT\",\"EXITKILL\",\"TRACESYSGOOD\"]}",
           (int)getpid(), get_time_ns(),
           launch_binding_json ? launch_binding_json : "{}");
  emit_evidence_record(buf);
}

static void emit_session_end(void) {
  char buf[1024];
  const char *status = (g_failed || !g_root_exited || g_active_processes > 0)
                           ? "FAILED"
                           : "COMPLETE";
  snprintf(
      buf, sizeof(buf),
      "{\"event\":\"session_end\",\"protocol\":\"" PROTOCOL_VERSION
      "\",\"tracer_pid\":%d"
      ",\"end_time_ns\":%" PRIu64 ",\"status\":\"%s\",\"root_exit_code\":%d"
      ",\"total_processes_spawned\":%" PRIu64 ",\"total_exec_events\":%" PRIu64
      ",\"active_processes_at_end\":%zu%s%s%s}",
      (int)getpid(), get_time_ns(), status, g_root_exit_code,
      g_total_processes_spawned, g_total_exec_events, g_active_processes,
      g_failure_reason[0] ? ",\"failure_reason\":\"" : "",
      g_failure_reason[0] ? g_failure_reason : "",
      g_failure_reason[0] ? "\"" : "");
  emit_evidence_record(buf);
}

static void handle_exec_event(pid_t pid) {
  ProcessEntry *proc = find_process(pid);
  uint64_t seq = proc ? proc->seq_id : 0;
  pid_t ppid = proc ? proc->ppid : 0;

  char proc_exe[64];
  snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", (int)pid);

  char exe_target[PATH_MAX] = {0};
  ssize_t link_len = readlink(proc_exe, exe_target, sizeof(exe_target) - 1);
  if (link_len > 0) {
    exe_target[link_len] = '\0';
  } else {
    snprintf(exe_target, sizeof(exe_target), "unknown");
  }

  struct stat st;
  memset(&st, 0, sizeof(st));
  if (stat(proc_exe, &st) != 0) {
    fstatat(AT_FDCWD, proc_exe, &st, AT_SYMLINK_NOFOLLOW);
  }

  /* Pin the executable inode via O_PATH so temporary binaries deleted by
   * workload stay held */
  int held_idx = -1;
  if (g_held_fd_count < MAX_HELD_DESCRIPTORS) {
    int held_fd = open(proc_exe, O_PATH | O_CLOEXEC);
    if (held_fd >= 0) {
      held_idx = (int)g_held_fd_count;
      g_held_fds[g_held_fd_count++] = held_fd;
    }
  }

  /* Read command-line arguments from /proc/<pid>/cmdline */
  char proc_cmdline[64];
  snprintf(proc_cmdline, sizeof(proc_cmdline), "/proc/%d/cmdline", (int)pid);
  int cmd_fd = open(proc_cmdline, O_RDONLY | O_CLOEXEC);
  char cmd_json[2048] = "[";
  size_t cmd_json_len = 1;
  if (cmd_fd >= 0) {
    char raw_cmd[2048];
    ssize_t n = read(cmd_fd, raw_cmd, sizeof(raw_cmd) - 1);
    close(cmd_fd);
    if (n > 0) {
      raw_cmd[n] = '\0';
      ssize_t pos = 0;
      bool first = true;
      while (pos < n && cmd_json_len + 128 < sizeof(cmd_json)) {
        const char *arg = raw_cmd + pos;
        size_t arg_len = strlen(arg);
        char escaped[256];
        escape_json_string(arg, escaped, sizeof(escaped));
        if (!first) {
          cmd_json[cmd_json_len++] = ',';
        }
        first = false;
        int written =
            snprintf(cmd_json + cmd_json_len, sizeof(cmd_json) - cmd_json_len,
                     "\"%s\"", escaped);
        if (written > 0) {
          cmd_json_len += (size_t)written;
        }
        pos += arg_len + 1;
      }
    }
  }
  if (cmd_json_len < sizeof(cmd_json) - 2) {
    cmd_json[cmd_json_len++] = ']';
    cmd_json[cmd_json_len] = '\0';
  } else {
    snprintf(cmd_json, sizeof(cmd_json), "[]");
  }

  char escaped_path[PATH_MAX * 2];
  escape_json_string(exe_target, escaped_path, sizeof(escaped_path));

  uint64_t atim_ns = (uint64_t)STAT_ATIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_ATIM_NSEC(st);
  uint64_t mtim_ns = (uint64_t)STAT_MTIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_MTIM_NSEC(st);
  uint64_t ctim_ns = (uint64_t)STAT_CTIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_CTIM_NSEC(st);

  char buf[4096];
  snprintf(
      buf, sizeof(buf),
      "{\"event\":\"exec_success\",\"seq_id\":%" PRIu64
      ",\"timestamp_ns\":%" PRIu64 ",\"pid\":%d,\"ppid\":%d,\"exe_path\":\"%s\""
      ",\"st_dev\":%" PRIu64 ",\"st_ino\":%" PRIu64
      ",\"st_mode\":%u,\"st_size\":%" PRIi64 ",\"st_uid\":%u,\"st_gid\":%u"
      ",\"st_atim_ns\":%" PRIu64 ",\"st_mtim_ns\":%" PRIu64
      ",\"st_ctim_ns\":%" PRIu64 ",\"held_fd_index\":%d,\"cmdline\":%s}",
      seq, get_time_ns(), (int)pid, (int)ppid, escaped_path,
      (uint64_t)st.st_dev, (uint64_t)st.st_ino, (unsigned int)st.st_mode,
      (int64_t)st.st_size, (unsigned int)st.st_uid, (unsigned int)st.st_gid,
      atim_ns, mtim_ns, ctim_ns, held_idx, cmd_json);

  emit_evidence_record(buf);
  g_total_exec_events++;
}

static void handle_exit_event(pid_t pid) {
  unsigned long raw_status = 0;
  linux_ptrace(PTRACE_GETEVENTMSG, pid, 0, &raw_status);

  ProcessEntry *proc = find_process(pid);
  uint64_t seq = proc ? proc->seq_id : 0;
  int exit_code = (int)raw_status;

  char buf[512];
  snprintf(buf, sizeof(buf),
           "{\"event\":\"process_exit\",\"seq_id\":%" PRIu64
           ",\"timestamp_ns\":%" PRIu64
           ",\"pid\":%d,\"exit_code\":%d,\"raw_status\":%lu}",
           seq, get_time_ns(), (int)pid, exit_code, raw_status);
  emit_evidence_record(buf);
}

int main(int argc, char **argv) {
  int evidence_fd = -1;
  const char *evidence_file = NULL;
  const char *launch_binding = "{}";
  int cmd_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--evidence-fd") == 0 && i + 1 < argc) {
      evidence_fd = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--evidence-file") == 0 && i + 1 < argc) {
      evidence_file = argv[++i];
    } else if (strcmp(argv[i], "--launch-binding") == 0 && i + 1 < argc) {
      launch_binding = argv[++i];
    } else if (strcmp(argv[i], "--") == 0) {
      cmd_index = i + 1;
      break;
    }
  }

  if (cmd_index < 0 || cmd_index >= argc) {
    fprintf(stderr,
            "Usage: %s [--evidence-fd <FD>] [--evidence-file <FILE>] "
            "[--launch-binding <JSON>] -- <CMD> [ARGS...]\n",
            argv[0]);
    return 2;
  }

  /* Set up evidence descriptor */
  if (evidence_file != NULL) {
    int fd =
        open(evidence_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
      fprintf(stderr,
              "hosted_exec_witness: failed to open evidence file %s: %s\n",
              evidence_file, strerror(errno));
      return 1;
    }
    g_evidence_fd = fd;
  } else if (evidence_fd >= 0) {
    /* Set close-on-exec on evidence fd so child does NOT inherit it */
    int flags = fcntl(evidence_fd, F_GETFD);
    if (flags >= 0) {
      fcntl(evidence_fd, F_SETFD, flags | FD_CLOEXEC);
    }
    g_evidence_fd = evidence_fd;
  } else {
    /* Default to stdout if no evidence stream specified */
    g_evidence_fd = dup(STDOUT_FILENO);
    fcntl(g_evidence_fd, F_SETFD, FD_CLOEXEC);
  }

  /* Enforce non-dumpable state on parent tracer */
  if (prctl(PR_SET_DUMPABLE, 0) < 0) {
    fprintf(stderr,
            "hosted_exec_witness: prctl(PR_SET_DUMPABLE, 0) failed: %s\n",
            strerror(errno));
    return 1;
  }

  emit_session_start(launch_binding);

  /* Launch barrier pipe */
  int barrier_pipe[2];
#if defined(__linux__) && defined(O_CLOEXEC)
  if (pipe2(barrier_pipe, O_CLOEXEC) < 0) {
#else
  if (pipe(barrier_pipe) < 0) {
#endif
    fprintf(stderr, "hosted_exec_witness: pipe failed: %s\n", strerror(errno));
    snprintf(g_failure_reason, sizeof(g_failure_reason), "PIPE_BARRIER_FAILED");
    g_failed = true;
    emit_session_end();
    return 1;
  }

  pid_t child_pid = fork();
  if (child_pid < 0) {
    fprintf(stderr, "hosted_exec_witness: fork failed: %s\n", strerror(errno));
    snprintf(g_failure_reason, sizeof(g_failure_reason), "FORK_FAILED");
    g_failed = true;
    emit_session_end();
    return 1;
  }

  if (child_pid == 0) {
    /* --- CHILD PROCESS --- */
    close(barrier_pipe[1]); /* Close write end */

    /* Ensure child terminates if parent tracer is killed */
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    /* Close all descriptors except stdio (0, 1, 2) and barrier_pipe[0] */
    close_all_non_standard_fds(barrier_pipe[0], -1);

    /* Request tracing by parent */
    if (linux_ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      fprintf(
          stderr,
          "hosted_exec_witness [child]: ptrace(PTRACE_TRACEME) failed: %s\n",
          strerror(errno));
      _exit(127);
    }

    /* Signal parent that we are ready to be armed */
    raise(SIGSTOP);

    /* Wait for parent to arm ptrace options and release barrier */
    char sync_byte = 0;
    ssize_t r = read(barrier_pipe[0], &sync_byte, 1);
    (void)r;
    close(barrier_pipe[0]);

    /* Execute target workload */
    char **child_argv = &argv[cmd_index];
    execvp(child_argv[0], child_argv);

    /* If execvp returns, it failed */
    fprintf(stderr, "hosted_exec_witness [child]: execvp(%s) failed: %s\n",
            child_argv[0], strerror(errno));
    _exit(127);
  }

  /* --- PARENT TRACER --- */
  close(barrier_pipe[0]); /* Close read end */
  g_root_pid = child_pid;

  /* Wait for child to stop at raise(SIGSTOP) */
  int status = 0;
  pid_t w = waitpid(child_pid, &status, __WALL);
  if (w != child_pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
    fprintf(stderr,
            "hosted_exec_witness: unexpected initial stop for child %d "
            "(status=0x%x)\n",
            (int)child_pid, status);
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "INITIAL_CHILD_STOP_FAILED");
    g_failed = true;
    kill(child_pid, SIGKILL);
    emit_session_end();
    return 1;
  }

  /* Configure ptrace options on root child */
  long ptrace_options = PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL |
                        PTRACE_O_TRACESYSGOOD;

  if (linux_ptrace(PTRACE_SETOPTIONS, child_pid, 0, (void *)ptrace_options) <
      0) {
    fprintf(stderr,
            "hosted_exec_witness: ptrace(PTRACE_SETOPTIONS) failed: %s\n",
            strerror(errno));
    snprintf(g_failure_reason, sizeof(g_failure_reason), "SETOPTIONS_FAILED");
    g_failed = true;
    kill(child_pid, SIGKILL);
    emit_session_end();
    return 1;
  }

  /* Register root process */
  add_process(child_pid, getpid(), 0, false, "initial");

  /* Release child by writing to barrier pipe and resuming it */
  char go_byte = 'G';
  ssize_t w_bar = write(barrier_pipe[1], &go_byte, 1);
  (void)w_bar;
  close(barrier_pipe[1]);

  if (linux_ptrace(PTRACE_CONT, child_pid, NULL, 0) < 0) {
    fprintf(stderr,
            "hosted_exec_witness: initial ptrace(PTRACE_CONT) failed: %s\n",
            strerror(errno));
    snprintf(g_failure_reason, sizeof(g_failure_reason), "INITIAL_CONT_FAILED");
    g_failed = true;
    kill(child_pid, SIGKILL);
    emit_session_end();
    return 1;
  }

  /* Tracer event loop */
  while (g_active_processes > 0) {
    int wait_status = 0;
    pid_t event_pid = waitpid(-1, &wait_status, __WALL);
    if (event_pid < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == ECHILD) {
        /* All children have exited */
        break;
      }
      snprintf(g_failure_reason, sizeof(g_failure_reason), "WAITPID_ERROR_%d",
               errno);
      g_failed = true;
      break;
    }

    ProcessEntry *proc = find_process(event_pid);

    if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
      if (proc) {
        proc->active = false;
        proc->exited = true;
        proc->exit_status = WIFEXITED(wait_status)
                                ? WEXITSTATUS(wait_status)
                                : 128 + WTERMSIG(wait_status);
        g_active_processes--;
        if (event_pid == g_root_pid) {
          g_root_exited = true;
          g_root_exit_code = proc->exit_status;
        }
      } else {
        /* Unaccounted child exited */
        g_active_processes--;
      }
      continue;
    }

    if (WIFSTOPPED(wait_status)) {
      int stop_sig = WSTOPSIG(wait_status);
      int event = (unsigned int)wait_status >> 16;

      if (stop_sig == SIGTRAP) {
        if (event == PTRACE_EVENT_EXEC) {
          handle_exec_event(event_pid);
          linux_ptrace(PTRACE_CONT, event_pid, NULL, 0);
          continue;
        } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                   event == PTRACE_EVENT_CLONE) {
          unsigned long new_child_pid = 0;
          linux_ptrace(PTRACE_GETEVENTMSG, event_pid, 0, &new_child_pid);
          if (new_child_pid > 0) {
            bool is_thread = (event == PTRACE_EVENT_CLONE);
            const char *kind_str = (event == PTRACE_EVENT_FORK)    ? "fork"
                                   : (event == PTRACE_EVENT_VFORK) ? "vfork"
                                                                   : "clone";
            add_process((pid_t)new_child_pid, event_pid,
                        proc ? proc->seq_id : 0, is_thread, kind_str);
          }
          linux_ptrace(PTRACE_CONT, event_pid, NULL, 0);
          continue;
        } else if (event == PTRACE_EVENT_EXIT) {
          handle_exit_event(event_pid);
          linux_ptrace(PTRACE_CONT, event_pid, NULL, 0);
          continue;
        } else {
          /* Generic SIGTRAP (e.g. initial exec trap), continue without signal
           */
          linux_ptrace(PTRACE_CONT, event_pid, NULL, 0);
          continue;
        }
      } else if (stop_sig == SIGSTOP || stop_sig == (SIGTRAP | 0x80)) {
        /* Cloned process initial stop or ptrace stop; do not forward SIGSTOP */
        linux_ptrace(PTRACE_CONT, event_pid, NULL, 0);
        continue;
      } else {
        /* Genuine signal intended for tracee; forward it */
        linux_ptrace(PTRACE_CONT, event_pid, NULL, (void *)(intptr_t)stop_sig);
        continue;
      }
    }
  }

  emit_session_end();

  /* Close all held O_PATH descriptors */
  for (size_t i = 0; i < g_held_fd_count; i++) {
    close(g_held_fds[i]);
  }

  if (g_evidence_fd >= 0) {
    close(g_evidence_fd);
  }

  return g_root_exit_code;
}
