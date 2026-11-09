/*
 * proof/hosted_exec_witness.c
 *
 * C-owned native parent tracer for Linux strict execution witness.
 * Operates unprivileged inside the container cage (UID 65534, dropped
 * capabilities). Enforces PR_SET_DUMPABLE=0 to prevent same-UID untrusted
 * children from inspecting or hijacking tracer memory or descriptor state via
 * /proc/<tracer_pid>/{mem,fd}.
 *
 * Uses Linux ptrace with:
 *   PTRACE_O_EXITKILL
 *   PTRACE_O_TRACEEXEC
 *   PTRACE_O_TRACEFORK
 *   PTRACE_O_TRACEVFORK
 *   PTRACE_O_TRACECLONE
 *   PTRACE_O_TRACEEXIT
 *   PTRACE_O_TRACESYSGOOD
 *
 * Syscall Mediation & Evasion Resistance:
 *   Intercepts syscalls via PTRACE_SYSCALL.
 *   Disallows any ptrace(2) calls from untrusted children.
 *   Rejects clone3(2) outright to eliminate userspace memory modification
 * races. Rejects IA32, x32, and AArch32 compat syscall entry paths. Inspects
 * clone(2) arguments; rejects CLONE_UNTRACED immediately. Fails closed on any
 * unaccounted child exit, ptrace failure, or unexpected ECHILD.
 *
 * Binary Classification & Raw Executable Capture:
 *   Classifies binaries into:
 *   1. Mutable Workload Outputs (in /private/tmp, /scratch, /tmp, /home/proof
 * or owned by current UID): MUST be opened with O_RDONLY | O_NOATIME
 * (preserving target st_atime). Never falls back to ordinary O_RDONLY; fails
 * closed if O_NOATIME is refused.
 *   2. Immutable System Binaries (e.g. /usr/bin/python3, /bin/bash owned by
 * root on verified ST_RDONLY mounts): verified via fstatvfs(ST_RDONLY) and
 * system UID ownership. Reading has zero atime source effect because the kernel
 * suppresses atime updates on read-only mounts. Computes SHA-256 digest.
 * Persists raw bytes for workload outputs to --raw-capture-dir. Fails closed on
 * destination open, write, or partial-write errors. Holds O_PATH descriptor;
 * fails closed if descriptor table is full or open fails.
 *
 * Inode Deduplication & Repeated Execution:
 *   Tracks captured executables by (st_dev, st_ino) with continuous O_PATH
 * descriptor hold (preventing kernel inode reuse during session). Repeated
 * executions of the same binary (e.g. bash, python, iyi) verify metadata
 * stability (st_size, st_ctime, st_mtim) and deduplicate without EEXIST or
 * destination collision.
 *
 * Non-Leader Thread Exec & Signal Semantics:
 *   Reconciles non-leader thread exec via PTRACE_GETEVENTMSG old_tid.
 *   Distinguishes clone initial stops from genuine workload signals; forwards
 *   application signals faithfully.
 *
 * Private Output Channel:
 *   Requires --evidence-fd >= 3. Child receives dedicated pipes for
 * stdout/stderr, completely isolated from the private evidence stream.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int prctl(int option, ...);

#if defined(__linux__)
#include <elf.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>

static inline long linux_ptrace(int req, pid_t pid, void *addr, void *data) {
  extern long ptrace(int, ...);
  return ptrace(req, pid, addr, data);
}

#define STAT_ATIM_SEC(st) ((st).st_atim.tv_sec)
#define STAT_ATIM_NSEC(st) ((st).st_atim.tv_nsec)
#define STAT_MTIM_SEC(st) ((st).st_mtim.tv_sec)
#define STAT_MTIM_NSEC(st) ((st).st_mtim.tv_nsec)
#define STAT_CTIM_SEC(st) ((st).st_ctim.tv_sec)
#define STAT_CTIM_NSEC(st) ((st).st_ctim.tv_nsec)

#else
/* Non-Linux stub definitions for toolchains and editors */
static inline long linux_ptrace(int req, pid_t pid, void *addr, void *data) {
  (void)req;
  (void)pid;
  (void)addr;
  (void)data;
  errno = ENOSYS;
  return -1;
}

#if defined(__APPLE__) || defined(__darwin__) || defined(__MACH__)
#define STAT_ATIM_SEC(st) ((st).st_atimespec.tv_sec)
#define STAT_ATIM_NSEC(st) ((st).st_atimespec.tv_nsec)
#define STAT_MTIM_SEC(st) ((st).st_mtimespec.tv_sec)
#define STAT_MTIM_NSEC(st) ((st).st_mtimespec.tv_nsec)
#define STAT_CTIM_SEC(st) ((st).st_ctimespec.tv_sec)
#define STAT_CTIM_NSEC(st) ((st).st_ctimespec.tv_nsec)
#else
#define STAT_ATIM_SEC(st) ((st).st_atime)
#define STAT_ATIM_NSEC(st) (0)
#define STAT_MTIM_SEC(st) ((st).st_mtime)
#define STAT_MTIM_NSEC(st) (0)
#define STAT_CTIM_SEC(st) ((st).st_ctime)
#define STAT_CTIM_NSEC(st) (0)
#endif

#endif

#define PROTOCOL_VERSION "iyi-exec-witness-v1"
#define MAX_TRACKED_PROCESSES 8192
#define MAX_HELD_DESCRIPTORS 1024

/* Linux constant fallbacks */
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
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
#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA 2
#endif
#ifndef PTRACE_CONT
#define PTRACE_CONT 7
#endif
#ifndef PTRACE_SYSCALL
#define PTRACE_SYSCALL 24
#endif
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
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

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000UL
#endif

/* -------------------------------------------------------------------------
 * Compact Standard SHA-256 (FIPS 180-4)
 * ------------------------------------------------------------------------- */
typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
} SHA256_CTX;

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
  static const uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0x0bef9a3f, 0x47b5481d};
  uint32_t W[64];
  for (int i = 0; i < 16; i++) {
    W[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
           ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 =
        rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
    uint32_t s1 =
        rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
    W[i] = W[i - 16] + s0 + W[i - 7] + s1;
  }
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + K[i] + W[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
  size_t index = (size_t)(ctx->count & 0x3f);
  ctx->count += len;
  size_t part_len = 64 - index;
  size_t i = 0;
  if (len >= part_len) {
    memcpy(&ctx->buffer[index], data, part_len);
    sha256_transform(ctx->state, ctx->buffer);
    for (i = part_len; i + 63 < len; i += 64) {
      sha256_transform(ctx->state, &data[i]);
    }
    index = 0;
  }
  memcpy(&ctx->buffer[index], &data[i], len - i);
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
  uint8_t bits[8];
  uint64_t total_bits = ctx->count * 8;
  for (int i = 0; i < 8; i++) {
    bits[7 - i] = (uint8_t)((total_bits >> (i * 8)) & 0xff);
  }
  size_t index = (size_t)(ctx->count & 0x3f);
  size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
  static const uint8_t padding[64] = {0x80};
  sha256_update(ctx, padding, pad_len);
  sha256_update(ctx, bits, 8);
  for (int i = 0; i < 8; i++) {
    hash[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
    hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
    hash[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
  }
}

/* -------------------------------------------------------------------------
 * Process & Witness State
 * ------------------------------------------------------------------------- */
typedef struct {
  pid_t pid;
  pid_t ppid;
  uint64_t seq_id;
  uint64_t parent_seq_id;
  bool is_thread;
  bool active;
  bool exited;
  bool in_syscall;
  bool initial_stop_pending;
  int exit_status;
} ProcessEntry;

typedef struct {
  uint64_t st_dev;
  uint64_t st_ino;
  uint64_t st_ctime_ns;
  uint64_t st_mtim_ns;
  int64_t st_size;
  char sha256[65];
  int held_fd;
  bool is_system_binary;
} CapturedExecutable;

static ProcessEntry g_processes[MAX_TRACKED_PROCESSES];
static size_t g_process_count = 0;
static size_t g_active_processes = 0;
static uint64_t g_seq_counter = 0;

static CapturedExecutable g_captured_execs[MAX_HELD_DESCRIPTORS];
static size_t g_captured_exec_count = 0;

static int g_evidence_fd = -1;
static char g_raw_capture_dir[PATH_MAX] = {0};
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

static void kill_all_tracees(void) {
  for (size_t i = 0; i < g_process_count; i++) {
    if (g_processes[i].active && g_processes[i].pid > 0) {
      kill(g_processes[i].pid, SIGKILL);
    }
  }
}

static bool write_all(int fd, const void *buf, size_t count) {
  const char *ptr = (const char *)buf;
  size_t remaining = count;
  while (remaining > 0) {
    ssize_t written = write(fd, ptr, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (written == 0) {
      errno = EPIPE;
      return false;
    }
    ptr += (size_t)written;
    remaining -= (size_t)written;
  }
  return true;
}

static void close_all_non_standard_fds(int keep_fd1, int keep_fd2) {
  /*
   * Executed strictly in child process before execve.
   * Preserves standard fds 0, 1, 2 and explicitly kept fds (keep_fd1,
   * keep_fd2). Closes all other descriptors to prevent control/evidence channel
   * theft.
   */
#if defined(__linux__) && defined(SYS_close_range)
  int k1 = keep_fd1;
  int k2 = keep_fd2;
  if (k1 > k2) {
    int tmp = k1;
    k1 = k2;
    k2 = tmp;
  }

  if (k1 < 3 && k2 < 3) {
    if (syscall(SYS_close_range, 3, (unsigned int)~0U, 0) == 0) {
      return;
    }
  } else if (k1 >= 3 && k2 < 3) {
    bool ok = true;
    if (k1 > 3) {
      if (syscall(SYS_close_range, 3, (unsigned int)(k1 - 1), 0) != 0) {
        ok = false;
      }
    }
    if (syscall(SYS_close_range, (unsigned int)(k1 + 1), (unsigned int)~0U,
                0) != 0) {
      ok = false;
    }
    if (ok) {
      return;
    }
  } else if (k1 >= 3 && k2 >= 3) {
    bool ok = true;
    if (k1 > 3) {
      if (syscall(SYS_close_range, 3, (unsigned int)(k1 - 1), 0) != 0) {
        ok = false;
      }
    }
    if (k2 > k1 + 1) {
      if (syscall(SYS_close_range, (unsigned int)(k1 + 1),
                  (unsigned int)(k2 - 1), 0) != 0) {
        ok = false;
      }
    }
    if (syscall(SYS_close_range, (unsigned int)(k2 + 1), (unsigned int)~0U,
                0) != 0) {
      ok = false;
    }
    if (ok) {
      return;
    }
  }
#endif

  DIR *dir = opendir("/proc/self/fd");
  if (dir != NULL) {
    int dfd = dirfd(dir);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (de->d_name[0] == '.') {
        continue;
      }
      int fd = atoi(de->d_name);
      if (fd >= 3 && fd != dfd && fd != keep_fd1 && fd != keep_fd2) {
        close(fd);
      }
    }
    closedir(dir);
    return;
  }

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
  if (g_evidence_fd < 0 || g_failed) {
    return;
  }
  size_t len = strlen(json_line);
  if (!write_all(g_evidence_fd, json_line, len) ||
      !write_all(g_evidence_fd, "\n", 1)) {
    int err = errno;
    g_failed = true;
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "EVIDENCE_WRITE_FAILED_ERRNO_%d", err);
    fprintf(stderr, "hosted_exec_witness: fatal evidence write failure: %s\n",
            strerror(err));
    kill_all_tracees();
  }
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
    kill_all_tracees();
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
  e->in_syscall = false;
  e->initial_stop_pending = is_thread;
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

static CapturedExecutable *find_captured_exec(uint64_t dev, uint64_t ino) {
  for (size_t i = 0; i < g_captured_exec_count; i++) {
    if (g_captured_execs[i].st_dev == dev &&
        g_captured_execs[i].st_ino == ino) {
      return &g_captured_execs[i];
    }
  }
  return NULL;
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

static bool check_syscall_entry(pid_t pid, char *err_buf, size_t err_buf_len) {
#if defined(__linux__) && (defined(__x86_64__) || defined(__aarch64__))
  struct iovec iov;
#if defined(__x86_64__)
  struct user_regs_struct regs;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  if (linux_ptrace(PTRACE_GETREGSET, pid, (void *)(intptr_t)NT_PRSTATUS,
                   &iov) != 0) {
    snprintf(err_buf, err_buf_len, "PTRACE_GETREGSET_FAILED_%d", errno);
    return false;
  }
  /* Reject IA32 compat entry: CS == 0x23 on x86_64 */
  if (regs.cs == 0x23) {
    snprintf(err_buf, err_buf_len, "COMPAT_IA32_SYSCALL_DISALLOWED");
    return false;
  }
  /* Reject x32 ABI entry bit */
  if (regs.orig_rax & 0x40000000UL) {
    snprintf(err_buf, err_buf_len, "COMPAT_X32_SYSCALL_DISALLOWED");
    return false;
  }
  long sys_no = (long)regs.orig_rax;
  if (sys_no == 101) { /* __NR_ptrace */
    snprintf(err_buf, err_buf_len, "DISALLOWED_PTRACE_SYSCALL");
    return false;
  }
  if (sys_no == 435) { /* __NR_clone3: rejected outright to eliminate userspace
                          memory modification race */
    snprintf(err_buf, err_buf_len, "DISALLOWED_CLONE3_SYSCALL");
    return false;
  }
  if (sys_no == 56) { /* __NR_clone */
    unsigned long flags = (unsigned long)regs.rdi;
    if (flags & CLONE_UNTRACED) {
      snprintf(err_buf, err_buf_len, "CLONE_UNTRACED_ATTEMPT");
      return false;
    }
  }
#elif defined(__aarch64__)
  struct user_pt_regs regs;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  if (linux_ptrace(PTRACE_GETREGSET, pid, (void *)(intptr_t)NT_PRSTATUS,
                   &iov) != 0) {
    snprintf(err_buf, err_buf_len, "PTRACE_GETREGSET_FAILED_%d", errno);
    return false;
  }
  /* Reject AArch32 compat mode: pstate & 0x10 */
  if (regs.pstate & 0x10) {
    snprintf(err_buf, err_buf_len, "COMPAT_AARCH32_SYSCALL_DISALLOWED");
    return false;
  }
  long sys_no = (long)regs.regs[8];
  if (sys_no == 117) { /* __NR_ptrace */
    snprintf(err_buf, err_buf_len, "DISALLOWED_PTRACE_SYSCALL");
    return false;
  }
  if (sys_no == 435) { /* __NR_clone3 */
    snprintf(err_buf, err_buf_len, "DISALLOWED_CLONE3_SYSCALL");
    return false;
  }
  if (sys_no == 220) { /* __NR_clone */
    unsigned long flags = (unsigned long)regs.regs[0];
    if (flags & CLONE_UNTRACED) {
      snprintf(err_buf, err_buf_len, "CLONE_UNTRACED_ATTEMPT");
      return false;
    }
  }
#endif
#else
  (void)pid;
  snprintf(err_buf, err_buf_len, "UNSUPPORTED_ARCH_FOR_SYSCALL_MEDIATION");
  return false;
#endif
  return true;
}

static bool resume_tracee(pid_t pid, int sig) {
  if (linux_ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(intptr_t)sig) < 0) {
    int err = errno;
    if (err != ESRCH) {
      g_failed = true;
      snprintf(g_failure_reason, sizeof(g_failure_reason),
               "PTRACE_SYSCALL_FAILED_PID_%d_ERRNO_%d", (int)pid, err);
      fprintf(
          stderr,
          "hosted_exec_witness: ptrace PTRACE_SYSCALL failed on pid %d: %s\n",
          (int)pid, strerror(err));
      kill_all_tracees();
      return false;
    }
  }
  return true;
}

static void handle_exec_event(pid_t pid) {
  /* Check for non-leader thread exec migration via PTRACE_GETEVENTMSG */
  unsigned long old_tid = 0;
  if (linux_ptrace(PTRACE_GETEVENTMSG, pid, 0, &old_tid) == 0 && old_tid > 0 &&
      old_tid != (unsigned long)pid) {
    ProcessEntry *old_proc = find_process((pid_t)old_tid);
    if (old_proc != NULL) {
      old_proc->active = false;
      old_proc->exited = true;
      g_active_processes--;
    }
    ProcessEntry *leader_proc = find_process(pid);
    if (leader_proc == NULL) {
      uint64_t parent_seq = old_proc ? old_proc->parent_seq_id : 0;
      leader_proc =
          add_process(pid, getpid(), parent_seq, false, "exec_leader");
    }
  }

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

  uint64_t atim_ns = (uint64_t)STAT_ATIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_ATIM_NSEC(st);
  uint64_t mtim_ns = (uint64_t)STAT_MTIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_MTIM_NSEC(st);
  uint64_t ctim_ns = (uint64_t)STAT_CTIM_SEC(st) * 1000000000ULL +
                     (uint64_t)STAT_CTIM_NSEC(st);

  char sha256_hex[65] = {0};
  int64_t actual_bytes_captured = 0;
  int held_idx = -1;
  bool is_immutable_system_binary = false;
  bool is_deduplicated = false;

  /*
   * Deduplication Check:
   * Check if (st_dev, st_ino) was already captured and is currently pinned by
   * an open O_PATH fd. The held O_PATH descriptor prevents the Linux kernel
   * from recycling that inode number. If metadata (st_size, st_ctime, st_mtim)
   * is identical, we deduplicate safely without EEXIST.
   */
  CapturedExecutable *existing =
      find_captured_exec((uint64_t)st.st_dev, (uint64_t)st.st_ino);
  if (existing != NULL) {
    if (existing->st_size == (int64_t)st.st_size &&
        existing->st_ctime_ns == ctim_ns && existing->st_mtim_ns == mtim_ns) {
      strncpy(sha256_hex, existing->sha256, sizeof(sha256_hex) - 1);
      actual_bytes_captured = existing->st_size;
      held_idx = (int)(existing - g_captured_execs);
      is_immutable_system_binary = existing->is_system_binary;
      is_deduplicated = true;
      goto emit_exec_record;
    }
  }

  /* Pin executable inode via O_PATH. Must fail closed if descriptor allocation
   * fails. */
  if (g_captured_exec_count >= MAX_HELD_DESCRIPTORS) {
    g_failed = true;
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "HELD_FD_LIMIT_EXCEEDED");
    fprintf(stderr, "hosted_exec_witness: fatal: held descriptor table full\n");
    kill_all_tracees();
    return;
  }

  int held_fd = open(proc_exe, O_PATH | O_CLOEXEC);
  if (held_fd < 0) {
    int err = errno;
    g_failed = true;
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "HELD_FD_OPEN_FAILED_ERRNO_%d", err);
    fprintf(stderr,
            "hosted_exec_witness: fatal: open(O_PATH) failed on %s: %s\n",
            proc_exe, strerror(err));
    kill_all_tracees();
    return;
  }

  /*
   * Binary Classification:
   * 1. Mutable Workload Outputs:
   *    Files owned by current UID (65534) or located in mutable paths
   * (/private/tmp, /scratch, /home/proof, /tmp). MUST be opened with O_RDONLY |
   * O_NOATIME to preserve st_atime. Fails closed on any refusal.
   * 2. Immutable System Binaries:
   *    Files owned by system (st_uid != current UID) on verified ST_RDONLY
   * mounts. Kernel suppresses atime updates on MS_RDONLY mounts; reading has
   * zero atime source effect.
   */
  bool is_workload_artifact = (st.st_uid == (uid_t)getuid()) ||
                              (strncmp(exe_target, "/private/tmp", 12) == 0) ||
                              (strncmp(exe_target, "/scratch", 8) == 0) ||
                              (strncmp(exe_target, "/home/proof", 11) == 0) ||
                              (strncmp(exe_target, "/tmp", 4) == 0);

  int raw_fd = open(proc_exe, O_RDONLY | O_NOATIME | O_CLOEXEC);
  if (raw_fd < 0) {
    int open_err = errno;
    if (is_workload_artifact) {
      close(held_fd);
      g_failed = true;
      snprintf(g_failure_reason, sizeof(g_failure_reason),
               "O_NOATIME_FAILED_WORKLOAD_ARTIFACT_ERRNO_%d", open_err);
      fprintf(stderr,
              "hosted_exec_witness: fatal: open(O_NOATIME) refused on mutable "
              "workload output %s: %s\n",
              proc_exe, strerror(open_err));
      kill_all_tracees();
      return;
    }

    struct statvfs stfs;
    if (fstatvfs(held_fd, &stfs) == 0 && (stfs.f_flag & ST_RDONLY) &&
        (st.st_uid != (uid_t)getuid())) {
      raw_fd = open(proc_exe, O_RDONLY | O_CLOEXEC);
      if (raw_fd < 0) {
        int err = errno;
        close(held_fd);
        g_failed = true;
        snprintf(g_failure_reason, sizeof(g_failure_reason),
                 "SYSTEM_BINARY_OPEN_FAILED_ERRNO_%d", err);
        fprintf(
            stderr,
            "hosted_exec_witness: fatal: open failed on system binary %s: %s\n",
            proc_exe, strerror(err));
        kill_all_tracees();
        return;
      }
      is_immutable_system_binary = true;
    } else {
      close(held_fd);
      g_failed = true;
      snprintf(g_failure_reason, sizeof(g_failure_reason),
               "O_NOATIME_REFUSED_NON_RDONLY_MOUNT_ERRNO_%d", open_err);
      fprintf(stderr,
              "hosted_exec_witness: fatal: O_NOATIME refused and mount not "
              "verified ST_RDONLY for %s\n",
              proc_exe);
      kill_all_tracees();
      return;
    }
  }

  SHA256_CTX sha_ctx;
  sha256_init(&sha_ctx);
  uint8_t read_buf[16384];
  ssize_t bytes_n;

  int save_fd = -1;
  if (g_raw_capture_dir[0] != '\0' && !is_immutable_system_binary) {
    char save_path[PATH_MAX];
    snprintf(save_path, sizeof(save_path), "%s/%" PRIu64 "_%" PRIu64 ".bin",
             g_raw_capture_dir, (uint64_t)st.st_dev, (uint64_t)st.st_ino);
    /* Use O_CREAT | O_TRUNC to persist captured bytes safely */
    save_fd = open(save_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (save_fd < 0) {
      int err = errno;
      close(raw_fd);
      close(held_fd);
      g_failed = true;
      snprintf(g_failure_reason, sizeof(g_failure_reason),
               "RAW_PERSIST_OPEN_FAILED_ERRNO_%d", err);
      fprintf(stderr,
              "hosted_exec_witness: fatal: failed to create raw capture file "
              "%s: %s\n",
              save_path, strerror(err));
      kill_all_tracees();
      return;
    }
  }

  while ((bytes_n = read(raw_fd, read_buf, sizeof(read_buf))) > 0) {
    sha256_update(&sha_ctx, read_buf, (size_t)bytes_n);
    actual_bytes_captured += bytes_n;
    if (save_fd >= 0) {
      if (!write_all(save_fd, read_buf, (size_t)bytes_n)) {
        int err = errno;
        close(save_fd);
        close(raw_fd);
        close(held_fd);
        g_failed = true;
        snprintf(g_failure_reason, sizeof(g_failure_reason),
                 "RAW_PERSIST_WRITE_FAILED_ERRNO_%d", err);
        fprintf(
            stderr,
            "hosted_exec_witness: fatal: raw persistence write failed: %s\n",
            strerror(err));
        kill_all_tracees();
        return;
      }
    }
  }
  if (save_fd >= 0) {
    close(save_fd);
  }
  close(raw_fd);

  if (bytes_n < 0 || actual_bytes_captured <= 0) {
    close(held_fd);
    g_failed = true;
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "RAW_CAPTURE_EMPTY_OR_READ_ERROR");
    fprintf(stderr,
            "hosted_exec_witness: fatal: raw executable capture produced 0 "
            "bytes on %s\n",
            proc_exe);
    kill_all_tracees();
    return;
  }

  uint8_t digest[32];
  sha256_final(&sha_ctx, digest);
  for (int i = 0; i < 32; i++) {
    snprintf(sha256_hex + i * 2, 3, "%02x", digest[i]);
  }

  /* Register in captured executables table for deduplication */
  held_idx = (int)g_captured_exec_count;
  CapturedExecutable *ce = &g_captured_execs[g_captured_exec_count++];
  ce->st_dev = (uint64_t)st.st_dev;
  ce->st_ino = (uint64_t)st.st_ino;
  ce->st_ctime_ns = ctim_ns;
  ce->st_mtim_ns = mtim_ns;
  ce->st_size = actual_bytes_captured;
  strncpy(ce->sha256, sha256_hex, sizeof(ce->sha256) - 1);
  ce->held_fd = held_fd;
  ce->is_system_binary = is_immutable_system_binary;

emit_exec_record:;
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

  char buf[4096];
  snprintf(
      buf, sizeof(buf),
      "{\"event\":\"exec_success\",\"seq_id\":%" PRIu64
      ",\"timestamp_ns\":%" PRIu64 ",\"pid\":%d,\"ppid\":%d,\"exe_path\":\"%s\""
      ",\"st_dev\":%" PRIu64 ",\"st_ino\":%" PRIu64
      ",\"st_mode\":%u,\"st_size\":%" PRIi64 ",\"st_uid\":%u,\"st_gid\":%u"
      ",\"st_atim_ns\":%" PRIu64 ",\"st_mtim_ns\":%" PRIu64
      ",\"st_ctim_ns\":%" PRIu64
      ",\"held_fd_index\":%d,\"sha256\":\"%s\",\"size_bytes\":%" PRIi64
      ",\"raw_captured\":true,\"system_binary\":%s,\"deduplicated\":%s,"
      "\"cmdline\":%s}",
      seq, get_time_ns(), (int)pid, (int)ppid, escaped_path,
      (uint64_t)st.st_dev, (uint64_t)st.st_ino, (unsigned int)st.st_mode,
      (int64_t)st.st_size, (unsigned int)st.st_uid, (unsigned int)st.st_gid,
      atim_ns, mtim_ns, ctim_ns, held_idx, sha256_hex, actual_bytes_captured,
      is_immutable_system_binary ? "true" : "false",
      is_deduplicated ? "true" : "false", cmd_json);

  emit_evidence_record(buf);
  g_total_exec_events++;

  if (!is_immutable_system_binary && g_raw_capture_dir[0] != '\0') {
    char cap_buf[1024];
    char cap_file[128];
    snprintf(cap_file, sizeof(cap_file), "%" PRIu64 "_%" PRIu64 ".bin",
             (uint64_t)st.st_dev, (uint64_t)st.st_ino);
    snprintf(cap_buf, sizeof(cap_buf),
             "{\"event\":\"raw_exec_capture\",\"seq_id\":%" PRIu64
             ",\"timestamp_ns\":%" PRIu64 ",\"st_dev\":%" PRIu64
             ",\"st_ino\":%" PRIu64 ",\"exe_path\":\"%s\""
             ",\"size_bytes\":%" PRIi64
             ",\"sha256\":\"%s\",\"captured_file\":\"%s\",\"deduplicated\":%s}",
             seq, get_time_ns(), (uint64_t)st.st_dev, (uint64_t)st.st_ino,
             escaped_path, actual_bytes_captured, sha256_hex, cap_file,
             is_deduplicated ? "true" : "false");
    emit_evidence_record(cap_buf);
  }
}

static void handle_exit_event(pid_t pid) {
  unsigned long raw_status = 0;
  if (linux_ptrace(PTRACE_GETEVENTMSG, pid, 0, &raw_status) < 0) {
    int err = errno;
    g_failed = true;
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "GETEVENTMSG_EXIT_FAILED_PID_%d_ERRNO_%d", (int)pid, err);
    fprintf(
        stderr,
        "hosted_exec_witness: ptrace GETEVENTMSG exit failed on pid %d: %s\n",
        (int)pid, strerror(err));
    kill_all_tracees();
    return;
  }

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
#ifndef __linux__
  fprintf(stderr, "hosted_exec_witness: Fatal: non-Linux platforms are "
                  "strictly unsupported.\n");
  return 255;
#endif

  int evidence_fd = -1;
  const char *launch_binding = "{}";
  int cmd_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--evidence-fd") == 0 && i + 1 < argc) {
      evidence_fd = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--raw-capture-dir") == 0 && i + 1 < argc) {
      strncpy(g_raw_capture_dir, argv[++i], sizeof(g_raw_capture_dir) - 1);
    } else if (strcmp(argv[i], "--launch-binding") == 0 && i + 1 < argc) {
      launch_binding = argv[++i];
    } else if (strcmp(argv[i], "--") == 0) {
      cmd_index = i + 1;
      break;
    }
  }

  if (cmd_index < 0 || cmd_index >= argc || evidence_fd < 3) {
    fprintf(stderr,
            "Usage: %s --evidence-fd <FD>=3 [--raw-capture-dir <DIR>] "
            "[--launch-binding <JSON>] -- <CMD> [ARGS...]\n",
            argv[0]);
    fprintf(stderr, "Error: --evidence-fd >= 3 is strictly required to "
                    "guarantee private evidence channel.\n");
    return 2;
  }

  /* Set close-on-exec on evidence fd so child does NOT inherit it */
  int flags = fcntl(evidence_fd, F_GETFD);
  if (flags < 0) {
    fprintf(stderr, "hosted_exec_witness: invalid --evidence-fd %d: %s\n",
            evidence_fd, strerror(errno));
    return 2;
  }
  fcntl(evidence_fd, F_SETFD, flags | FD_CLOEXEC);
  g_evidence_fd = evidence_fd;

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

  /* Dedicated child stdio pipes so untrusted child stdout/stderr cannot reach
   * evidence channel */
  int child_out_pipe[2];
  int child_err_pipe[2];
#if defined(__linux__) && defined(O_CLOEXEC)
  if (pipe2(child_out_pipe, O_CLOEXEC) < 0 ||
      pipe2(child_err_pipe, O_CLOEXEC) < 0) {
#else
  if (pipe(child_out_pipe) < 0 || pipe(child_err_pipe) < 0) {
#endif
    fprintf(stderr, "hosted_exec_witness: child log pipe creation failed: %s\n",
            strerror(errno));
    snprintf(g_failure_reason, sizeof(g_failure_reason),
             "CHILD_PIPE_CREATION_FAILED");
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
    close(barrier_pipe[1]);
    close(child_out_pipe[0]);
    close(child_err_pipe[0]);

    /* Redirect child stdout/stderr to isolated pipes */
    dup2(child_out_pipe[1], STDOUT_FILENO);
    dup2(child_err_pipe[1], STDERR_FILENO);
    close(child_out_pipe[1]);
    close(child_err_pipe[1]);

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

    /* Signal parent that child is ready for ptrace options */
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
  close(barrier_pipe[0]);
  close(child_out_pipe[1]);
  close(child_err_pipe[1]);
  g_root_pid = child_pid;

  /* Set non-blocking on child read pipes */
  int f_out = fcntl(child_out_pipe[0], F_GETFL);
  if (f_out >= 0)
    fcntl(child_out_pipe[0], F_SETFL, f_out | O_NONBLOCK);
  int f_err = fcntl(child_err_pipe[0], F_GETFL);
  if (f_err >= 0)
    fcntl(child_err_pipe[0], F_SETFL, f_err | O_NONBLOCK);

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
    kill_all_tracees();
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
    kill_all_tracees();
    emit_session_end();
    return 1;
  }

  /* Register root process */
  add_process(child_pid, getpid(), 0, false, "initial");

  /* Release child by writing to barrier pipe and resuming it via PTRACE_SYSCALL
   */
  char go_byte = 'G';
  ssize_t w_bar = write(barrier_pipe[1], &go_byte, 1);
  (void)w_bar;
  close(barrier_pipe[1]);

  if (!resume_tracee(child_pid, 0)) {
    emit_session_end();
    return 1;
  }

/* Helper macro to drain child output pipes non-blockingly to host container
 * stderr */
#define DRAIN_CHILD_PIPES()                                                    \
  do {                                                                         \
    char log_buf[4096];                                                        \
    ssize_t n_log;                                                             \
    while ((n_log = read(child_out_pipe[0], log_buf, sizeof(log_buf))) > 0) {  \
      write_all(STDERR_FILENO, log_buf, (size_t)n_log);                        \
    }                                                                          \
    while ((n_log = read(child_err_pipe[0], log_buf, sizeof(log_buf))) > 0) {  \
      write_all(STDERR_FILENO, log_buf, (size_t)n_log);                        \
    }                                                                          \
  } while (0)

  /* Tracer event loop */
  while (g_active_processes > 0 && !g_failed) {
    DRAIN_CHILD_PIPES();

    int wait_status = 0;
    pid_t event_pid = waitpid(-1, &wait_status, __WALL);
    if (event_pid < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == ECHILD) {
        if (g_active_processes > 0) {
          g_failed = true;
          snprintf(g_failure_reason, sizeof(g_failure_reason),
                   "ECHILD_WITH_ACTIVE_TRACEES_%zu", g_active_processes);
          fprintf(stderr,
                  "hosted_exec_witness: fatal: ECHILD while %zu active tracees "
                  "remain unaccounted\n",
                  g_active_processes);
          kill_all_tracees();
        }
        break;
      }
      snprintf(g_failure_reason, sizeof(g_failure_reason), "WAITPID_ERROR_%d",
               errno);
      g_failed = true;
      kill_all_tracees();
      break;
    }

    ProcessEntry *proc = find_process(event_pid);

    if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status)) {
      if (proc != NULL && proc->active) {
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
        g_failed = true;
        snprintf(g_failure_reason, sizeof(g_failure_reason),
                 "UNACCOUNTED_CHILD_EXIT_PID_%d", (int)event_pid);
        fprintf(stderr,
                "hosted_exec_witness: fatal: unaccounted child %d exited\n",
                (int)event_pid);
        kill_all_tracees();
        break;
      }
      continue;
    }

    if (WIFSTOPPED(wait_status)) {
      int stop_sig = WSTOPSIG(wait_status);
      int event = (unsigned int)wait_status >> 16;

      if (proc == NULL) {
        g_failed = true;
        snprintf(g_failure_reason, sizeof(g_failure_reason),
                 "UNACCOUNTED_STOPPED_CHILD_%d", (int)event_pid);
        fprintf(stderr,
                "hosted_exec_witness: fatal: unaccounted stopped child %d "
                "(sig=%d)\n",
                (int)event_pid, stop_sig);
        kill_all_tracees();
        break;
      }

      if (stop_sig == SIGTRAP) {
        if (event == PTRACE_EVENT_EXEC) {
          handle_exec_event(event_pid);
          proc->in_syscall = false;
          resume_tracee(event_pid, 0);
          continue;
        } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                   event == PTRACE_EVENT_CLONE) {
          unsigned long new_child_pid = 0;
          if (linux_ptrace(PTRACE_GETEVENTMSG, event_pid, 0, &new_child_pid) <
              0) {
            int err = errno;
            g_failed = true;
            snprintf(g_failure_reason, sizeof(g_failure_reason),
                     "GETEVENTMSG_FORK_FAILED_PID_%d_ERRNO_%d", (int)event_pid,
                     err);
            fprintf(stderr,
                    "hosted_exec_witness: ptrace GETEVENTMSG failed on pid %d: "
                    "%s\n",
                    (int)event_pid, strerror(err));
            kill_all_tracees();
            break;
          }
          if (new_child_pid > 0) {
            bool is_thread = (event == PTRACE_EVENT_CLONE);
            const char *kind_str = (event == PTRACE_EVENT_FORK)    ? "fork"
                                   : (event == PTRACE_EVENT_VFORK) ? "vfork"
                                                                   : "clone";
            add_process((pid_t)new_child_pid, event_pid, proc->seq_id,
                        is_thread, kind_str);
          }
          resume_tracee(event_pid, 0);
          continue;
        } else if (event == PTRACE_EVENT_EXIT) {
          handle_exit_event(event_pid);
          resume_tracee(event_pid, 0);
          continue;
        } else {
          /* Genuine application SIGTRAP (e.g. debugger breakpoint int3),
           * forward it */
          resume_tracee(event_pid, SIGTRAP);
          continue;
        }
      } else if (stop_sig == SIGSTOP) {
        if (proc->initial_stop_pending) {
          proc->initial_stop_pending = false;
          resume_tracee(event_pid, 0);
        } else {
          /* Genuine workload SIGSTOP; forward */
          resume_tracee(event_pid, SIGSTOP);
        }
        continue;
      } else if (stop_sig == (SIGTRAP | 0x80)) {
        /* Syscall trap from PTRACE_O_TRACESYSGOOD */
        if (!proc->in_syscall) {
          proc->in_syscall = true;
          char violation[128] = {0};
          if (!check_syscall_entry(event_pid, violation, sizeof(violation))) {
            g_failed = true;
            snprintf(g_failure_reason, sizeof(g_failure_reason),
                     "SYSCALL_VIOLATION_%s", violation);
            fprintf(stderr,
                    "hosted_exec_witness: security violation on pid %d: %s\n",
                    (int)event_pid, violation);
            kill_all_tracees();
            break;
          }
        } else {
          proc->in_syscall = false;
        }
        resume_tracee(event_pid, 0);
        continue;
      } else {
        /* Genuine application signal; forward */
        resume_tracee(event_pid, stop_sig);
        continue;
      }
    }
  }

  DRAIN_CHILD_PIPES();
  close(child_out_pipe[0]);
  close(child_err_pipe[0]);

  emit_session_end();

  /* Close all held O_PATH descriptors */
  for (size_t i = 0; i < g_captured_exec_count; i++) {
    if (g_captured_execs[i].held_fd >= 0) {
      close(g_captured_execs[i].held_fd);
    }
  }

  if (g_evidence_fd >= 0) {
    close(g_evidence_fd);
  }

  return g_failed ? 1 : g_root_exit_code;
}
