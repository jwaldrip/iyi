// proof/bpf_canary_host.c
// Dedicated trusted host-side BPF tracer for successful-exec object identity.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/capability.h>
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;
#include <sys/prctl.h>
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif
#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif
#endif

#ifndef __linux__
#ifndef BPF_PROG_TYPE_TRACING
#define BPF_PROG_TYPE_TRACING 26
#endif
#ifndef BPF_LINK_TYPE_RAW_TRACEPOINT
#define BPF_LINK_TYPE_RAW_TRACEPOINT 1
#endif
#ifndef BPF_LINK_TYPE_TRACING
#define BPF_LINK_TYPE_TRACING 2
#endif
#ifndef BPF_TRACE_RAW_TP
#define BPF_TRACE_RAW_TP 24
#endif
#endif

#include "bpf_canary_types.h"

struct host_context {
  FILE *out_fp;
  uint64_t events_captured;
  uint64_t target_cgroup_id;
  int verbose;
};

struct probe_report {
  const char *status;
  bool load_supported;
  bool attach_supported;
  bool hook_identity_verified;
  bool link_association_verified;

  // Real queried kernel program metadata
  bool prog_info_valid;
  uint32_t prog_id;
  uint32_t prog_type;
  uint32_t btf_id;
  uint32_t attach_btf_id;
  char prog_name[16];
  uint8_t prog_tag[8];

  // Real queried kernel link metadata
  bool link_info_valid;
  uint32_t link_id;
  uint32_t link_type;
  uint32_t link_prog_id;
  char link_tp_name[64];
  char observed_hook_name[64];
  const char *observed_hook_kind;
  const char *requested_program_name;
  const char *requested_attach_target;
  const char *fd_ownership_lifecycle;

  uint64_t target_tgid;
  uid_t uid;
  gid_t gid;
  bool cap_bpf;
  bool cap_perfmon;
  bool cap_sys_admin;
  bool all_other_caps_clear;

  // Section 6 & 7: Verified privilege sets and identity evidence
  uid_t ruid;
  uid_t euid;
  uid_t suid;
  gid_t rgid;
  gid_t egid;
  gid_t sgid;
  int supplementary_groups_count;
  bool no_new_privs;
  uint64_t cap_effective;
  uint64_t cap_permitted;
  uint64_t cap_inheritable;
  uint64_t cap_bounding;
  uint64_t cap_ambient;
  bool caps_strictly_bpf_perfmon;

  // Section 6: Libbpf memlock opt-out evidence
  bool memlock_rlim_disabled;

  // Section 6: Successful-load verifier logging evidence
  bool verifier_log_valid;
  size_t verifier_log_bytes;
  char verifier_conclusion[256];
  const char *verifier_log_path;
  const char *verifier_log_content;

  // Section 6: CO-RE relocation evidence
  bool core_relocation_retained;
  size_t libbpf_debug_log_bytes;
  const char *libbpf_debug_log_path;
  const char *libbpf_debug_log_content;

  const char *error_message;
};

static volatile sig_atomic_t stop_requested = 0;
static void sig_handler(int sig) {
  (void)sig;
  stop_requested = 1;
}

static FILE *safe_open_file(const char *path, bool append,
                            const char **err_out) {
  if (!path)
    return NULL;

  int flags = O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC;
  if (append) {
    flags |= O_APPEND;
  } else {
    flags |= O_TRUNC;
  }

  int fd = open(path, flags, 0600);
  if (fd < 0) {
    *err_out = strerror(errno);
    return NULL;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    *err_out = "Target path is not a regular file";
    return NULL;
  }

  FILE *fp = fdopen(fd, append ? "a" : "w");
  if (!fp) {
    *err_out = strerror(errno);
    close(fd);
    return NULL;
  }
  return fp;
}

static int safe_touch_ready_file(const char *ready_path) {
  if (!ready_path)
    return 0;

  int fd = open(ready_path,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    perror("[bpf_canary_host] Failed to create ready file");
    return -1;
  }
  const char msg[] = "READY\n";
  ssize_t written = write(fd, msg, sizeof(msg) - 1);
  close(fd);
  return (written == sizeof(msg) - 1) ? 0 : -1;
}

static int safe_write_pid_file(const char *pid_path) {
  if (!pid_path)
    return 0;

  int fd = open(pid_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0600);
  if (fd < 0) {
    perror("[bpf_canary_host] Failed to create pid file");
    return -1;
  }
  char buf[32];
  int len = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
  ssize_t written = write(fd, buf, len);
  close(fd);
  return (written == len) ? 0 : -1;
}

#ifdef __linux__
static char g_libbpf_debug_log[131072];
static size_t g_libbpf_debug_log_len = 0;
static bool g_core_relocation_seen = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  (void)level;
  va_list args_copy;
  va_copy(args_copy, args);

  if (g_libbpf_debug_log_len < sizeof(g_libbpf_debug_log) - 1) {
    int written = vsnprintf(g_libbpf_debug_log + g_libbpf_debug_log_len,
                            sizeof(g_libbpf_debug_log) - g_libbpf_debug_log_len,
                            format, args_copy);
    if (written > 0) {
      g_libbpf_debug_log_len += (size_t)written;
      if (g_libbpf_debug_log_len >= sizeof(g_libbpf_debug_log)) {
        g_libbpf_debug_log_len = sizeof(g_libbpf_debug_log) - 1;
      }
    }
  }
  va_end(args_copy);

  if (format &&
      (strstr(format, "relo") != NULL || strstr(format, "CO-RE") != NULL ||
       strstr(format, "relocation") != NULL)) {
    g_core_relocation_seen = true;
  }

  // Section 6: Retain libbpf relocation/debug output to stderr unconditionally
  return vfprintf(stderr, format, args);
}

/*
 * Verify genuinely restricted observer privileges:
 * 1. Reject UID 0 (root) in real, effective, or saved UID.
 * 2. Reject GID 0 (root) in real, effective, or saved GID.
 * 3. Require empty supplementary groups (count == 0).
 * 4. Verify PR_SET_NO_NEW_PRIVS is active.
 * 5. Effective, permitted, inheritable, ambient, and bounding sets strictly
 *    restricted to CAP_PERFMON (bit 38) and CAP_BPF (bit 39).
 *    Expected mask is 000000c000000000.
 */
static int verify_restricted_privileges(int verbose, struct probe_report *r) {
  uid_t ruid = 0, euid = 0, suid = 0;
  gid_t rgid = 0, egid = 0, sgid = 0;

  if (getresuid(&ruid, &euid, &suid) != 0) {
    perror("[bpf_canary_host] getresuid failed");
    return -1;
  }
  if (getresgid(&rgid, &egid, &sgid) != 0) {
    perror("[bpf_canary_host] getresgid failed");
    return -1;
  }

  r->uid = euid;
  r->gid = egid;
  r->ruid = ruid;
  r->euid = euid;
  r->suid = suid;
  r->rgid = rgid;
  r->egid = egid;
  r->sgid = sgid;

  // Reject UID 0 (root) in any identity (real, effective, saved)
  if (ruid == 0 || euid == 0 || suid == 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Refusing to execute with root UID "
            "(ruid=%u, euid=%u, suid=%u). "
            "Must run under an unprivileged user.\n",
            ruid, euid, suid);
    return -1;
  }

  // Reject GID 0 (root) in any identity (real, effective, saved)
  if (rgid == 0 || egid == 0 || sgid == 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Refusing to execute with root GID "
            "(rgid=%u, egid=%u, sgid=%u).\n",
            rgid, egid, sgid);
    return -1;
  }

  // Require empty supplementary groups (--clear-groups)
  int n_groups = getgroups(0, NULL);
  r->supplementary_groups_count = n_groups;
  if (n_groups < 0) {
    perror("[bpf_canary_host] getgroups failed");
    return -1;
  }
  if (n_groups > 0) {
    fprintf(
        stderr,
        "[bpf_canary_host] ERROR: Supplementary groups not empty (count=%d). "
        "setpriv must clear all supplementary groups.\n",
        n_groups);
    return -1;
  }

  // Verify PR_SET_NO_NEW_PRIVS is active
  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: PR_SET_NO_NEW_PRIVS is not active\n");
    return -1;
  }
  r->no_new_privs = true;

  // Query capability sets via capget
  struct __user_cap_header_struct hdr = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[2];
  memset(data, 0, sizeof(data));

  if (syscall(SYS_capget, &hdr, data) != 0) {
    perror("[bpf_canary_host] capget failed");
    return -1;
  }

  uint64_t cap_eff =
      ((uint64_t)data[1].effective << 32) | (uint64_t)data[0].effective;
  uint64_t cap_prm =
      ((uint64_t)data[1].permitted << 32) | (uint64_t)data[0].permitted;
  uint64_t cap_inh =
      ((uint64_t)data[1].inheritable << 32) | (uint64_t)data[0].inheritable;

  // Query bounding set
  uint64_t cap_bnd = 0;
  for (int cap = 0; cap <= 63; cap++) {
    int ret = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (ret < 0) {
      break;
    }
    if (ret == 1) {
      cap_bnd |= (1ULL << cap);
    }
  }

  // Query ambient set
  uint64_t cap_amb = 0;
  for (int cap = 0; cap <= 63; cap++) {
    int ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
    if (ret < 0) {
      break;
    }
    if (ret == 1) {
      cap_amb |= (1ULL << cap);
    }
  }

  const uint64_t expected_mask =
      (1ULL << 38) | (1ULL << 39); // 0x000000c000000000ULL

  r->cap_effective = cap_eff;
  r->cap_permitted = cap_prm;
  r->cap_inheritable = cap_inh;
  r->cap_bounding = cap_bnd;
  r->cap_ambient = cap_amb;

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Capability sets:\n"
            "  Effective:   0x%016llx\n"
            "  Permitted:   0x%016llx\n"
            "  Inheritable: 0x%016llx\n"
            "  Bounding:    0x%016llx\n"
            "  Ambient:     0x%016llx\n"
            "  Expected:    0x%016llx\n",
            (unsigned long long)cap_eff, (unsigned long long)cap_prm,
            (unsigned long long)cap_inh, (unsigned long long)cap_bnd,
            (unsigned long long)cap_amb, (unsigned long long)expected_mask);
  }

  // Reject any capability outside {CAP_PERFMON (bit 38), CAP_BPF (bit 39)} in
  // ANY set
  if ((cap_eff & ~expected_mask) != 0 || (cap_prm & ~expected_mask) != 0 ||
      (cap_inh & ~expected_mask) != 0 || (cap_bnd & ~expected_mask) != 0 ||
      (cap_amb & ~expected_mask) != 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Capabilities outside approved set "
            "{CAP_BPF, CAP_PERFMON} in sets:\n"
            "  Eff: 0x%016llx  Prm: 0x%016llx  Inh: 0x%016llx  Bnd: 0x%016llx  "
            "Amb: 0x%016llx\n",
            (unsigned long long)cap_eff, (unsigned long long)cap_prm,
            (unsigned long long)cap_inh, (unsigned long long)cap_bnd,
            (unsigned long long)cap_amb);
    return -1;
  }

  // Ensure CAP_BPF and CAP_PERFMON are present in permitted set
  if ((cap_prm & expected_mask) != expected_mask) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Missing required scoped capabilities "
            "CAP_BPF / CAP_PERFMON in permitted set: prm=0x%016llx\n",
            (unsigned long long)cap_prm);
    return -1;
  }

  // Raise permitted capabilities to effective if not already set
  if ((cap_eff & expected_mask) != expected_mask) {
    data[1].effective = (uint32_t)(expected_mask >> 32);
    data[0].effective = (uint32_t)(expected_mask & 0xffffffff);
    if (syscall(SYS_capset, &hdr, data) != 0) {
      perror("[bpf_canary_host] capset failed raising permitted to effective");
      return -1;
    }
    cap_eff = ((uint64_t)data[1].effective << 32) | (uint64_t)data[0].effective;
    r->cap_effective = cap_eff;
  }

  if (cap_eff != expected_mask) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Effective capabilities mismatch: "
            "0x%016llx != 0x%016llx\n",
            (unsigned long long)cap_eff, (unsigned long long)expected_mask);
    return -1;
  }

  r->cap_bpf = ((cap_eff & (1ULL << 39)) != 0);
  r->cap_perfmon = ((cap_eff & (1ULL << 38)) != 0);
  r->cap_sys_admin = ((cap_eff & (1ULL << 21)) != 0);
  r->all_other_caps_clear =
      ((cap_eff & ~expected_mask) == 0 && (cap_prm & ~expected_mask) == 0 &&
       (cap_inh & ~expected_mask) == 0 && (cap_bnd & ~expected_mask) == 0 &&
       (cap_amb & ~expected_mask) == 0);
  r->caps_strictly_bpf_perfmon = true;

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Verified restricted observer privileges: UID=%u "
            "GID=%u groups=0 "
            "Caps=0x%016llx (CAP_BPF=1, CAP_PERFMON=1, CAP_SYS_ADMIN=0, "
            "no_new_privs=1)\n",
            r->uid, r->gid, (unsigned long long)cap_eff);
  }
  return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  struct host_context *c = (struct host_context *)ctx;
  if (data_sz < sizeof(struct exec_event)) {
    fprintf(stderr, "[bpf_canary_host] Short event received: %zu < %zu\n",
            data_sz, sizeof(struct exec_event));
    return 0;
  }

  const struct exec_event *e = (const struct exec_event *)data;
  c->events_captured++;

  if (c->out_fp) {
    char comm_buf[32];
    size_t len = 0;
    for (size_t i = 0; i < sizeof(e->comm) && e->comm[i]; i++) {
      char ch = e->comm[i];
      if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\') {
        comm_buf[len++] = ch;
      } else {
        comm_buf[len++] = '_';
      }
    }
    comm_buf[len] = '\0';

    fprintf(c->out_fp,
            "{\"cgroup_id\":%llu,\"dev\":%llu,\"inode\":%llu,"
            "\"pid\":%u,"
            "\"tgid\":%u,\"comm\":\"%s\"}\n",
            (unsigned long long)e->cgroup_id, (unsigned long long)e->dev,
            (unsigned long long)e->inode, e->pid, e->tgid, comm_buf);
    fflush(c->out_fp);
  }
  return 0;
}
#endif

static void sanitize_json_str(char *dst, size_t dst_sz, const char *src) {
  if (!dst || dst_sz == 0)
    return;
  dst[0] = '\0';
  if (!src)
    return;
  size_t d = 0;
  for (size_t s = 0; src[s] != '\0' && d + 1 < dst_sz; s++) {
    char c = src[s];
    if (c == '"' || c == '\\') {
      if (d + 2 < dst_sz) {
        dst[d++] = '\\';
        dst[d++] = c;
      } else {
        break;
      }
    } else if (c >= 32 && c <= 126) {
      dst[d++] = c;
    } else if (c == '\n' || c == '\r' || c == '\t') {
      dst[d++] = ' ';
    }
  }
  dst[d] = '\0';
}

static int write_probe_report(const char *path, struct probe_report *r) {
  if (!path)
    return -1;

  char auto_vlog_path[1024] = {0};
  char auto_llog_path[1024] = {0};

  // If companion log content is present and no explicit path was set, derive
  // companion paths
  if (r->verifier_log_content && r->verifier_log_bytes > 0 &&
      !r->verifier_log_path) {
    snprintf(auto_vlog_path, sizeof(auto_vlog_path), "%s.verifier.log", path);
    r->verifier_log_path = auto_vlog_path;
  }
  if (r->libbpf_debug_log_content && r->libbpf_debug_log_bytes > 0 &&
      !r->libbpf_debug_log_path) {
    snprintf(auto_llog_path, sizeof(auto_llog_path), "%s.libbpf.log", path);
    r->libbpf_debug_log_path = auto_llog_path;
  }

  // Write verifier log if path and content are present
  if (r->verifier_log_path && r->verifier_log_content &&
      r->verifier_log_bytes > 0) {
    const char *err_v = NULL;
    FILE *vf = safe_open_file(r->verifier_log_path, false, &err_v);
    if (vf) {
      fwrite(r->verifier_log_content, 1, r->verifier_log_bytes, vf);
      fclose(vf);
    }
  }

  // Write libbpf debug log if path and content are present
  if (r->libbpf_debug_log_path && r->libbpf_debug_log_content &&
      r->libbpf_debug_log_bytes > 0) {
    const char *err_l = NULL;
    FILE *lf = safe_open_file(r->libbpf_debug_log_path, false, &err_l);
    if (lf) {
      fwrite(r->libbpf_debug_log_content, 1, r->libbpf_debug_log_bytes, lf);
      fclose(lf);
    }
  }

  const char *err_open = NULL;
  FILE *sf = safe_open_file(path, false, &err_open);
  if (!sf) {
    fprintf(stderr,
            "[bpf_canary_host] Failed to open status file safely (%s): %s\n",
            path, err_open ? err_open : "unknown");
    return -1;
  }

  char sanitized_err[512] = {0};
  if (r->error_message) {
    sanitize_json_str(sanitized_err, sizeof(sanitized_err), r->error_message);
  }

  fprintf(sf, "{\n");
  fprintf(sf, "  \"status\": \"%s\",\n", r->status);
  fprintf(sf, "  \"strict_eligible\": false,\n");
  fprintf(sf, "  \"exec_identity_tested\": false,\n");
  fprintf(sf, "  \"bpf_load_supported\": %s,\n",
          r->load_supported ? "true" : "false");
  fprintf(sf, "  \"bpf_attach_supported\": %s,\n",
          r->attach_supported ? "true" : "false");
  fprintf(sf, "  \"hook_identity_verified\": %s,\n",
          r->hook_identity_verified ? "true" : "false");
  fprintf(sf, "  \"link_association_verified\": %s,\n",
          r->link_association_verified ? "true" : "false");
  fprintf(sf, "  \"requested_program_name\": \"%s\",\n",
          r->requested_program_name ? r->requested_program_name : "null");
  fprintf(sf, "  \"requested_attach_target\": \"%s\",\n",
          r->requested_attach_target ? r->requested_attach_target : "null");
  fprintf(sf, "  \"fd_ownership_lifecycle\": \"%s\",\n",
          r->fd_ownership_lifecycle);

  if (r->prog_info_valid) {
    char tag_hex[17];
    for (int i = 0; i < 8; i++) {
      snprintf(tag_hex + i * 2, 3, "%02x", r->prog_tag[i]);
    }
    tag_hex[16] = '\0';
    fprintf(sf, "  \"observed_kernel_prog\": {\n");
    fprintf(sf, "    \"prog_id\": %u,\n", r->prog_id);
    fprintf(sf, "    \"prog_type\": %u,\n", r->prog_type);
    fprintf(sf, "    \"prog_name\": \"%s\",\n", r->prog_name);
    fprintf(sf, "    \"btf_id\": %u,\n", r->btf_id);
    fprintf(sf, "    \"attach_btf_id\": %u,\n", r->attach_btf_id);
    fprintf(sf, "    \"tag\": \"%s\"\n", tag_hex);
    fprintf(sf, "  },\n");
  } else {
    fprintf(sf, "  \"observed_kernel_prog\": null,\n");
  }

  if (r->link_info_valid) {
    fprintf(sf, "  \"observed_kernel_link\": {\n");
    fprintf(sf, "    \"link_id\": %u,\n", r->link_id);
    fprintf(sf, "    \"link_type\": %u,\n", r->link_type);
    fprintf(sf, "    \"link_type_name\": \"BPF_LINK_TYPE_RAW_TRACEPOINT\",\n");
    fprintf(sf, "    \"link_prog_id\": %u,\n", r->link_prog_id);
    fprintf(sf, "    \"link_tp_name\": \"%s\",\n",
            r->link_tp_name[0] ? r->link_tp_name : "null");
    fprintf(sf, "    \"target_hook_name\": \"%s\",\n",
            r->observed_hook_name[0] ? r->observed_hook_name : "null");
    fprintf(sf, "    \"target_hook_kind\": \"%s\"\n",
            r->observed_hook_kind ? r->observed_hook_kind : "null");
    fprintf(sf, "  },\n");
  } else {
    fprintf(sf, "  \"observed_kernel_link\": null,\n");
  }

  fprintf(sf, "  \"target_tgid\": %llu,\n", (unsigned long long)r->target_tgid);
  fprintf(sf, "  \"process_identity\": {\n");
  fprintf(sf, "    \"uid\": %u,\n", (unsigned int)r->uid);
  fprintf(sf, "    \"gid\": %u,\n", (unsigned int)r->gid);
  fprintf(sf, "    \"ruid\": %u,\n", (unsigned int)r->ruid);
  fprintf(sf, "    \"euid\": %u,\n", (unsigned int)r->euid);
  fprintf(sf, "    \"suid\": %u,\n", (unsigned int)r->suid);
  fprintf(sf, "    \"rgid\": %u,\n", (unsigned int)r->rgid);
  fprintf(sf, "    \"egid\": %u,\n", (unsigned int)r->egid);
  fprintf(sf, "    \"sgid\": %u,\n", (unsigned int)r->sgid);
  fprintf(sf, "    \"supplementary_groups_count\": %d\n",
          r->supplementary_groups_count);
  fprintf(sf, "  },\n");
  fprintf(sf, "  \"capabilities\": {\n");
  fprintf(sf, "    \"cap_bpf\": %s,\n", r->cap_bpf ? "true" : "false");
  fprintf(sf, "    \"cap_perfmon\": %s,\n", r->cap_perfmon ? "true" : "false");
  fprintf(sf, "    \"cap_sys_admin\": %s,\n",
          r->cap_sys_admin ? "true" : "false");
  fprintf(sf, "    \"all_other_caps_clear\": %s,\n",
          r->all_other_caps_clear ? "true" : "false");
  fprintf(sf, "    \"effective_mask\": \"%016llx\",\n",
          (unsigned long long)r->cap_effective);
  fprintf(sf, "    \"permitted_mask\": \"%016llx\",\n",
          (unsigned long long)r->cap_permitted);
  fprintf(sf, "    \"inheritable_mask\": \"%016llx\",\n",
          (unsigned long long)r->cap_inheritable);
  fprintf(sf, "    \"bounding_mask\": \"%016llx\",\n",
          (unsigned long long)r->cap_bounding);
  fprintf(sf, "    \"ambient_mask\": \"%016llx\",\n",
          (unsigned long long)r->cap_ambient);
  fprintf(sf, "    \"expected_mask\": \"000000c000000000\",\n");
  fprintf(sf, "    \"no_new_privs\": %s\n", r->no_new_privs ? "true" : "false");
  fprintf(sf, "  },\n");
  fprintf(sf, "  \"memlock\": {\n");
  fprintf(sf, "    \"automatic_rlim_disabled\": %s\n",
          r->memlock_rlim_disabled ? "true" : "false");
  fprintf(sf, "  },\n");
  fprintf(sf, "  \"verifier_evidence\": {\n");
  fprintf(sf, "    \"log_valid\": %s,\n",
          r->verifier_log_valid ? "true" : "false");
  fprintf(sf, "    \"log_bytes\": %zu,\n", r->verifier_log_bytes);
  fprintf(sf, "    \"conclusion\": %s%s%s,\n",
          r->verifier_conclusion[0] ? "\"" : "",
          r->verifier_conclusion[0] ? r->verifier_conclusion : "null",
          r->verifier_conclusion[0] ? "\"" : "");
  fprintf(sf, "    \"log_file\": %s%s%s\n", r->verifier_log_path ? "\"" : "",
          r->verifier_log_path ? r->verifier_log_path : "null",
          r->verifier_log_path ? "\"" : "");
  fprintf(sf, "  },\n");
  fprintf(sf, "  \"relocation_evidence\": {\n");
  fprintf(sf, "    \"core_relocation_retained\": %s,\n",
          r->core_relocation_retained ? "true" : "false");
  fprintf(sf, "    \"libbpf_debug_log_bytes\": %zu,\n",
          r->libbpf_debug_log_bytes);
  fprintf(sf, "    \"log_file\": %s%s%s\n",
          r->libbpf_debug_log_path ? "\"" : "",
          r->libbpf_debug_log_path ? r->libbpf_debug_log_path : "null",
          r->libbpf_debug_log_path ? "\"" : "");
  fprintf(sf, "  },\n");
  if (r->error_message) {
    fprintf(sf, "  \"error_message\": \"%s\"\n", sanitized_err);
  } else {
    fprintf(sf, "  \"error_message\": null\n");
  }
  fprintf(sf, "}\n");

  if (fflush(sf) != 0 || fclose(sf) != 0) {
    fprintf(stderr, "[bpf_canary_host] Failed to flush or close status file\n");
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  uint64_t target_cgroup_id = 0;
  const char *out_path = NULL;
  const char *status_path = NULL;
  const char *ready_path = NULL;
  const char *pid_path = NULL;
  const char *bpf_obj_path = "proof/bpf_canary.bpf.o";
  const char *verifier_log_path = NULL;
  const char *libbpf_log_path = NULL;
  int probe_only = 0;
  int sim_loss = 0;
  int verbose = 0;
  int duration = 0;

  static struct option long_options[] = {
      {"cgroup-id", required_argument, 0, 'c'},
      {"output", required_argument, 0, 'o'},
      {"status", required_argument, 0, 's'},
      {"ready-file", required_argument, 0, 'r'},
      {"pid-file", required_argument, 0, 'P'},
      {"bpf-obj", required_argument, 0, 'b'},
      {"probe-only", no_argument, 0, 'p'},
      {"sim-loss", no_argument, 0, 'l'},
      {"duration", required_argument, 0, 'd'},
      {"verbose", no_argument, 0, 'v'},
      {"verifier-log", required_argument, 0, 'V'},
      {"libbpf-log", required_argument, 0, 'L'},
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "c:o:s:r:P:b:pld:vV:L:", long_options,
                            NULL)) != -1) {
    switch (opt) {
    case 'c':
      target_cgroup_id = strtoull(optarg, NULL, 0);
      break;
    case 'o':
      out_path = optarg;
      break;
    case 's':
      status_path = optarg;
      break;
    case 'r':
      ready_path = optarg;
      break;
    case 'P':
      pid_path = optarg;
      break;
    case 'b':
      bpf_obj_path = optarg;
      break;
    case 'p':
      probe_only = 1;
      break;
    case 'l':
      sim_loss = 1;
      break;
    case 'd':
      duration = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'V':
      verifier_log_path = optarg;
      break;
    case 'L':
      libbpf_log_path = optarg;
      break;
    default:
      fprintf(stderr,
              "Usage: %s [--cgroup-id <id>] [--output <file>] "
              "[--status <file>] "
              "[--ready-file <file>] [--pid-file <file>] "
              "[--bpf-obj <path>] "
              "[--probe-only] [--sim-loss] [--duration <sec>] "
              "[--verbose] [--verifier-log <file>] [--libbpf-log <file>]\n",
              argv[0]);
      return 1;
    }
  }
  // Missing --status must fail
  if (!status_path) {
    fprintf(stderr, "[bpf_canary_host] ERROR: --status <path> is required\n");
    return 1;
  }

#ifndef __linux__
  fprintf(stderr, "[bpf_canary_host] Linux kernel BPF required. "
                  "Not supported on host "
                  "platform.\n");
  struct probe_report unsupp_rep;
  memset(&unsupp_rep, 0, sizeof(unsupp_rep));
  unsupp_rep.status = "UNSUPPORTED_PLATFORM";
  unsupp_rep.fd_ownership_lifecycle = "unattached";
  unsupp_rep.error_message = "Non-Linux platform";
  write_probe_report(status_path, &unsupp_rep);
  return 1;
#else
  if (probe_only) {
    // In foreground diagnostic mode: retain/restore default signal disposition
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
  } else {
    // In polling tracer mode: install signal handler for clean graceful stop
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
  }

  libbpf_set_print(libbpf_print_fn);

  struct probe_report rep;
  memset(&rep, 0, sizeof(rep));
  rep.status = "UNINITIALIZED";
  rep.requested_program_name = "sched_process_exec";
  rep.requested_attach_target = "tp_btf/sched_process_exec";
  rep.fd_ownership_lifecycle = "unattached";

  // 1. Verify restricted capabilities: reject root UID 0 and caps outside
  // approved set
  if (verify_restricted_privileges(verbose, &rep) != 0) {
    rep.status = "PRIVILEGE_RESTRICTION_FAILED";
    rep.error_message = "Failed privilege restriction check: nonroot identity, "
                        "empty groups, or BPF/PERFMON caps required";
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Section 6: Disable automatic memlock-limit adjustment with
  // libbpf_set_memlock_rlim(0) before loading
  int rlim_res = libbpf_set_memlock_rlim(0);
  if (rlim_res != 0) {
    int m_err = -errno;
    fprintf(
        stderr,
        "[bpf_canary_host] ERROR: libbpf_set_memlock_rlim(0) failed: %s (%d)\n",
        strerror(-m_err), m_err);
    rep.status = "MEMLOCK_RLIM_FAILED";
    rep.error_message = "libbpf_set_memlock_rlim(0) failed to disable "
                        "automatic limit adjustment";
    write_probe_report(status_path, &rep);
    return 1;
  }
  rep.memlock_rlim_disabled = true;
  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Disabled libbpf automatic memlock adjustment\n");
  }

  // 2. Open BPF object with logging options (Section 6: Requests verifier
  // logging for successful loads)
  static char g_verifier_log_buf[131072];
  memset(g_verifier_log_buf, 0, sizeof(g_verifier_log_buf));

  struct bpf_object_open_opts open_opts;
  memset(&open_opts, 0, sizeof(open_opts));
  open_opts.sz = sizeof(open_opts);
  open_opts.kernel_log_level = 1;
  open_opts.kernel_log_buf = g_verifier_log_buf;
  open_opts.kernel_log_size = sizeof(g_verifier_log_buf);

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Opening BPF object: %s (kernel_log_level=1, "
            "buf_sz=%zu)\n",
            bpf_obj_path, sizeof(g_verifier_log_buf));
  }

  struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, &open_opts);
  if (!obj) {
    int err = -errno;
    fprintf(stderr, "[bpf_canary_host] bpf_object__open_file failed: %s (%d)\n",
            strerror(-err), err);
    rep.status = "OPEN_FAILED";
    rep.error_message = strerror(-err);
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Locate program before load to ensure explicit log level and buffer
  // configuration
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "sched_process_exec");
  if (!prog) {
    fprintf(stderr, "[bpf_canary_host] Program sched_process_exec not found\n");
    rep.status = "PROGRAM_MISSING";
    rep.error_message = "sched_process_exec missing in BPF object";
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  bpf_program__set_log_level(prog, 1);
  bpf_program__set_log_buf(prog, g_verifier_log_buf,
                           sizeof(g_verifier_log_buf));

  // 3. Load BPF object into kernel FIRST before accessing map FDs
  if (verbose) {
    fprintf(stderr, "[bpf_canary_host] Loading BPF object into kernel under "
                    "restricted capabilities...\n");
  }

  int err = bpf_object__load(obj);
  if (err) {
    int load_err = -errno;
    fprintf(stderr, "[bpf_canary_host] bpf_object__load failed: %s (%d)\n",
            strerror(-load_err), load_err);
    // Section 6: Libbpf also performs internal feature probes. A failure before
    // the intended program's load must be reported at that stage, without
    // claiming the typed program itself was rejected.
    if (g_verifier_log_buf[0] == '\0') {
      rep.status = "FEATURE_PROBE_OR_PRECHECK_FAILED";
      rep.error_message = "Failure occurred before typed program verifier load "
                          "(feature probe, BTF, or map error)";
    } else {
      rep.status = "LOAD_FAILED";
      rep.error_message = strerror(-load_err);
    }
    rep.verifier_log_content = g_verifier_log_buf;
    rep.verifier_log_bytes = strlen(g_verifier_log_buf);
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  rep.load_supported = true;

  // Section 6: Treat missing/truncated required logs as incomplete evidence
  const char *vlog = g_verifier_log_buf;
  if (vlog[0] == '\0') {
    size_t plog_sz = 0;
    const char *plog = bpf_program__log_buf(prog, &plog_sz);
    if (plog && plog[0] != '\0') {
      vlog = plog;
    }
  }

  if (vlog[0] == '\0') {
    fprintf(
        stderr,
        "[bpf_canary_host] ERROR: Successful load verifier log is missing\n");
    rep.status = "VERIFIER_LOG_MISSING";
    rep.error_message = "Required kernel verifier log is missing after load";
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  size_t vlog_len = strlen(vlog);
  if (vlog_len >= sizeof(g_verifier_log_buf) - 1) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Verifier log was truncated (%zu bytes)\n",
            vlog_len);
    rep.status = "VERIFIER_LOG_TRUNCATED";
    rep.error_message = "Kernel verifier log was truncated";
    rep.verifier_log_content = vlog;
    rep.verifier_log_bytes = vlog_len;
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  const char *proc_line = strstr(vlog, "processed ");
  if (!proc_line) {
    fprintf(stderr, "[bpf_canary_host] ERROR: Verifier log conclusion "
                    "('processed ') not found\n");
    rep.status = "VERIFIER_LOG_INCOMPLETE";
    rep.error_message =
        "Kernel verifier log incomplete (missing verifier conclusion)";
    rep.verifier_log_content = vlog;
    rep.verifier_log_bytes = vlog_len;
    rep.libbpf_debug_log_content = g_libbpf_debug_log;
    rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  rep.verifier_log_valid = true;
  rep.verifier_log_bytes = vlog_len;
  rep.verifier_log_content = vlog;
  const char *nl = strchr(proc_line, '\n');
  size_t line_len = nl ? (size_t)(nl - proc_line) : strlen(proc_line);
  if (line_len >= sizeof(rep.verifier_conclusion)) {
    line_len = sizeof(rep.verifier_conclusion) - 1;
  }
  for (size_t i = 0; i < line_len; i++) {
    char ch = proc_line[i];
    if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\') {
      rep.verifier_conclusion[i] = ch;
    } else {
      rep.verifier_conclusion[i] = ' ';
    }
  }
  rep.verifier_conclusion[line_len] = '\0';

  rep.core_relocation_retained = g_core_relocation_seen;
  rep.libbpf_debug_log_bytes = g_libbpf_debug_log_len;
  rep.libbpf_debug_log_content = g_libbpf_debug_log;
  rep.verifier_log_path = verifier_log_path;
  rep.libbpf_debug_log_path = libbpf_log_path;

  if (verbose) {
    fprintf(stderr, "[bpf_canary_host] Verifier log captured (%zu bytes): %s\n",
            vlog_len, rep.verifier_conclusion);
  }

  int prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "[bpf_canary_host] Invalid program fd: %d\n", prog_fd);
    rep.status = "PROG_FD_INVALID";
    rep.error_message = "Invalid program fd after load";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  struct bpf_prog_info pinfo;
  memset(&pinfo, 0, sizeof(pinfo));
  __u32 pinfo_len = sizeof(pinfo);
  if (bpf_obj_get_info_by_fd(prog_fd, &pinfo, &pinfo_len) != 0) {
    int info_err = -errno;
    fprintf(
        stderr,
        "[bpf_canary_host] bpf_obj_get_info_by_fd for prog failed: %s (%d)\n",
        strerror(-info_err), info_err);
    rep.status = "PROG_INFO_FAILED";
    rep.error_message =
        "Failed to query kernel program info via bpf_obj_get_info_by_fd";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Validate program type: MUST be BPF_PROG_TYPE_TRACING (26)
  if (pinfo.type != BPF_PROG_TYPE_TRACING) {
    fprintf(stderr,
            "[bpf_canary_host] Program type mismatch: expected "
            "BPF_PROG_TYPE_TRACING (%d), got %u\n",
            BPF_PROG_TYPE_TRACING, pinfo.type);
    rep.status = "PROG_TYPE_MISMATCH";
    rep.error_message = "Kernel program type is not BPF_PROG_TYPE_TRACING";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  if (pinfo.id == 0) {
    fprintf(stderr, "[bpf_canary_host] Invalid kernel program id: 0\n");
    rep.status = "PROG_ID_INVALID";
    rep.error_message = "Kernel returned program id 0";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  rep.prog_info_valid = true;
  rep.prog_id = pinfo.id;
  rep.prog_type = pinfo.type;
  rep.btf_id = pinfo.btf_id;
  rep.attach_btf_id = pinfo.attach_btf_id;
  memcpy(rep.prog_name, pinfo.name, sizeof(rep.prog_name) - 1);
  rep.prog_name[sizeof(rep.prog_name) - 1] = '\0';
  memcpy(rep.prog_tag, pinfo.tag, 8);

  // 5. Access config_map with valid FD AFTER load and BEFORE attach
  struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "config_map");
  if (!cfg_map) {
    fprintf(stderr, "[bpf_canary_host] config_map not found in BPF object\n");
    rep.status = "CONFIG_MAP_MISSING";
    rep.error_message = "config_map missing in BPF object";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }
  int cfg_fd = bpf_map__fd(cfg_map);
  if (cfg_fd < 0) {
    fprintf(stderr, "[bpf_canary_host] Invalid config_map fd: %d\n", cfg_fd);
    rep.status = "CONFIG_MAP_INVALID_FD";
    rep.error_message = "config_map fd is invalid after load";
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  if (probe_only) {
    // In probe-only diagnostic mode: configure own actual TGID in the loaded
    // map before attach
    uint64_t my_tgid = (uint64_t)getpid();
    if (my_tgid == 0) {
      fprintf(stderr, "[bpf_canary_host] ERROR: Own TGID is 0\n");
      rep.status = "TGID_INVALID";
      rep.error_message = "Own TGID is 0";
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }
    rep.target_tgid = my_tgid;
    __u32 k_tgid = BPF_CANARY_CFG_TARGET_TGID;
    __u64 v_tgid = my_tgid;
    if (bpf_map_update_elem(cfg_fd, &k_tgid, &v_tgid, BPF_ANY) != 0) {
      int update_err = -errno;
      fprintf(stderr,
              "[bpf_canary_host] bpf_map_update_elem for target_tgid failed: "
              "%s (%d)\n",
              strerror(-update_err), update_err);
      rep.status = "MAP_UPDATE_FAILED";
      rep.error_message =
          "Failed to update target_tgid in config_map after load";
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }
    if (verbose) {
      fprintf(
          stderr,
          "[bpf_canary_host] Configured own TGID %llu in loaded config_map\n",
          (unsigned long long)v_tgid);
    }
  } else {
    __u32 k_cg = BPF_CANARY_CFG_TARGET_CGROUP;
    __u64 v_cg = target_cgroup_id;
    if (bpf_map_update_elem(cfg_fd, &k_cg, &v_cg, BPF_ANY) != 0) {
      int update_err = -errno;
      rep.status = "MAP_UPDATE_FAILED";
      rep.error_message = "Failed to update target_cgroup in config_map";
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }

    __u32 k_filt = BPF_CANARY_CFG_FILTER_ENABLED;
    __u64 v_filt = (target_cgroup_id != 0) ? 1 : 0;
    if (bpf_map_update_elem(cfg_fd, &k_filt, &v_filt, BPF_ANY) != 0) {
      int update_err = -errno;
      rep.status = "MAP_UPDATE_FAILED";
      rep.error_message = "Failed to update filter_enabled in config_map";
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }

    __u32 k_sim = BPF_CANARY_CFG_SIMULATE_LOSS;
    __u64 v_sim = sim_loss ? 1 : 0;
    if (bpf_map_update_elem(cfg_fd, &k_sim, &v_sim, BPF_ANY) != 0) {
      int update_err = -errno;
      rep.status = "MAP_UPDATE_FAILED";
      rep.error_message = "Failed to update sim_loss in config_map";
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }
  }

  // 6. Attach program via FD-owned link
  struct bpf_link *link = bpf_program__attach(prog);
  if (!link) {
    err = -errno;
    fprintf(stderr, "[bpf_canary_host] bpf_program__attach failed: %s (%d)\n",
            strerror(-err), err);
    rep.status = "ATTACH_FAILED";
    rep.error_message = strerror(-err);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  rep.attach_supported = true;
  rep.fd_ownership_lifecycle = "attached_link_fd_held";

  // Query and validate real link metadata from attached kernel link
  int link_fd = bpf_link__fd(link);
  if (link_fd < 0) {
    int l_err = -errno;
    fprintf(stderr, "[bpf_canary_host] Invalid link fd: %d (%s)\n", link_fd,
            strerror(-l_err));
    rep.status = "LINK_FD_INVALID";
    rep.error_message = "Invalid link fd after attach";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  struct bpf_link_info linfo;
  memset(&linfo, 0, sizeof(linfo));
  char tp_name_buf[128];
  memset(tp_name_buf, 0, sizeof(tp_name_buf));
  linfo.raw_tracepoint.tp_name = (__u64)(uintptr_t)tp_name_buf;
  linfo.raw_tracepoint.tp_name_len = sizeof(tp_name_buf);

  __u32 linfo_len = sizeof(linfo);
  if (bpf_obj_get_info_by_fd(link_fd, &linfo, &linfo_len) != 0) {
    int info_err = -errno;
    fprintf(
        stderr,
        "[bpf_canary_host] bpf_obj_get_info_by_fd for link failed: %s (%d)\n",
        strerror(-info_err), info_err);
    rep.status = "LINK_INFO_FAILED";
    rep.error_message =
        "Failed to query kernel link info via bpf_obj_get_info_by_fd";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Validate link type: kernel routes TRACING+BPF_TRACE_RAW_TP to
  // BPF_LINK_TYPE_RAW_TRACEPOINT (1)
  if (linfo.type != BPF_LINK_TYPE_RAW_TRACEPOINT) {
    fprintf(stderr,
            "[bpf_canary_host] Link type mismatch: expected "
            "BPF_LINK_TYPE_RAW_TRACEPOINT (%u), got %u\n",
            (unsigned int)BPF_LINK_TYPE_RAW_TRACEPOINT, linfo.type);
    rep.status = "LINK_TYPE_MISMATCH";
    rep.error_message = "Kernel link type is not BPF_LINK_TYPE_RAW_TRACEPOINT";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Validate link-program association: link.prog_id MUST match prog.id
  if (linfo.prog_id != pinfo.id) {
    fprintf(stderr,
            "[bpf_canary_host] Link program association mismatch: "
            "link.prog_id=%u != prog.id=%u\n",
            linfo.prog_id, pinfo.id);
    rep.status = "LINK_ASSOCIATION_MISMATCH";
    rep.error_message =
        "Kernel link is not associated with expected program ID";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  if (linfo.id == 0) {
    fprintf(stderr, "[bpf_canary_host] Invalid kernel link id: 0\n");
    rep.status = "LINK_ID_INVALID";
    rep.error_message = "Kernel returned link id 0";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  // Validate raw tracepoint name from link info
  tp_name_buf[sizeof(tp_name_buf) - 1] = '\0';
  if (strcmp(tp_name_buf, "sched_process_exec") != 0) {
    fprintf(stderr,
            "[bpf_canary_host] Link raw_tracepoint tp_name mismatch: expected "
            "'sched_process_exec', got '%s'\n",
            tp_name_buf);
    rep.status = "LINK_TP_NAME_MISMATCH";
    rep.error_message =
        "Kernel link raw_tracepoint name does not match sched_process_exec";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  snprintf(rep.link_tp_name, sizeof(rep.link_tp_name), "%s", tp_name_buf);

  // Validate program attach BTF ID: must be non-zero
  if (pinfo.attach_btf_id == 0) {
    fprintf(stderr, "[bpf_canary_host] Program attach_btf_id is zero\n");
    rep.status = "BTF_ID_INVALID";
    rep.error_message = "Kernel reported zero attach_btf_id for program";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }
  // Resolve and compare kernel BTF target symbol from /sys/kernel/btf/vmlinux
  struct btf *vbtf = btf__load_vmlinux_btf();
  if (!vbtf) {
    int v_err = -errno;
    fprintf(stderr, "[bpf_canary_host] btf__load_vmlinux_btf failed: %s (%d)\n",
            strerror(-v_err), v_err);
    rep.status = "VMLINUX_BTF_LOAD_FAILED";
    rep.error_message =
        "Failed to load vmlinux BTF to verify target hook identity";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  const struct btf_type *target_type =
      btf__type_by_id(vbtf, pinfo.attach_btf_id);
  if (!target_type) {
    fprintf(stderr,
            "[bpf_canary_host] Target BTF ID %u not found in vmlinux BTF\n",
            pinfo.attach_btf_id);
    rep.status = "TARGET_BTF_TYPE_NOT_FOUND";
    rep.error_message = "Target BTF ID not found in kernel vmlinux BTF";
    btf__free(vbtf);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }
  // Verify BTF kind is BTF_KIND_TYPEDEF (8)
#ifndef BTF_KIND_TYPEDEF
#define BTF_KIND_TYPEDEF 8
#endif
#ifndef BTF_INFO_KIND
#define BTF_INFO_KIND(info) (((info) >> 24) & 0x1f)
#endif
  __u32 target_kind = BTF_INFO_KIND(target_type->info);
  if (target_kind != BTF_KIND_TYPEDEF) {
    fprintf(stderr,
            "[bpf_canary_host] BTF target kind mismatch: expected "
            "BTF_KIND_TYPEDEF (%u), got %u\n",
            (unsigned int)BTF_KIND_TYPEDEF, target_kind);
    rep.status = "TARGET_BTF_KIND_MISMATCH";
    rep.error_message = "Attached BTF target is not BTF_KIND_TYPEDEF";
    btf__free(vbtf);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  const char *target_name = btf__name_by_offset(vbtf, target_type->name_off);
  if (!target_name ||
      strcmp(target_name, "btf_trace_sched_process_exec") != 0) {
    fprintf(stderr,
            "[bpf_canary_host] BTF target hook mismatch: expected "
            "'btf_trace_sched_process_exec', got '%s'\n",
            target_name ? target_name : "NULL");
    rep.status = "HOOK_IDENTITY_MISMATCH";
    rep.error_message =
        "Attached BTF hook target does not match btf_trace_sched_process_exec";
    btf__free(vbtf);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    write_probe_report(status_path, &rep);
    return 1;
  }

  snprintf(rep.observed_hook_name, sizeof(rep.observed_hook_name), "%s",
           target_name);
  rep.observed_hook_kind = "BTF_KIND_TYPEDEF";
  rep.link_info_valid = true;
  rep.link_id = linfo.id;
  rep.link_type = linfo.type;
  rep.link_prog_id = linfo.prog_id;
  rep.hook_identity_verified = true;
  rep.link_association_verified = true;
  btf__free(vbtf);
  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Attached link: link_id=%u prog_id=%u "
            "link_type=%u (RAW_TRACEPOINT: %s) "
            "(prog_info_valid=%d link_info_valid=%d)\n",
            rep.link_id, rep.prog_id, rep.link_type, rep.link_tp_name,
            rep.prog_info_valid, rep.link_info_valid);
  }

  // 7. In probe-only diagnostic mode: skip ringbuf/containers, detach link and
  // close object BEFORE reporting success
  if (probe_only) {
    if (stop_requested) {
      bpf_link__destroy(link);
      link = NULL;
      bpf_object__close(obj);
      obj = NULL;
      rep.status = "CANCELED";
      rep.fd_ownership_lifecycle = "detached_and_closed_on_cancellation";
      rep.error_message = "Diagnostic execution canceled by signal";
      write_probe_report(status_path, &rep);
      return 130;
    }

    int detach_res = bpf_link__destroy(link);
    link = NULL;
    if (detach_res != 0) {
      int d_err = -errno;
      fprintf(stderr, "[bpf_canary_host] bpf_link__destroy failed: %s (%d)\n",
              strerror(-d_err), d_err);
      rep.status = "DETACH_FAILED";
      rep.fd_ownership_lifecycle = "detach_error";
      rep.error_message = strerror(-d_err);
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }

    bpf_object__close(obj);
    obj = NULL;
    rep.fd_ownership_lifecycle = "detached_and_closed_before_report";

    if (stop_requested) {
      rep.status = "CANCELED";
      rep.fd_ownership_lifecycle = "detached_and_closed_on_cancellation";
      rep.error_message = "Diagnostic execution canceled by signal";
      write_probe_report(status_path, &rep);
      return 130;
    }

    // Success reported only after verified link and object lifetime
    rep.status = "PROBE_SUCCESS";
    rep.error_message = NULL;

    if (write_probe_report(status_path, &rep) != 0) {
      fprintf(stderr, "[bpf_canary_host] Failed to write probe report\n");
      return 1;
    }
    return 0;
  }

  // Non-probe-only mode (full execution witness testing)
  if (pid_path) {
    if (safe_write_pid_file(pid_path) != 0) {
      rep.status = "PID_FILE_FAILED";
      rep.error_message = "Failed to write pid file";
      bpf_link__destroy(link);
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }
  }

  struct host_context ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.target_cgroup_id = target_cgroup_id;
  ctx.verbose = verbose;

  if (out_path) {
    const char *err_open = NULL;
    ctx.out_fp = safe_open_file(out_path, true, &err_open);
    if (!ctx.out_fp) {
      fprintf(stderr,
              "[bpf_canary_host] Failed to open output file safely (%s): %s\n",
              out_path, err_open ? err_open : "unknown");
      rep.status = "OUTPUT_OPEN_FAILED";
      rep.error_message = err_open;
      bpf_link__destroy(link);
      bpf_object__close(obj);
      write_probe_report(status_path, &rep);
      return 1;
    }
  } else {
    ctx.out_fp = stdout;
  }

  struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
  if (!events_map) {
    fprintf(stderr, "[bpf_canary_host] events map not found\n");
    rep.status = "EVENTS_MAP_MISSING";
    rep.error_message = "events map missing";
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    write_probe_report(status_path, &rep);
    return 1;
  }

  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(events_map), handle_event, &ctx, NULL);
  if (!rb) {
    fprintf(stderr, "[bpf_canary_host] ring_buffer__new failed: %s\n",
            strerror(errno));
    rep.status = "RINGBUF_INIT_FAILED";
    rep.error_message = strerror(errno);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    write_probe_report(status_path, &rep);
    return 1;
  }

  if (ready_path) {
    if (safe_touch_ready_file(ready_path) != 0) {
      rep.status = "READY_FILE_FAILED";
      rep.error_message = "Failed to create ready file safely";
      ring_buffer__free(rb);
      bpf_link__destroy(link);
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      write_probe_report(status_path, &rep);
      return 1;
    }
  }

  int poll_fatal_err = 0;
  time_t start_time = time(NULL);
  while (!stop_requested) {
    int poll_res = ring_buffer__poll(rb, 100);
    if (poll_res < 0) {
      if (poll_res != -EINTR && errno != EINTR) {
        fprintf(stderr,
                "[bpf_canary_host] ring_buffer__poll fatal error: %d (%s)\n",
                poll_res, strerror(errno));
        poll_fatal_err = poll_res;
        break;
      }
    }
    if (duration > 0 && (time(NULL) - start_time) >= duration) {
      break;
    }
  }

  if (poll_fatal_err < 0) {
    rep.status = "POLL_FAILED";
    rep.error_message = "ring_buffer__poll fatal error";
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    write_probe_report(status_path, &rep);
    return 1;
  }

  ring_buffer__consume(rb);

  struct bpf_map *loss_map = bpf_object__find_map_by_name(obj, "loss_counter");
  uint64_t loss_count = 0;
  uint64_t error_count = 0;
  uint64_t delivered_count = 0;
  if (loss_map) {
    int loss_fd = bpf_map__fd(loss_map);
    __u32 k0 = BPF_CANARY_LOSS_COUNT;
    bpf_map_lookup_elem(loss_fd, &k0, &loss_count);
    __u32 k1 = BPF_CANARY_ERROR_COUNT;
    bpf_map_lookup_elem(loss_fd, &k1, &error_count);
    __u32 k2 = BPF_CANARY_EVENT_COUNT;
    bpf_map_lookup_elem(loss_fd, &k2, &delivered_count);
  }

  int exit_code = 0;
  if (loss_count > 0) {
    rep.status = "LOSS_DETECTED";
    rep.error_message = "Ring buffer loss detected";
    exit_code = 2;
  } else if (error_count > 0) {
    rep.status = "BPF_ERRORS";
    rep.error_message = "Kernel extraction failed for some events";
    exit_code = 3;
  } else {
    rep.status = "OK";
    rep.error_message = NULL;
  }

  ring_buffer__free(rb);
  bpf_link__destroy(link);
  bpf_object__close(obj);
  if (ctx.out_fp && ctx.out_fp != stdout)
    fclose(ctx.out_fp);

  write_probe_report(status_path, &rep);
  return exit_code;
#endif
}
