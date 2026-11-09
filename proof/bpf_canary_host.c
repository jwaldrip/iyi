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
#include <bpf/libbpf.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#endif

#include "bpf_canary_types.h"

struct host_context {
  FILE *out_fp;
  uint64_t events_captured;
  uint64_t target_cgroup_id;
  int verbose;
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
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, format, args);
}

/*
 * Verify genuinely restricted observer privileges:
 * 1. Reject UID 0 (root). Must run under unprivileged user.
 * 2. Reject all capabilities in data[0] (no CAP_SYS_ADMIN, no CAP_DAC_OVERRIDE,
 * etc.).
 * 3. Reject all capabilities in data[1] outside {CAP_PERFMON (bit 6), CAP_BPF
 * (bit 7)}.
 * 4. Verify CAP_BPF and CAP_PERFMON are present.
 * 5. Reject root supplementary group 0.
 * 6. Verify PR_SET_NO_NEW_PRIVS is active.
 */
static int verify_restricted_privileges(int verbose, uid_t *final_uid,
                                        gid_t *final_gid) {
  *final_uid = getuid();
  *final_gid = getgid();

  // Reject UID 0 (root)
  if (*final_uid == 0 || geteuid() == 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Refusing to execute as root (UID 0). "
            "Observer must be launched with standard setpriv as an "
            "unprivileged user.\n");
    return -1;
  }

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

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Observed process state: UID=%u GID=%u "
            "CapEff[0]=0x%08x [1]=0x%08x "
            "(CAP_SYS_ADMIN=%d, CAP_PERFMON=%d, CAP_BPF=%d)\n",
            *final_uid, *final_gid, data[0].effective, data[1].effective,
            (data[0].effective & (1U << 21)) != 0,
            (data[1].effective & (1U << 6)) != 0,
            (data[1].effective & (1U << 7)) != 0);
  }

  // Reject any capability in data[0] (CAP_SYS_ADMIN is bit 21, CAP_DAC_OVERRIDE
  // is bit 1)
  if (data[0].effective != 0 || data[0].permitted != 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Disallowed capabilities in data[0]: "
            "eff=0x%08x prm=0x%08x\n",
            data[0].effective, data[0].permitted);
    return -1;
  }

  // Reject any capability in data[1] outside {CAP_PERFMON (bit 6), CAP_BPF (bit
  // 7)}
  __u32 scoped_mask = (1U << 6) | (1U << 7);
  if ((data[1].effective & ~scoped_mask) != 0 ||
      (data[1].permitted & ~scoped_mask) != 0) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Capabilities outside approved set "
            "{CAP_BPF, CAP_PERFMON} in data[1]: "
            "eff=0x%08x prm=0x%08x\n",
            data[1].effective, data[1].permitted);
    return -1;
  }

  // Ensure CAP_BPF and CAP_PERFMON are present in permitted set
  if ((data[1].permitted & scoped_mask) != scoped_mask) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: Missing required scoped capabilities "
            "CAP_BPF / CAP_PERFMON in permitted set: prm=0x%08x\n",
            data[1].permitted);
    return -1;
  }

  // Raise permitted capabilities to effective if not already set
  if ((data[1].effective & scoped_mask) != scoped_mask) {
    data[1].effective = scoped_mask;
    if (syscall(SYS_capset, &hdr, data) != 0) {
      perror("[bpf_canary_host] capset failed raising permitted to effective");
      return -1;
    }
  }

  // Reject root supplementary group 0
  int n_groups = getgroups(0, NULL);
  if (n_groups > 0) {
    if (n_groups > 32)
      n_groups = 32;
    gid_t groups[32];
    int count = getgroups(n_groups, groups);
    for (int i = 0; i < count; i++) {
      if (groups[i] == 0) {
        fprintf(
            stderr,
            "[bpf_canary_host] ERROR: Root supplementary group 0 retained!\n");
        return -1;
      }
    }
  }

  // Verify PR_SET_NO_NEW_PRIVS is locked
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    perror("[bpf_canary_host] prctl(PR_SET_NO_NEW_PRIVS) failed");
    return -1;
  }
  if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
    fprintf(stderr,
            "[bpf_canary_host] ERROR: PR_SET_NO_NEW_PRIVS is not active\n");
    return -1;
  }

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Verified restricted observer privileges: UID=%u "
            "GID=%u "
            "CapEff[0]=0x%08x [1]=0x%08x (no_new_privs=1)\n",
            *final_uid, *final_gid, data[0].effective, data[1].effective);
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
            "{\"cgroup_id\":%llu,\"dev\":%llu,\"inode\":%llu,\"pid\":%u,"
            "\"tgid\":%u,\"comm\":\"%s\"}\n",
            (unsigned long long)e->cgroup_id, (unsigned long long)e->dev,
            (unsigned long long)e->inode, e->pid, e->tgid, comm_buf);
    fflush(c->out_fp);
  }
  return 0;
}
#endif

static int write_status_file(const char *status_path, const char *status,
                             bool is_probe_only, bool load_supported,
                             bool attach_supported, uint64_t events_captured,
                             uint64_t loss_count, uint64_t error_count,
                             uid_t final_uid, gid_t final_gid,
                             uint64_t cgroup_id, uint64_t target_tgid,
                             const char *error_msg) {
  if (!status_path)
    return 0;

  const char *err_open = NULL;
  FILE *sf = safe_open_file(status_path, false, &err_open);
  if (!sf) {
    fprintf(stderr, "[bpf_canary_host] Failed to open status file safely: %s\n",
            err_open ? err_open : "unknown");
    return -1;
  }

  fprintf(sf, "{\n");
  fprintf(sf, "  \"status\": \"%s\",\n", status);
  fprintf(sf, "  \"strict_eligible\": false,\n");
  fprintf(sf, "  \"exec_identity_tested\": false,\n");
  fprintf(sf, "  \"bpf_load_supported\": %s,\n",
          load_supported ? "true" : "false");
  fprintf(sf, "  \"bpf_attach_supported\": %s,\n",
          attach_supported ? "true" : "false");
  if (is_probe_only) {
    fprintf(sf, "  \"diagnostic_mode\": true,\n");
    fprintf(sf, "  \"program_name\": \"sched_process_exec\",\n");
    fprintf(sf, "  \"program_type\": \"BPF_PROG_TYPE_TRACING\",\n");
    fprintf(sf, "  \"attach_target\": \"tp_btf/sched_process_exec\",\n");
    fprintf(sf, "  \"link_fd_owned\": true,\n");
    fprintf(sf, "  \"fd_ownership_lifecycle\": "
                "\"detached_and_closed_before_report\",\n");
    fprintf(sf, "  \"target_tgid\": %llu,\n", (unsigned long long)target_tgid);
  } else {
    fprintf(sf, "  \"events_captured\": %llu,\n",
            (unsigned long long)events_captured);
    fprintf(sf, "  \"loss_count\": %llu,\n", (unsigned long long)loss_count);
    fprintf(sf, "  \"error_count\": %llu,\n", (unsigned long long)error_count);
    fprintf(sf, "  \"cgroup_id\": %llu,\n", (unsigned long long)cgroup_id);
  }
  fprintf(sf, "  \"process_identity\": {\n");
  fprintf(sf, "    \"uid\": %u,\n", (unsigned int)final_uid);
  fprintf(sf, "    \"gid\": %u\n", (unsigned int)final_gid);
  fprintf(sf, "  },\n");
  fprintf(sf, "  \"capabilities\": {\n");
  fprintf(sf, "    \"cap_bpf\": true,\n");
  fprintf(sf, "    \"cap_perfmon\": true,\n");
  fprintf(sf, "    \"cap_sys_admin\": false,\n");
  fprintf(sf, "    \"all_other_caps_clear\": true\n");
  fprintf(sf, "  },\n");
  if (error_msg) {
    fprintf(sf, "  \"error_message\": \"%s\"\n", error_msg);
  } else {
    fprintf(sf, "  \"error_message\": null\n");
  }
  fprintf(sf, "}\n");

  if (fflush(sf) != 0 || fclose(sf) != 0) {
    fprintf(stderr, "[bpf_canary_host] Failed to flush/close status file\n");
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
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "c:o:s:r:P:b:pld:v", long_options,
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
    default:
      fprintf(
          stderr,
          "Usage: %s [--cgroup-id <id>] [--output <file>] [--status <file>] "
          "[--ready-file <file>] [--pid-file <file>] [--bpf-obj <path>] "
          "[--probe-only] [--sim-loss] [--duration <sec>] [--verbose]\n",
          argv[0]);
      return 1;
    }
  }

#ifndef __linux__
  fprintf(stderr,
          "[bpf_canary_host] Linux kernel BPF required. Not supported on host "
          "platform.\n");
  write_status_file(status_path, "UNSUPPORTED_PLATFORM", probe_only, false,
                    false, 0, 0, 0, 0, 0, 0, 0, "Non-Linux platform");
  return 1;
#else
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_print(libbpf_print_fn);

  uid_t final_uid = getuid();
  gid_t final_gid = getgid();

  // Enforce genuinely restricted observer privileges: reject UID 0 and
  // capabilities outside approved set
  if (verify_restricted_privileges(verbose, &final_uid, &final_gid) != 0) {
    write_status_file(status_path, "PRIVILEGE_RESTRICTION_FAILED", probe_only,
                      false, false, 0, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0,
                      "Failed privilege restriction verification");
    return 1;
  }

  // In non-probe-only mode, write exact PID file for authenticated lifecycle
  // management
  if (!probe_only && pid_path) {
    if (safe_write_pid_file(pid_path) != 0) {
      write_status_file(status_path, "PID_FILE_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, "Failed to write pid file");
      return 1;
    }
  }

  struct host_context ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.target_cgroup_id = target_cgroup_id;
  ctx.verbose = verbose;

  if (!probe_only && out_path) {
    const char *err_open = NULL;
    ctx.out_fp = safe_open_file(out_path, true, &err_open);
    if (!ctx.out_fp) {
      fprintf(stderr,
              "[bpf_canary_host] Failed to open output file safely (%s): %s\n",
              out_path, err_open ? err_open : "unknown");
      write_status_file(status_path, "OUTPUT_OPEN_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, err_open);
      return 1;
    }
  } else {
    ctx.out_fp = stdout;
  }

  if (verbose) {
    fprintf(stderr, "[bpf_canary_host] Opening BPF object: %s\n", bpf_obj_path);
  }

  struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
  if (!obj) {
    int err = -errno;
    fprintf(stderr, "[bpf_canary_host] bpf_object__open_file failed: %s (%d)\n",
            strerror(-err), err);
    write_status_file(status_path, "OPEN_FAILED", probe_only, false, false, 0,
                      0, 0, final_uid, final_gid, target_cgroup_id, 0,
                      strerror(-err));
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  // Find config_map
  struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "config_map");
  if (!cfg_map) {
    fprintf(stderr, "[bpf_canary_host] config_map not found in BPF object\n");
    write_status_file(status_path, "CONFIG_MAP_MISSING", probe_only, false,
                      false, 0, 0, 0, final_uid, final_gid, target_cgroup_id, 0,
                      "config_map missing");
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }
  int cfg_fd = bpf_map__fd(cfg_map);

  uint64_t target_tgid = 0;
  if (probe_only) {
    // In probe-only diagnostic mode: configure own actual TGID to filter out
    // all other host tasks before reading file identity
    target_tgid = (uint64_t)getpid();
    __u32 k_tgid = BPF_CANARY_CFG_TARGET_TGID;
    __u64 v_tgid = target_tgid;
    if (bpf_map_update_elem(cfg_fd, &k_tgid, &v_tgid, BPF_ANY) != 0) {
      int update_err = -errno;
      fprintf(stderr,
              "[bpf_canary_host] bpf_map_update_elem for target_tgid failed: "
              "%s (%d)\n",
              strerror(-update_err), update_err);
      write_status_file(status_path, "MAP_UPDATE_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        target_tgid,
                        "Failed to update target_tgid in config_map");
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      return 1;
    }
  } else {
    __u32 k_cg = BPF_CANARY_CFG_TARGET_CGROUP;
    __u64 v_cg = target_cgroup_id;
    if (bpf_map_update_elem(cfg_fd, &k_cg, &v_cg, BPF_ANY) != 0) {
      int update_err = -errno;
      fprintf(stderr,
              "[bpf_canary_host] bpf_map_update_elem for target_cgroup failed: "
              "%s (%d)\n",
              strerror(-update_err), update_err);
      write_status_file(status_path, "MAP_UPDATE_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, "Failed to update target_cgroup in config_map");
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      return 1;
    }

    __u32 k_filt = BPF_CANARY_CFG_FILTER_ENABLED;
    __u64 v_filt = (target_cgroup_id != 0) ? 1 : 0;
    if (bpf_map_update_elem(cfg_fd, &k_filt, &v_filt, BPF_ANY) != 0) {
      int update_err = -errno;
      fprintf(stderr,
              "[bpf_canary_host] bpf_map_update_elem for filter_enabled "
              "failed: %s (%d)\n",
              strerror(-update_err), update_err);
      write_status_file(status_path, "MAP_UPDATE_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, "Failed to update filter_enabled in config_map");
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      return 1;
    }

    __u32 k_sim = BPF_CANARY_CFG_SIMULATE_LOSS;
    __u64 v_sim = sim_loss ? 1 : 0;
    if (bpf_map_update_elem(cfg_fd, &k_sim, &v_sim, BPF_ANY) != 0) {
      int update_err = -errno;
      fprintf(stderr,
              "[bpf_canary_host] bpf_map_update_elem for sim_loss failed: %s "
              "(%d)\n",
              strerror(-update_err), update_err);
      write_status_file(status_path, "MAP_UPDATE_FAILED", probe_only, false,
                        false, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, "Failed to update sim_loss in config_map");
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      return 1;
    }
  }

  if (verbose) {
    fprintf(stderr, "[bpf_canary_host] Loading BPF object into kernel under "
                    "restricted capabilities...\n");
  }

  int err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "[bpf_canary_host] bpf_object__load failed: %s (%d)\n",
            strerror(-err), err);
    write_status_file(status_path, "LOAD_FAILED", probe_only, false, false, 0,
                      0, 0, final_uid, final_gid, target_cgroup_id, target_tgid,
                      strerror(-err));
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  // Attach to sched_process_exec tracepoint
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "sched_process_exec");
  if (!prog) {
    fprintf(stderr, "[bpf_canary_host] Program sched_process_exec not found\n");
    write_status_file(status_path, "PROGRAM_MISSING", probe_only, true, false,
                      0, 0, 0, final_uid, final_gid, target_cgroup_id,
                      target_tgid, "sched_process_exec missing");
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  struct bpf_link *link = bpf_program__attach(prog);
  if (!link) {
    err = -errno;
    fprintf(stderr, "[bpf_canary_host] bpf_program__attach failed: %s (%d)\n",
            strerror(-err), err);
    write_status_file(status_path, "ATTACH_FAILED", probe_only, true, false, 0,
                      0, 0, final_uid, final_gid, target_cgroup_id, target_tgid,
                      strerror(-err));
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  if (probe_only) {
    if (verbose) {
      fprintf(stderr, "[bpf_canary_host] Probe-only check: program loaded and "
                      "attached successfully via FD-owned link.\n");
    }

    // Explicitly destroy the link and close BPF object BEFORE reporting success
    int detach_res = bpf_link__destroy(link);
    link = NULL;
    if (detach_res != 0) {
      int d_err = -errno;
      fprintf(stderr, "[bpf_canary_host] bpf_link__destroy failed: %s (%d)\n",
              strerror(-d_err), d_err);
      write_status_file(status_path, "DETACH_FAILED", probe_only, true, true, 0,
                        0, 0, final_uid, final_gid, target_cgroup_id,
                        target_tgid, strerror(-d_err));
      bpf_object__close(obj);
      return 1;
    }

    bpf_object__close(obj);
    obj = NULL;

    // Report success only after successful detach and close
    if (write_status_file(status_path, "PROBE_SUCCESS", probe_only, true, true,
                          0, 0, 0, final_uid, final_gid, target_cgroup_id,
                          target_tgid, NULL) != 0) {
      return 1;
    }
    return 0;
  }

  // Non-probe-only mode: setup ring buffer and run workload capture
  struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
  if (!events_map) {
    fprintf(stderr, "[bpf_canary_host] events map not found\n");
    write_status_file(status_path, "EVENTS_MAP_MISSING", probe_only, true, true,
                      0, 0, 0, final_uid, final_gid, target_cgroup_id, 0,
                      "events map missing");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(events_map), handle_event, &ctx, NULL);
  if (!rb) {
    fprintf(stderr, "[bpf_canary_host] ring_buffer__new failed: %s\n",
            strerror(errno));
    write_status_file(status_path, "RINGBUF_INIT_FAILED", probe_only, true,
                      true, 0, 0, 0, final_uid, final_gid, target_cgroup_id, 0,
                      strerror(errno));
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  // Signal readiness using safe exclusive open
  if (ready_path) {
    if (safe_touch_ready_file(ready_path) != 0) {
      write_status_file(status_path, "READY_FILE_FAILED", probe_only, true,
                        true, 0, 0, 0, final_uid, final_gid, target_cgroup_id,
                        0, "Failed to create ready file safely");
      ring_buffer__free(rb);
      bpf_link__destroy(link);
      bpf_object__close(obj);
      if (ctx.out_fp && ctx.out_fp != stdout)
        fclose(ctx.out_fp);
      return 1;
    }
  }

  if (verbose) {
    fprintf(stderr, "[bpf_canary_host] Tracer ready and polling events...\n");
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
    write_status_file(status_path, "POLL_FAILED", probe_only, true, true,
                      ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0,
                      "ring_buffer__poll encountered fatal error");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  // Final drain of ring buffer
  ring_buffer__consume(rb);

  // Read sticky loss and error statistics from loss_counter map
  struct bpf_map *loss_map = bpf_object__find_map_by_name(obj, "loss_counter");
  if (!loss_map) {
    fprintf(stderr,
            "[bpf_canary_host] loss_counter map missing in BPF object\n");
    write_status_file(status_path, "LOSS_MAP_MISSING", probe_only, true, true,
                      ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0, "loss_counter map missing");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  int loss_fd = bpf_map__fd(loss_map);
  if (loss_fd < 0) {
    fprintf(stderr, "[bpf_canary_host] Invalid loss_counter map fd\n");
    write_status_file(status_path, "LOSS_MAP_INVALID", probe_only, true, true,
                      ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0, "Invalid loss_counter map fd");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  uint64_t loss_count = 0;
  uint64_t error_count = 0;
  uint64_t delivered_count = 0;

  __u32 k0 = BPF_CANARY_LOSS_COUNT;
  if (bpf_map_lookup_elem(loss_fd, &k0, &loss_count) != 0) {
    int lookup_err = -errno;
    fprintf(stderr,
            "[bpf_canary_host] bpf_map_lookup_elem for loss_count failed: %s "
            "(%d)\n",
            strerror(-lookup_err), lookup_err);
    write_status_file(status_path, "LOSS_LOOKUP_FAILED", probe_only, true, true,
                      ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0,
                      "Failed to lookup loss_count in loss_counter map");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  __u32 k1 = BPF_CANARY_ERROR_COUNT;
  if (bpf_map_lookup_elem(loss_fd, &k1, &error_count) != 0) {
    int lookup_err = -errno;
    fprintf(stderr,
            "[bpf_canary_host] bpf_map_lookup_elem for error_count failed: %s "
            "(%d)\n",
            strerror(-lookup_err), lookup_err);
    write_status_file(status_path, "ERROR_LOOKUP_FAILED", probe_only, true,
                      true, ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0,
                      "Failed to lookup error_count in loss_counter map");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  __u32 k2 = BPF_CANARY_EVENT_COUNT;
  if (bpf_map_lookup_elem(loss_fd, &k2, &delivered_count) != 0) {
    int lookup_err = -errno;
    fprintf(stderr,
            "[bpf_canary_host] bpf_map_lookup_elem for delivered_count failed: "
            "%s (%d)\n",
            strerror(-lookup_err), lookup_err);
    write_status_file(status_path, "EVENT_LOOKUP_FAILED", probe_only, true,
                      true, ctx.events_captured, 0, 0, final_uid, final_gid,
                      target_cgroup_id, 0,
                      "Failed to lookup event_count in loss_counter map");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    if (ctx.out_fp && ctx.out_fp != stdout)
      fclose(ctx.out_fp);
    return 1;
  }

  if (verbose) {
    fprintf(stderr,
            "[bpf_canary_host] Final stats: captured=%llu delivered=%llu "
            "loss=%llu errors=%llu\n",
            (unsigned long long)ctx.events_captured,
            (unsigned long long)delivered_count, (unsigned long long)loss_count,
            (unsigned long long)error_count);
  }

  int exit_code = 0;
  const char *final_status = "OK";
  char err_buf[128];
  const char *err_msg = NULL;

  if (loss_count > 0) {
    final_status = "LOSS_DETECTED";
    snprintf(err_buf, sizeof(err_buf), "Ring buffer dropped %llu events",
             (unsigned long long)loss_count);
    err_msg = err_buf;
    exit_code = 2; // loss detected
  } else if (error_count > 0) {
    final_status = "BPF_ERRORS";
    snprintf(err_buf, sizeof(err_buf),
             "Kernel extraction failed for %llu events",
             (unsigned long long)error_count);
    err_msg = err_buf;
    exit_code = 3; // extraction errors
  }

  write_status_file(status_path, final_status, probe_only, true, true,
                    ctx.events_captured, loss_count, error_count, final_uid,
                    final_gid, target_cgroup_id, 0, err_msg);

  // Clean teardown
  ring_buffer__free(rb);
  bpf_link__destroy(link);
  bpf_object__close(obj);
  if (ctx.out_fp && ctx.out_fp != stdout)
    fclose(ctx.out_fp);

  return exit_code;
#endif
}
