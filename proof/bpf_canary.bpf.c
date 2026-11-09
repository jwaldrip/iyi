// proof/bpf_canary.bpf.c
// Dedicated trusted host-side BPF tracer for successful-exec object identity.

#include "bpf_canary_types.h"

#if __has_include("vmlinux.h")
#include "vmlinux.h"
#else
#if defined(__linux__) || defined(__bpf__)
#include <linux/bpf.h>
#include <linux/types.h>
#endif
#include "bpf_canary_kernel_types.h"
#endif

#if defined(__linux__) || defined(__bpf__)
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#elif __has_include(<bpf/bpf_helpers.h>)
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#else
// Fallback declarations ONLY for non-Linux host editor / analyzer
#if defined(__APPLE__) && !defined(__bpf__)
#define SEC(name)
#else
#define SEC(name) __attribute__((section(name), used))
#endif
#define BPF_PROG(name, args...) name(args)
#define BPF_CORE_READ(src, a...) 0
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
                                    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * Configuration map set by userspace host tracer before/during execution:
 * Key 0: target_cgroup_id (__u64)
 * Key 1: filter_enabled (__u64, 1 = filter by cgroup, 0 = capture all)
 * Key 2: simulate_loss (__u64, 1 = simulate reservation drop to test loss
 * detection) Key 3: target_tgid (__u64, diagnostic target TGID; returns
 * immediately for others)
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPF_CANARY_CFG_MAX);
  __type(key, __u32);
  __type(value, __u64);
} config_map SEC(".maps");

/*
 * Sticky statistics and loss counters:
 * Key 0: loss_count (counter of dropped events or buffer full events)
 * Key 1: error_count (counter of kernel extraction failures)
 * Key 2: event_count (counter of successfully submitted events)
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, BPF_CANARY_STAT_MAX);
  __type(key, __u32);
  __type(value, __u64);
} loss_counter SEC(".maps");

/*
 * Preallocated non-evicting 256 KB ring buffer for execution events.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
  __u64 *val = bpf_map_lookup_elem(&loss_counter, &key);
  if (val) {
    __sync_fetch_and_add(val, 1);
  }
}

/*
 * Normalize kernel internal dev_t (MAJOR in 31:20, MINOR in 19:0)
 * into userspace st_dev encoding: (minor & 0xff) | (major << 8) | ((minor &
 * ~0xff) << 12)
 */
static __always_inline __u64 encode_dev(__u32 dev) {
  unsigned int major = dev >> 20;
  unsigned int minor = dev & ((1U << 20) - 1);
  return (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ~0xff) << 12);
}

/*
 * Hook: tp_btf/sched_process_exec
 * Fires in kernel bprm_execve() ONLY after successful binary execution setup.
 * Accesses kernel task_struct and linux_binprm directly via BTF.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *p, int old_pid,
             struct linux_binprm *bprm) {
  (void)old_pid;

  // 1. Diagnostic TGID filter: return immediately for other TGIDs before
  // inspecting file identity
  __u32 key_tgid = BPF_CANARY_CFG_TARGET_TGID;
  __u64 *target_tgid = bpf_map_lookup_elem(&config_map, &key_tgid);
  if (target_tgid && *target_tgid != 0) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 current_tgid = (__u32)(pid_tgid >> 32);
    if (current_tgid != (__u32)*target_tgid) {
      return 0; // Filter out immediately before inspecting file identity
    }
  }

  // 2. Filter by target container cgroup if enabled
  __u64 cgid = bpf_get_current_cgroup_id();
  __u32 key_filt = BPF_CANARY_CFG_FILTER_ENABLED;
  __u64 *filter_enabled = bpf_map_lookup_elem(&config_map, &key_filt);
  if (filter_enabled && *filter_enabled != 0) {
    __u32 key_cg = BPF_CANARY_CFG_TARGET_CGROUP;
    __u64 *target_cg = bpf_map_lookup_elem(&config_map, &key_cg);
    if (!target_cg || cgid != *target_cg) {
      // Event originated outside the target container cgroup - ignore
      return 0;
    }
  }

  // 3. Check simulated loss flag (used to verify sticky loss counter detection)
  __u32 key_sim = BPF_CANARY_CFG_SIMULATE_LOSS;
  __u64 *sim_loss = bpf_map_lookup_elem(&config_map, &key_sim);
  if (sim_loss && *sim_loss != 0) {
    inc_stat(BPF_CANARY_LOSS_COUNT);
    return 0;
  }

  // 4. Extract kernel file object identity (dev, inode)
  __u64 ino = 0;
  __u64 dev = 0;

  // Primary: bprm->file->f_inode
  if (bprm) {
    struct file *f = BPF_CORE_READ(bprm, file);
    if (f) {
      struct inode *i = BPF_CORE_READ(f, f_inode);
      if (i) {
        ino = BPF_CORE_READ(i, i_ino);
        struct super_block *sb = BPF_CORE_READ(i, i_sb);
        if (sb) {
          dev = BPF_CORE_READ(sb, s_dev);
        }
      }
    }
  }

  // Fallback: p->mm->exe_file->f_inode
  if (!ino && p) {
    struct mm_struct *mm = BPF_CORE_READ(p, mm);
    if (mm) {
      struct file *exe = BPF_CORE_READ(mm, exe_file);
      if (exe) {
        struct inode *exe_i = BPF_CORE_READ(exe, f_inode);
        if (exe_i) {
          ino = BPF_CORE_READ(exe_i, i_ino);
          struct super_block *sb = BPF_CORE_READ(exe_i, i_sb);
          if (sb) {
            dev = BPF_CORE_READ(sb, s_dev);
          }
        }
      }
    }
  }

  if (!ino) {
    inc_stat(BPF_CANARY_ERROR_COUNT);
    return 0;
  }

  // 5. Reserve space in preallocated ring buffer
  struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) {
    // Reservation failed (buffer full / dropped) - increment sticky loss
    // counter
    inc_stat(BPF_CANARY_LOSS_COUNT);
    return 0;
  }

  // 6. Populate verified event
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  e->cgroup_id = cgid;
  e->dev = encode_dev(dev);
  e->inode = ino;
  e->pid = (__u32)pid_tgid;
  e->tgid = (__u32)(pid_tgid >> 32);
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);

  // 7. Increment delivered event count
  inc_stat(BPF_CANARY_EVENT_COUNT);
  return 0;
}
