#include "e3_bpf_kernel_types.h"
#include "e3_bpf_types.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct e3_bpf_state);
} e3_state SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, E3_BPF_RING_BYTES);
} e3_events SEC(".maps");

/* 0 = success, 1 = missing pointer, 2 = failed read or invalid value. */
#define READ_FIELD(dst, src, member)                                           \
  (bpf_core_read(&(dst), sizeof(dst), &((src)->member)))

static __always_inline __u64 dev_encode(__u32 d) {
  __u64 major = d >> 20, minor = d & ((1U << 20) - 1);
  return (minor & 0xff) | (major << 8) | ((minor & ~255ULL) << 12);
}

static __always_inline int object_from_file(struct file *file,
                                            struct e3_bpf_object *out) {
  struct inode *inode = 0;
  struct super_block *sb = 0;
  struct vfsmount *vfsmnt = 0;
  struct mount *mount;
  unsigned long ino = 0;
  long long size = 0;
  __u16 mode = 0;
  __u32 dev = 0;
  int mount_id = 0;
  if (!file)
    return 1;
  if (READ_FIELD(inode, file, f_inode))
    return 2;
  if (!inode)
    return 1;
  if (READ_FIELD(sb, inode, i_sb))
    return 2;
  if (!sb)
    return 1;
  if (READ_FIELD(ino, inode, i_ino) || READ_FIELD(size, inode, i_size) ||
      READ_FIELD(mode, inode, i_mode) || READ_FIELD(dev, sb, s_dev) ||
      READ_FIELD(vfsmnt, file, f_path.mnt))
    return 2;
  if (!vfsmnt)
    return 1;
  mount = (void *)((char *)vfsmnt - bpf_core_field_offset(struct mount, mnt));
  if (READ_FIELD(mount_id, mount, mnt_id))
    return 2;
  if (!ino || size < 0 || mount_id <= 0)
    return 2;
  out->dev = dev_encode(dev);
  out->inode = ino;
  out->size = (__u64)size;
  out->mount_id = (__u32)mount_id;
  out->mode = mode;
  return 0;
}

static __always_inline int task_identity(struct task_struct *p,
                                         struct e3_bpf_exec_event *event) {
  int pid = 0, tgid = 0;
  __u64 current = bpf_get_current_pid_tgid(), birth = 0;
  if (!p)
    return 1;
  if (READ_FIELD(pid, p, pid) || READ_FIELD(tgid, p, tgid) ||
      READ_FIELD(birth, p, start_boottime))
    return 2;
  if (pid <= 0 || tgid <= 0 || !birth || (__u32)current != (__u32)pid ||
      (__u32)(current >> 32) != (__u32)tgid)
    return 2;
  event->tid = pid;
  event->tgid = tgid;
  event->birth_boottime_ns = birth;
  return 0;
}

static __always_inline int pid_namespace(struct task_struct *p, __u32 *result) {
  struct pid *pid = 0;
  struct pid_namespace *ns = 0;
  __u32 level = 0, inum = 0;
  const char *base;
  if (!p)
    return 1;
  if (READ_FIELD(pid, p, thread_pid))
    return 2;
  if (!pid)
    return 1;
  if (READ_FIELD(level, pid, level))
    return 2;
  /* Linux MAX_PID_NS_LEVEL is 32. Compute the actual task namespace,
   * not nsproxy->pid_ns_for_children, which may describe a different one. */
  if (level > 32)
    return 2;
  base = (const char *)pid + bpf_core_field_offset(struct pid, numbers) +
         level * bpf_core_type_size(struct upid) +
         bpf_core_field_offset(struct upid, ns);
  if (bpf_core_read(&ns, sizeof(ns), base))
    return 2;
  if (!ns)
    return 1;
  if (READ_FIELD(inum, ns, ns.inum) || !inum)
    return 2;
  *result = inum;
  return 0;
}

static __always_inline int mount_namespace(struct task_struct *p,
                                           __u32 *result) {
  struct nsproxy *proxy = 0;
  struct mnt_namespace *ns = 0;
  __u32 inum = 0;
  if (!p)
    return 1;
  if (READ_FIELD(proxy, p, nsproxy))
    return 2;
  if (!proxy)
    return 1;
  if (READ_FIELD(ns, proxy, mnt_ns))
    return 2;
  if (!ns)
    return 1;
  if (READ_FIELD(inum, ns, ns.inum) || !inum)
    return 2;
  *result = inum;
  return 0;
}

#define RECORD_GROUP(event, bit, expression)                                   \
  do {                                                                         \
    int result_ = (expression);                                                \
    if (result_ == 0)                                                          \
      (event)->status |= (bit);                                                \
    else if (result_ == 1)                                                     \
      (event)->unavailable |= (bit);                                           \
    else                                                                       \
      (event)->read_error |= (bit);                                            \
  } while (0)

SEC("tp_btf/sched_process_exec")
int BPF_PROG(e3_sched_process_exec, struct task_struct *p, int old_pid,
             struct linux_binprm *bprm) {
  __u32 key = 0;
  struct e3_bpf_state *state = bpf_map_lookup_elem(&e3_state, &key);
  struct e3_bpf_exec_event *e;
  struct file *binfile = 0, *exefile = 0;
  struct mm_struct *mm = 0;
  __u64 cgroup = bpf_get_current_cgroup_id(), prior;
  int result;

  /* Surface broken configuration as an invalid frame when possible. If the
   * map and ring both fail, only the independent stop join can expose loss. */
  if (!state || !state->target_cgroup_id) {
    e = bpf_ringbuf_reserve(&e3_events, sizeof(*e), 0);
    if (e) {
      __builtin_memset(e, 0, sizeof(*e));
      bpf_ringbuf_submit(e, 0);
    }
    return 0;
  }
  if (cgroup != state->target_cgroup_id)
    return 0;
  prior = __sync_fetch_and_add(&state->attempts, 1);
  if (prior >= E3_BPF_MAX_EVENTS) {
    __sync_fetch_and_or(&state->overflow, 1);
    return 0;
  }
  e = bpf_ringbuf_reserve(&e3_events, sizeof(*e), 0);
  if (!e) {
    __sync_fetch_and_add(&state->loss, 1);
    return 0;
  }
  __builtin_memset(e, 0, sizeof(*e));
  e->version = E3_BPF_VERSION;
  e->length = sizeof(*e);
  e->sequence = prior + 1;
  e->cgroup_id = cgroup;
  e->old_tid = old_pid > 0 ? (__u32)old_pid : 0;
  RECORD_GROUP(e, E3_BPF_TASK_OK, task_identity(p, e));
  RECORD_GROUP(e, E3_BPF_PID_NS_OK, pid_namespace(p, &e->pid_namespace_inode));
  RECORD_GROUP(e, E3_BPF_MNT_NS_OK,
               mount_namespace(p, &e->mount_namespace_inode));

  result = !bprm ? 1
           : READ_FIELD(binfile, bprm, file)
               ? 2
               : object_from_file(binfile, &e->binprm);
  RECORD_GROUP(e, E3_BPF_BINPRM_OK, result);
  result = !p                      ? 1
           : READ_FIELD(mm, p, mm) ? 2
           : !mm                   ? 1
           : READ_FIELD(exefile, mm, exe_file)
               ? 2
               : object_from_file(exefile, &e->exe);
  RECORD_GROUP(e, E3_BPF_EXE_OK, result);
  if (e->status != E3_BPF_ALL_OK || e->unavailable || e->read_error ||
      !e->old_tid)
    __sync_fetch_and_add(&state->extraction_errors, 1);
  __sync_fetch_and_add(&state->submitted, 1);
  bpf_ringbuf_submit(e, 0);
  return 0;
}
