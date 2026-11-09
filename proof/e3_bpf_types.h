#ifndef E3_BPF_TYPES_H
#define E3_BPF_TYPES_H

#if defined(__linux__) || defined(__bpf__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

#define E3_BPF_VERSION 1U
#define E3_BPF_MAX_EVENTS 65536U
#define E3_BPF_RING_BYTES (256U * 1024U)

/* Each bit is set only after every read in that group succeeded. */
#define E3_BPF_TASK_OK (1U << 0)
#define E3_BPF_PID_NS_OK (1U << 1)
#define E3_BPF_MNT_NS_OK (1U << 2)
#define E3_BPF_BINPRM_OK (1U << 3)
#define E3_BPF_EXE_OK (1U << 4)
#define E3_BPF_ALL_OK                                                          \
  (E3_BPF_TASK_OK | E3_BPF_PID_NS_OK | E3_BPF_MNT_NS_OK | E3_BPF_BINPRM_OK |   \
   E3_BPF_EXE_OK)

struct e3_bpf_object {
  __u64 dev; /* Linux userspace st_dev encoding */
  __u64 inode;
  __u64 size;
  __u32 mount_id; /* ID in the observed task's mount namespace */
  __u32 mode;
};

/* Native-endian local ABI, version and exact length checked by the reader. */
struct e3_bpf_exec_event {
  __u32 version;
  __u32 length;
  __u32 status;
  __u32 reserved;
  __u32 unavailable; /* group contained a missing kernel pointer */
  __u32 read_error;  /* group had a failed kernel memory read */
  __u64 sequence;
  __u64 cgroup_id;
  __u64 birth_boottime_ns;
  __u32 tid;
  __u32 tgid;
  __u32 old_tid; /* tracepoint old_pid, important for nonleader exec */
  __u32 pid_namespace_inode;
  __u32 mount_namespace_inode;
  __u32 reserved2;
  struct e3_bpf_object binprm;
  struct e3_bpf_object exe;
};

/* One preallocated array entry, configured before attachment. */
struct e3_bpf_state {
  __u64 target_cgroup_id;
  __u64 attempts;
  __u64 submitted;
  __u64 loss;
  __u64 extraction_errors;
  __u64 overflow;
};

#endif
