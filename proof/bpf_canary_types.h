#ifndef BPF_CANARY_TYPES_H
#define BPF_CANARY_TYPES_H

#if defined(__KERNEL__) && !defined(__BPF__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/*
 * Event structure emitted by tp_btf/sched_process_exec.
 * Represents an authenticated successful execution event for a kernel file
 * object. Dev and inode identify the executed regular file in the kernel
 * filesystem.
 */
struct exec_event {
  __u64 cgroup_id;
  __u64 dev;
  __u64 inode;
  __u32 pid;
  __u32 tgid;
  char comm[16];
};

enum bpf_canary_config_key {
  BPF_CANARY_CFG_TARGET_CGROUP = 0,
  BPF_CANARY_CFG_FILTER_ENABLED = 1,
  BPF_CANARY_CFG_SIMULATE_LOSS = 2,
  BPF_CANARY_CFG_TARGET_TGID = 3,
  BPF_CANARY_CFG_MAX = 4,
};

enum bpf_canary_loss_key {
  BPF_CANARY_LOSS_COUNT = 0,
  BPF_CANARY_ERROR_COUNT = 1,
  BPF_CANARY_EVENT_COUNT = 2,
  BPF_CANARY_STAT_MAX = 3,
};

#endif /* BPF_CANARY_TYPES_H */
