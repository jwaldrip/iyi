#ifndef BPF_CANARY_KERNEL_TYPES_H
#define BPF_CANARY_KERNEL_TYPES_H

/*
 * Minimal CO-RE definitions for tp_btf/sched_process_exec.
 * Used when full vmlinux.h is not generated.
 * Uses explicit integer types (__u32, int, unsigned long)
 * without hosted sys/types.h libc dependencies.
 */

#include "bpf_canary_types.h"

#ifndef BPF_TARGET
#if defined(__bpf__) || defined(__BPF__)
#define BPF_TARGET 1
#endif
#endif

#if defined(BPF_TARGET) && !defined(BPF_NO_PRESERVE_ACCESS_INDEX)
#define __preserve_access __attribute__((preserve_access_index))
#else
#define __preserve_access
#endif

struct super_block {
  __u32 s_dev;
} __preserve_access;

struct inode {
  unsigned long i_ino;
  struct super_block *i_sb;
} __preserve_access;

struct file {
  struct inode *f_inode;
} __preserve_access;

struct linux_binprm {
  struct file *file;
} __preserve_access;

struct mm_struct {
  struct file *exe_file;
} __preserve_access;

struct task_struct {
  int pid;
  int tgid;
  struct mm_struct *mm;
} __preserve_access;

#endif /* BPF_CANARY_KERNEL_TYPES_H */
