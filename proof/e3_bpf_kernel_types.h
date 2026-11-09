#ifndef E3_BPF_KERNEL_TYPES_H
#define E3_BPF_KERNEL_TYPES_H
#include <linux/types.h>
#define E3_CORE __attribute__((preserve_access_index))
struct ns_common {
  unsigned int inum;
} E3_CORE;
struct pid_namespace {
  struct ns_common ns;
} E3_CORE;
struct mnt_namespace {
  struct ns_common ns;
} E3_CORE;
struct upid {
  int nr;
  struct pid_namespace *ns;
} E3_CORE;
struct pid {
  unsigned int level;
  struct upid numbers[1];
} E3_CORE;
struct nsproxy {
  struct mnt_namespace *mnt_ns;
} E3_CORE;
struct super_block {
  __u32 s_dev;
} E3_CORE;
struct inode {
  unsigned long i_ino;
  __u16 i_mode;
  long long i_size;
  struct super_block *i_sb;
} E3_CORE;
struct vfsmount {
  void *mnt_root;
} E3_CORE;
struct mount {
  struct vfsmount mnt;
  int mnt_id;
} E3_CORE;
struct path {
  struct vfsmount *mnt;
  void *dentry;
} E3_CORE;
struct file {
  struct inode *f_inode;
  struct path f_path;
} E3_CORE;
struct linux_binprm {
  struct file *file;
} E3_CORE;
struct mm_struct {
  struct file *exe_file;
} E3_CORE;
struct task_struct {
  int pid;
  int tgid;
  __u64 start_boottime;
  struct pid *thread_pid;
  struct nsproxy *nsproxy;
  struct mm_struct *mm;
} E3_CORE;
#endif
