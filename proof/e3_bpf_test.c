#define _POSIX_C_SOURCE 200809L
#include "e3_bpf_host.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static struct e3_bpf_exec_event event(unsigned long long seq) {
  struct e3_bpf_exec_event e = {0};
  e.version = E3_BPF_VERSION;
  e.length = sizeof(e);
  e.status = E3_BPF_ALL_OK;
  e.sequence = seq;
  e.cgroup_id = 42;
  e.birth_boottime_ns = 93;
  e.tid = 17;
  e.tgid = 17;
  e.old_tid = 17;
  e.pid_namespace_inode = 19;
  e.mount_namespace_inode = 20;
  e.binprm.dev = 123;
  e.binprm.inode = 456;
  e.binprm.size = 789;
  e.binprm.mount_id = 9;
  e.binprm.mode = 0100755;
  e.exe = e.binprm;
  return e;
}

static void must_reject(struct e3_bpf_exec_event e) {
  struct e3_bpf_capture c;
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(e3_bpf_capture_record(&c, &e, sizeof(e)) < 0);
  assert(c.failed);
  e3_bpf_capture_destroy(&c);
}

static void valid_and_record_failures(void) {
  struct e3_bpf_capture c;
  struct e3_bpf_state s = {
      .target_cgroup_id = 42, .attempts = 2, .submitted = 2};
  struct e3_bpf_exec_event a = event(1), b = event(2), bad;
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(!e3_bpf_capture_record(&c, &b, sizeof(b)));
  assert(!e3_bpf_capture_record(&c, &a, sizeof(a)));
  assert(!e3_bpf_capture_finish(&c, &s, 2));
  assert(c.finished && c.count == 2);
  assert(e3_bpf_capture_record(&c, &a, sizeof(a)) < 0);
  e3_bpf_capture_destroy(&c);

#define REJECT(field, value)                                                   \
  do {                                                                         \
    bad = a;                                                                   \
    bad.field = (value);                                                       \
    must_reject(bad);                                                          \
  } while (0)
  REJECT(version, 2);
  REJECT(length, 0);
  REJECT(status, 0);
  REJECT(unavailable, E3_BPF_EXE_OK);
  REJECT(read_error, E3_BPF_TASK_OK);
  REJECT(reserved, 1);
  REJECT(reserved2, 1);
  REJECT(sequence, 0);
  REJECT(sequence, 5);
  REJECT(cgroup_id, 43);
  REJECT(tid, 0);
  REJECT(tgid, 0);
  REJECT(old_tid, 0);
  REJECT(birth_boottime_ns, 0);
  REJECT(pid_namespace_inode, 0);
  REJECT(mount_namespace_inode, 0);
  REJECT(binprm.inode, 0);
  REJECT(binprm.mount_id, 0);
  REJECT(exe.inode, 457);
  REJECT(exe.dev, 124);
  REJECT(exe.mount_id, 10);
  REJECT(exe.mode, 0100644);
  REJECT(exe.size, 790);
  bad = a;
  bad.binprm.mode = bad.exe.mode = 0040755;
  must_reject(bad);
#undef REJECT
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(e3_bpf_capture_record(&c, &a, sizeof(a) - 1) < 0);
  e3_bpf_capture_destroy(&c);
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(e3_bpf_capture_record(&c, &a, sizeof(a) + 1) < 0);
  e3_bpf_capture_destroy(&c);
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(!e3_bpf_capture_record(&c, &a, sizeof(a)));
  assert(e3_bpf_capture_record(&c, &a, sizeof(a)) < 0);
  e3_bpf_capture_destroy(&c);
}

static void counter_failures(void) {
  struct e3_bpf_capture c;
  struct e3_bpf_exec_event e = event(1);
  struct e3_bpf_state good = {
      .target_cgroup_id = 42, .attempts = 1, .submitted = 1};
  struct e3_bpf_state bad;
#define BAD_COUNTER(field, value)                                              \
  do {                                                                         \
    bad = good;                                                                \
    bad.field = (value);                                                       \
    assert(!e3_bpf_capture_init(&c, 42, 4));                                   \
    assert(!e3_bpf_capture_record(&c, &e, sizeof(e)));                         \
    assert(e3_bpf_capture_finish(&c, &bad, 1) < 0);                            \
    e3_bpf_capture_destroy(&c);                                                \
  } while (0)
  BAD_COUNTER(target_cgroup_id, 43);
  BAD_COUNTER(loss, 1);
  BAD_COUNTER(extraction_errors, 1);
  BAD_COUNTER(overflow, 1);
  BAD_COUNTER(attempts, 2);
  BAD_COUNTER(submitted, 0);
#undef BAD_COUNTER
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(!e3_bpf_capture_record(&c, &e, sizeof(e)));
  assert(e3_bpf_capture_finish(&c, &good, 2) < 0);
  e3_bpf_capture_destroy(&c);
  assert(!e3_bpf_capture_init(&c, 42, 4));
  assert(e3_bpf_capture_finish(&c, &good, 1) < 0);
  e3_bpf_capture_destroy(&c);
  assert(!e3_bpf_capture_init(&c, 42, 4));
  e.sequence = 2;
  assert(!e3_bpf_capture_record(&c, &e, sizeof(e)));
  assert(e3_bpf_capture_finish(&c, &good, 1) < 0);
  e3_bpf_capture_destroy(&c);
}

static void report_failures(void) {
  struct e3_bpf_capture source, decoded;
  struct e3_bpf_exec_event e = event(1);
  struct e3_bpf_state s = {
      .target_cgroup_id = 42, .attempts = 1, .submitted = 1};
  struct e3_bpf_report_header h;
  FILE *f = tmpfile();
  int fd;
  assert(f);
  fd = fileno(f);
  assert(!e3_bpf_capture_init(&source, 42, 4));
  assert(!e3_bpf_capture_record(&source, &e, sizeof(e)));
  assert(!e3_bpf_capture_finish(&source, &s, 1));
  assert(e3_bpf_capture_write(&source, -1) < 0);
  assert(!e3_bpf_capture_write(&source, fd));
  assert(!e3_bpf_capture_read(&decoded, fd, 4, 42, 1));
  assert(decoded.count == 1 && decoded.finished);
  e3_bpf_capture_destroy(&decoded);
  assert(e3_bpf_capture_read(&decoded, fd, 4, 43, 1) < 0);
  assert(e3_bpf_capture_read(&decoded, fd, 4, 42, 2) < 0);
  assert(e3_bpf_capture_read(&decoded, -1, 4, 42, 1) < 0);
  assert(pread(fd, &h, sizeof(h), 0) == (ssize_t)sizeof(h));
  h.strict_eligible = 1;
  assert(pwrite(fd, &h, sizeof(h), 0) == (ssize_t)sizeof(h));
  assert(e3_bpf_capture_read(&decoded, fd, 4, 42, 1) < 0);
  h.strict_eligible = 0;
  assert(pwrite(fd, &h, sizeof(h), 0) == (ssize_t)sizeof(h));
  assert(!ftruncate(fd, (off_t)(sizeof(h) + sizeof(e) - 1)));
  assert(e3_bpf_capture_read(&decoded, fd, 4, 42, 1) < 0);
  assert(!ftruncate(fd, (off_t)(sizeof(h) + sizeof(e) + 1)));
  assert(e3_bpf_capture_read(&decoded, fd, 4, 42, 1) < 0);
  e3_bpf_capture_destroy(&source);
  fclose(f);
}

int main(void) {
  valid_and_record_failures();
  counter_failures();
  report_failures();
  return 0;
}
