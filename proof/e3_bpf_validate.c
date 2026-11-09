#define _POSIX_C_SOURCE 200809L
#include "e3_bpf_host.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(struct e3_bpf_capture *c) {
  if (c)
    c->failed = 1;
  errno = EPROTO;
  return -1;
}

int e3_bpf_capture_init(struct e3_bpf_capture *c, uint64_t cgroup,
                        size_t limit) {
  if (!c || !cgroup || !limit || limit > E3_BPF_MAX_EVENTS) {
    errno = EINVAL;
    return -1;
  }
  memset(c, 0, sizeof(*c));
  c->events = calloc(limit, sizeof(*c->events));
  c->sequences = calloc(limit, 1);
  if (!c->events || !c->sequences) {
    e3_bpf_capture_destroy(c);
    errno = ENOMEM;
    return -1;
  }
  c->capacity = limit;
  c->cgroup_id = cgroup;
  return 0;
}

int e3_bpf_capture_record(struct e3_bpf_capture *c, const void *data,
                          size_t len) {
  struct e3_bpf_exec_event e;
  if (!c || c->failed || c->finished || !data || len != sizeof(e) ||
      !c->events || !c->sequences || c->count >= c->capacity)
    return fail(c);
  /* Ring records need not be aligned for a C struct load. */
  memcpy(&e, data, sizeof(e));
  if (e.version != E3_BPF_VERSION || e.length != sizeof(e) || e.reserved ||
      e.reserved2 || e.status != E3_BPF_ALL_OK || e.unavailable ||
      e.read_error || e.cgroup_id != c->cgroup_id || !e.sequence ||
      e.sequence > c->capacity || !e.tid || !e.tgid || !e.old_tid ||
      !e.birth_boottime_ns || !e.pid_namespace_inode ||
      !e.mount_namespace_inode || !e.binprm.inode || !e.binprm.mount_id ||
      (e.binprm.mode & 0170000U) != 0100000U || e.binprm.dev != e.exe.dev ||
      e.binprm.inode != e.exe.inode || e.binprm.mount_id != e.exe.mount_id ||
      e.binprm.mode != e.exe.mode || e.binprm.size != e.exe.size ||
      c->sequences[e.sequence - 1])
    return fail(c);
  c->sequences[e.sequence - 1] = 1;
  c->events[c->count++] = e;
  return 0;
}

int e3_bpf_capture_finish(struct e3_bpf_capture *c,
                          const struct e3_bpf_state *s, uint64_t stops) {
  if (!c || !s || c->failed || c->finished || !c->events || !c->sequences ||
      !stops || stops > c->capacity || s->target_cgroup_id != c->cgroup_id ||
      s->loss || s->extraction_errors || s->overflow || s->attempts != stops ||
      s->submitted != stops || c->count != stops)
    return fail(c);
  for (size_t i = 0; i < c->count; ++i)
    if (!c->sequences[i])
      return fail(c);
  c->counters = *s;
  c->independent_exec_stops = stops;
  c->finished = 1;
  return 0;
}

void e3_bpf_capture_destroy(struct e3_bpf_capture *c) {
  if (!c)
    return;
  free(c->events);
  free(c->sequences);
  memset(c, 0, sizeof(*c));
}

static int write_exact(int fd, const void *data, size_t len) {
  ssize_t n;
  do {
    n = write(fd, data, len);
  } while (n < 0 && errno == EINTR);
  if (n < 0 || (size_t)n != len) {
    if (n >= 0)
      errno = EIO;
    return -1;
  }
  return 0;
}

int e3_bpf_capture_write(const struct e3_bpf_capture *c, int fd) {
  struct e3_bpf_report_header h;
  if (!c || !c->finished || c->failed || fd < 0 || !c->count || !c->events) {
    errno = EINVAL;
    return -1;
  }
  memset(&h, 0, sizeof(h));
  h.version = E3_BPF_VERSION;
  h.header_length = sizeof(h);
  h.event_length = sizeof(*c->events);
  h.strict_eligible = 0;
  h.event_count = c->count;
  h.target_cgroup_id = c->cgroup_id;
  h.counters = c->counters;
  h.independent_exec_stops = c->independent_exec_stops;
  if (write_exact(fd, &h, sizeof(h)) ||
      write_exact(fd, c->events, c->count * sizeof(*c->events)))
    return -1;
  return 0;
}

static int read_exact_at(int fd, void *data, size_t len, off_t offset) {
  ssize_t n;
  do {
    n = pread(fd, data, len, offset);
  } while (n < 0 && errno == EINTR);
  if (n < 0 || (size_t)n != len) {
    if (n >= 0)
      errno = EIO;
    return -1;
  }
  return 0;
}

int e3_bpf_capture_read(struct e3_bpf_capture *c, int fd, size_t limit,
                        uint64_t expected_cgroup, uint64_t independent_stops) {
  struct e3_bpf_report_header h;
  struct e3_bpf_exec_event event;
  struct stat before, after;
  size_t expected;
  int saved;
  if (!c || fd < 0 || !limit || limit > E3_BPF_MAX_EVENTS || !expected_cgroup ||
      !independent_stops) {
    errno = EINVAL;
    return -1;
  }
  memset(c, 0, sizeof(*c));
  if (fstat(fd, &before) || !S_ISREG(before.st_mode) ||
      before.st_size < (off_t)sizeof(h) || read_exact_at(fd, &h, sizeof(h), 0))
    return fail(c);
  if (h.version != E3_BPF_VERSION || h.header_length != sizeof(h) ||
      h.event_length != sizeof(event) || h.strict_eligible || !h.event_count ||
      h.event_count > limit || h.target_cgroup_id != expected_cgroup ||
      h.independent_exec_stops != independent_stops)
    return fail(c);
  expected = sizeof(h) + (size_t)h.event_count * sizeof(event);
  if (before.st_size != (off_t)expected ||
      e3_bpf_capture_init(c, h.target_cgroup_id, limit))
    return fail(c);
  for (size_t i = 0; i < (size_t)h.event_count; ++i) {
    if (read_exact_at(fd, &event, sizeof(event),
                      (off_t)(sizeof(h) + i * sizeof(event))) ||
        e3_bpf_capture_record(c, &event, sizeof(event)))
      goto error;
  }
  if (fstat(fd, &after) || after.st_size != before.st_size ||
      after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
      e3_bpf_capture_finish(c, &h.counters, independent_stops))
    goto error;
  return 0;
error:
  saved = errno ? errno : EPROTO;
  e3_bpf_capture_destroy(c);
  c->failed = 1;
  errno = saved;
  return -1;
}
