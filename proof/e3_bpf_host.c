#define _GNU_SOURCE
#include "e3_bpf_host.h"
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

struct e3_bpf_observer {
  struct bpf_object *object;
  struct bpf_link *link;
  struct ring_buffer *ring;
  struct e3_bpf_capture capture;
  int state_fd;
  int detached;
};

static int event_callback(void *ctx, void *data, size_t length) {
  return e3_bpf_capture_record(ctx, data, length);
}

static int verify_observer_privileges(void) {
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;
  struct __user_cap_header_struct hdr = {.version = _LINUX_CAPABILITY_VERSION_3,
                                         .pid = 0};
  struct __user_cap_data_struct data[2] = {{0}, {0}};
  const uint64_t expected = (1ULL << 38) | (1ULL << 39);
  uint64_t effective, permitted, inheritable, bounding = 0, ambient = 0;
  int bound_seen = 0, ambient_seen = 0;
  if (getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) ||
      !ruid || !euid || !suid || !rgid || !egid || !sgid ||
      getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      syscall(SYS_capget, &hdr, data))
    goto denied;
  effective = ((uint64_t)data[1].effective << 32) | data[0].effective;
  permitted = ((uint64_t)data[1].permitted << 32) | data[0].permitted;
  inheritable = ((uint64_t)data[1].inheritable << 32) | data[0].inheritable;
  for (int cap = 0; cap < 64; ++cap) {
    int result = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (result < 0) {
      if (errno != EINVAL)
        goto denied;
      break;
    }
    bound_seen = cap + 1;
    if (result)
      bounding |= 1ULL << cap;
  }
  for (int cap = 0; cap < 64; ++cap) {
    int result = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
    if (result < 0) {
      if (errno != EINVAL)
        goto denied;
      break;
    }
    ambient_seen = cap + 1;
    if (result)
      ambient |= 1ULL << cap;
  }
  if (bound_seen < 40 || ambient_seen < 40 || effective != expected ||
      permitted != expected || ((inheritable | bounding | ambient) & ~expected))
    goto denied;
  return 0;
denied:
  errno = EPERM;
  return -1;
}

static int verify_hook(struct bpf_program *program, struct bpf_link *link) {
  struct bpf_prog_info pi = {0};
  struct bpf_link_info li = {0};
  struct btf *btf;
  const struct btf_type *type;
  const char *name;
  char tp[128] = {0};
  __u32 pi_size = sizeof(pi), li_size = sizeof(li);
  int valid;
  li.raw_tracepoint.tp_name = (__u64)(uintptr_t)tp;
  li.raw_tracepoint.tp_name_len = sizeof(tp);
  if (bpf_program__fd(program) < 0 || bpf_link__fd(link) < 0 ||
      bpf_obj_get_info_by_fd(bpf_program__fd(program), &pi, &pi_size) ||
      bpf_obj_get_info_by_fd(bpf_link__fd(link), &li, &li_size))
    return -1;
  if (!pi.id || pi.type != BPF_PROG_TYPE_TRACING || !pi.attach_btf_id ||
      !li.id || li.type != BPF_LINK_TYPE_RAW_TRACEPOINT ||
      li.prog_id != pi.id || !memchr(tp, '\0', sizeof(tp)) ||
      strcmp(tp, "sched_process_exec")) {
    errno = EPROTO;
    return -1;
  }
  btf = btf__load_vmlinux_btf();
  if (!btf || libbpf_get_error(btf)) {
    errno = EIO;
    return -1;
  }
  type = btf__type_by_id(btf, pi.attach_btf_id);
  name = type ? btf__name_by_offset(btf, type->name_off) : NULL;
  valid = type && BTF_INFO_KIND(type->info) == BTF_KIND_TYPEDEF && name &&
          !strcmp(name, "btf_trace_sched_process_exec");
  btf__free(btf);
  if (!valid) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

struct e3_bpf_observer *e3_bpf_observer_open(const char *path, uint64_t cgroup,
                                             size_t limit) {
  struct e3_bpf_observer *o = NULL;
  struct bpf_program *program;
  struct bpf_map *state_map, *events_map;
  struct e3_bpf_state state = {0};
  __u32 key = 0;
  int err;
  if (!path || !*path || !cgroup || !limit || limit > E3_BPF_MAX_EVENTS) {
    errno = EINVAL;
    return NULL;
  }
  if (verify_observer_privileges())
    return NULL;
  o = calloc(1, sizeof(*o));
  if (!o)
    return NULL;
  o->state_fd = -1;
  if (e3_bpf_capture_init(&o->capture, cgroup, limit))
    goto error;
  o->object = bpf_object__open_file(path, NULL);
  err = libbpf_get_error(o->object);
  if (err || !o->object) {
    o->object = NULL;
    errno = err ? -err : EIO;
    goto error;
  }
  err = bpf_object__load(o->object);
  if (err) {
    errno = -err;
    goto error;
  }
  state_map = bpf_object__find_map_by_name(o->object, "e3_state");
  events_map = bpf_object__find_map_by_name(o->object, "e3_events");
  program =
      bpf_object__find_program_by_name(o->object, "e3_sched_process_exec");
  if (!state_map || !events_map || !program) {
    errno = ENOENT;
    goto error;
  }
  if (!bpf_program__section_name(program) ||
      strcmp(bpf_program__section_name(program), "tp_btf/sched_process_exec") ||
      bpf_program__type(program) != BPF_PROG_TYPE_TRACING) {
    errno = EPROTO;
    goto error;
  }
  if (bpf_map__type(state_map) != BPF_MAP_TYPE_ARRAY ||
      bpf_map__key_size(state_map) != sizeof(key) ||
      bpf_map__value_size(state_map) != sizeof(state) ||
      bpf_map__max_entries(state_map) != 1 ||
      bpf_map__type(events_map) != BPF_MAP_TYPE_RINGBUF ||
      bpf_map__max_entries(events_map) != E3_BPF_RING_BYTES) {
    errno = EPROTO;
    goto error;
  }
  o->state_fd = bpf_map__fd(state_map);
  if (o->state_fd < 0 || bpf_map__fd(events_map) < 0) {
    errno = EBADF;
    goto error;
  }
  state.target_cgroup_id = cgroup;
  if (bpf_map_update_elem(o->state_fd, &key, &state, BPF_ANY))
    goto error;
  {
    struct e3_bpf_state readback = {0};
    if (bpf_map_lookup_elem(o->state_fd, &key, &readback))
      goto error;
    if (memcmp(&readback, &state, sizeof(state))) {
      errno = EPROTO;
      goto error;
    }
  }
  o->ring = ring_buffer__new(bpf_map__fd(events_map), event_callback,
                             &o->capture, NULL);
  err = libbpf_get_error(o->ring);
  if (err || !o->ring) {
    o->ring = NULL;
    errno = err ? -err : EIO;
    goto error;
  }
  o->link = bpf_program__attach(program);
  err = libbpf_get_error(o->link);
  if (err || !o->link) {
    o->link = NULL;
    errno = err ? -err : EIO;
    goto error;
  }
  if (verify_hook(program, o->link))
    goto error;
  return o;
error:
  err = errno ? errno : EIO;
  e3_bpf_observer_close(o);
  errno = err;
  return NULL;
}

int e3_bpf_observer_poll(struct e3_bpf_observer *o, int timeout_ms) {
  int n;
  if (!o || !o->ring || !o->link || o->detached || o->capture.failed ||
      timeout_ms < 0) {
    errno = EINVAL;
    return -1;
  }
  n = ring_buffer__poll(o->ring, timeout_ms);
  if (n < 0 || o->capture.failed) {
    o->capture.failed = 1;
    if (n < 0)
      errno = -n;
    return -1;
  }
  return n;
}

int e3_bpf_observer_finish(struct e3_bpf_observer *o, uint64_t stops) {
  struct e3_bpf_state state = {0};
  __u32 key = 0;
  int n, rc;
  if (!o || !o->link || !o->ring || o->detached || o->capture.failed) {
    if (o)
      o->capture.failed = 1;
    errno = EINVAL;
    return -1;
  }
  rc = bpf_link__destroy(o->link);
  o->link = NULL;
  o->detached = 1;
  if (rc) {
    o->capture.failed = 1;
    errno = rc < 0 ? -rc : EIO;
    return -1;
  }
  do {
    n = ring_buffer__consume(o->ring);
    if (n < 0 || o->capture.failed) {
      o->capture.failed = 1;
      if (n < 0)
        errno = -n;
      return -1;
    }
  } while (n > 0);
  if (bpf_map_lookup_elem(o->state_fd, &key, &state)) {
    o->capture.failed = 1;
    return -1;
  }
  ring_buffer__free(o->ring);
  o->ring = NULL;
  bpf_object__close(o->object);
  o->object = NULL;
  o->state_fd = -1;
  return e3_bpf_capture_finish(&o->capture, &state, stops);
}

const struct e3_bpf_capture *
e3_bpf_observer_capture(const struct e3_bpf_observer *o) {
  return o && o->detached && o->capture.finished && !o->capture.failed
             ? &o->capture
             : NULL;
}

void e3_bpf_observer_close(struct e3_bpf_observer *o) {
  if (!o)
    return;
  if (o->link)
    bpf_link__destroy(o->link);
  if (o->ring)
    ring_buffer__free(o->ring);
  if (o->object)
    bpf_object__close(o->object);
  e3_bpf_capture_destroy(&o->capture);
  free(o);
}
