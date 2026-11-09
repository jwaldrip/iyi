#ifndef E3_BPF_HOST_H
#define E3_BPF_HOST_H

#include "e3_bpf_types.h"
#include <stddef.h>
#include <stdint.h>

/* Capture is a component witness, never an E3 proof or source-slot receipt. */
struct e3_bpf_capture {
  struct e3_bpf_exec_event *events;
  unsigned char *sequences;
  size_t count;
  size_t capacity;
  uint64_t cgroup_id;
  struct e3_bpf_state counters;
  uint64_t independent_exec_stops;
  int failed;
  int finished;
};

int e3_bpf_capture_init(struct e3_bpf_capture *, uint64_t cgroup_id,
                        size_t capacity);
int e3_bpf_capture_record(struct e3_bpf_capture *, const void *, size_t);
int e3_bpf_capture_finish(struct e3_bpf_capture *, const struct e3_bpf_state *,
                          uint64_t independent_exec_stops);
void e3_bpf_capture_destroy(struct e3_bpf_capture *);

/* All fields are local native-endian. A reader must require exact length,
 * version and strict_eligible == 0; event/stop identity joins are separate. */
struct e3_bpf_report_header {
  __u32 version;
  __u32 header_length;
  __u32 event_length;
  __u32 strict_eligible;
  __u64 event_count;
  __u64 target_cgroup_id;
  struct e3_bpf_state counters;
  __u64 independent_exec_stops;
};
int e3_bpf_capture_write(const struct e3_bpf_capture *, int fd);
/* Reads a bounded regular file from offset zero, requiring exact EOF.
 * The caller must authenticate file custody separately. */
int e3_bpf_capture_read(struct e3_bpf_capture *, int fd, size_t event_limit,
                        uint64_t expected_cgroup,
                        uint64_t independent_exec_stops);

struct e3_bpf_observer;
/* The caller pins and reviews object_path, protects the FD and ensures the
 * payload has no observer capabilities. Open checks this process's IDs,
 * groups, no_new_privs and BPF/PERFMON-only capability sets. */
struct e3_bpf_observer *e3_bpf_observer_open(const char *object_path,
                                             uint64_t cgroup_id,
                                             size_t event_limit);
int e3_bpf_observer_poll(struct e3_bpf_observer *, int timeout_ms);
/* Call only after externally verified workload quiescence. Destroys the link,
 * drains and reads counters; the caller still joins each event to a stop and
 * proves descriptor custody and the scope of all descendants. */
int e3_bpf_observer_finish(struct e3_bpf_observer *,
                           uint64_t independent_exec_stops);
const struct e3_bpf_capture *
e3_bpf_observer_capture(const struct e3_bpf_observer *);
/* Always destroys all owned links, ring, object and allocations. */
void e3_bpf_observer_close(struct e3_bpf_observer *);

#endif
