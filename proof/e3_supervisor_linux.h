#ifndef E3_SUPERVISOR_LINUX_H
#define E3_SUPERVISOR_LINUX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* These primitives do not qualify the supervisor topology or admit payloads.
 * Callers must establish the launch binding and same-UID isolation separately.
 */
#define E3_FRAME_MAX 4096U
#define E3_FRAME_MAGIC UINT32_C(0x45335731)

struct e3_channel {
  int fd;
  uint64_t next_send;
  uint64_t next_recv;
};

/* expected_pid is obtained from the C-owned launch, never a payload message.
 * Takes ownership of fd on success only.  The socket must be connected and
 * SOCK_SEQPACKET; inherited socketpair peer-credential semantics must be
 * qualified for the actual launcher before this can authenticate its peer.
 */
int e3_channel_init(struct e3_channel *channel, int fd, pid_t expected_pid,
                    uid_t expected_uid, gid_t expected_gid,
                    unsigned timeout_ms);
int e3_channel_send(struct e3_channel *channel, uint32_t type,
                    const void *payload, size_t length);
int e3_channel_receive(struct e3_channel *channel, uint32_t *type,
                       void *payload, size_t capacity, size_t *length);
void e3_channel_close(struct e3_channel *channel);

struct e3_object_id {
  uint64_t device;
  uint64_t inode;
  uint64_t size;
};
struct e3_custody {
  int output_fd;
  int reference_fd;
  struct e3_object_id id;
};

/* Duplicates the caller's opened descriptors with close-on-exec. Callers must
 * have stopped all relevant tasks and established writer exclusion themselves.
 * Same dev/inode here is not a cross-namespace mount identity mapping.
 */
int e3_custody_bind(struct e3_custody *custody, int output_fd, int reference_fd,
                    uint64_t max_bytes);
/* Checks the held reference and a separately opened exec descriptor. This
 * does not establish that exec_fd came from a synchronous /proc/pid/exe stop.
 */
int e3_custody_match_exec(const struct e3_custody *custody, int exec_fd);
/* Stream bytes from the retained descriptor with a strict bound and check for
 * obvious size/identity changes. This does not itself establish writer
 * exclusion. The consumer returns 0 on success; nonzero aborts the operation.
 */
int e3_custody_stream(const struct e3_custody *custody, uint64_t max_bytes,
                      int (*consume)(const void *, size_t, void *),
                      void *context);
void e3_custody_close(struct e3_custody *custody);

/* Refuses if not nonroot UID/GID 65534, NNP, seccomp filter mode, or if any
 * effective/permitted/inheritable/ambient capability is present. Filter mode
 * does not prove the filter is Docker's unchanged default profile.
 */
int e3_check_process_restrictions(void);

#endif
