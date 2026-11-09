#define _GNU_SOURCE
#include "e3_supervisor_linux.h"

#include <errno.h>
#ifdef __linux__
#include <fcntl.h>
#include <linux/capability.h>
#include <stdint.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

/* All framing fields are little-endian and are encoded explicitly. */
#define HEADER 20U
static void put32(unsigned char *p, uint32_t x) {
  for (unsigned i = 0; i < 4; i++)
    p[i] = (unsigned char)(x >> (8 * i));
}
static void put64(unsigned char *p, uint64_t x) {
  for (unsigned i = 0; i < 8; i++)
    p[i] = (unsigned char)(x >> (8 * i));
}
static uint32_t get32(const unsigned char *p) {
  uint32_t x = 0;
  for (unsigned i = 0; i < 4; i++)
    x |= (uint32_t)p[i] << (8 * i);
  return x;
}
static uint64_t get64(const unsigned char *p) {
  uint64_t x = 0;
  for (unsigned i = 0; i < 8; i++)
    x |= (uint64_t)p[i] << (8 * i);
  return x;
}
static int fail(void) {
  errno = EPROTO;
  return -1;
}

int e3_channel_init(struct e3_channel *c, int fd, pid_t pid, uid_t uid,
                    gid_t gid, unsigned timeout_ms) {
  struct ucred peer;
  socklen_t n = sizeof(peer);
  int type;
  socklen_t t = sizeof(type);
  if (!c || fd < 0 || pid <= 0 || !timeout_ms || timeout_ms > 60000)
    return fail();
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &t) || t != sizeof(type) ||
      type != SOCK_SEQPACKET ||
      getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &n) || n != sizeof(peer) ||
      peer.pid != pid || peer.uid != uid || peer.gid != gid)
    return fail();
  int flags = fcntl(fd, F_GETFD);
  struct timeval tv = {.tv_sec = timeout_ms / 1000,
                       .tv_usec = (timeout_ms % 1000) * 1000};
  if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) ||
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)))
    return -1;
  c->fd = fd;
  c->next_send = 0;
  c->next_recv = 0;
  return 0;
}
void e3_channel_close(struct e3_channel *c) {
  if (c && c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }
}
int e3_channel_send(struct e3_channel *c, uint32_t type, const void *payload,
                    size_t length) {
  unsigned char frame[HEADER + E3_FRAME_MAX];
  if (!c || c->fd < 0 || !type || length > E3_FRAME_MAX ||
      (length && !payload) || c->next_send == UINT64_MAX)
    return fail();
  put32(frame, E3_FRAME_MAGIC);
  put32(frame + 4, type);
  put32(frame + 8, (uint32_t)length);
  put64(frame + 12, c->next_send);
  if (length)
    memcpy(frame + HEADER, payload, length);
  ssize_t n = send(c->fd, frame, HEADER + length, MSG_NOSIGNAL);
  if (n < 0 || (size_t)n != HEADER + length) {
    e3_channel_close(c);
    return fail();
  }
  c->next_send++;
  return 0;
}
int e3_channel_receive(struct e3_channel *c, uint32_t *type, void *payload,
                       size_t capacity, size_t *length) {
  unsigned char frame[HEADER + E3_FRAME_MAX];
  /* Ancillary data is forbidden, but received rights must still be closed. */
  union {
    struct cmsghdr align;
    unsigned char bytes[CMSG_SPACE(256 * sizeof(int))];
  } control;
  struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
  struct msghdr msg = {.msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_control = control.bytes,
                       .msg_controllen = sizeof(control.bytes)};
  if (!c || c->fd < 0 || !type || !length || (capacity && !payload) ||
      c->next_recv == UINT64_MAX)
    return fail();
  ssize_t n = recvmsg(c->fd, &msg, MSG_CMSG_CLOEXEC);
  int ancillary = 0;
  if (n >= 0) {
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&msg); h; h = CMSG_NXTHDR(&msg, h)) {
      ancillary = 1;
      if (h->cmsg_level == SOL_SOCKET && h->cmsg_type == SCM_RIGHTS &&
          h->cmsg_len >= CMSG_LEN(0)) {
        size_t count = (h->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *fds = (int *)CMSG_DATA(h);
        for (size_t i = 0; i < count; i++)
          close(fds[i]);
      }
    }
  }
  if (n < (ssize_t)HEADER || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
      ancillary || get32(frame) != E3_FRAME_MAGIC || !get32(frame + 4) ||
      get64(frame + 12) != c->next_recv || get32(frame + 8) > E3_FRAME_MAX ||
      (size_t)n != HEADER + get32(frame + 8) || get32(frame + 8) > capacity) {
    e3_channel_close(c);
    return fail();
  }
  *type = get32(frame + 4);
  *length = get32(frame + 8);
  if (*length)
    memcpy(payload, frame + HEADER, *length);
  c->next_recv++;
  return 0;
}

static int object_stat(int fd, struct stat *s, uint64_t max_bytes) {
  if (fstat(fd, s) || !S_ISREG(s->st_mode) || s->st_size < 0 ||
      (uint64_t)s->st_size > max_bytes)
    return fail();
  return 0;
}
static int same(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size;
}
static int matches(const struct e3_custody *c, const struct stat *s) {
  return c->id.device == (uint64_t)s->st_dev &&
         c->id.inode == (uint64_t)s->st_ino &&
         c->id.size == (uint64_t)s->st_size;
}
int e3_custody_bind(struct e3_custody *c, int output, int reference,
                    uint64_t max) {
  struct stat a, b;
  if (!c || output < 0 || reference < 0)
    return fail();
  c->output_fd = c->reference_fd = -1;
  int out = fcntl(output, F_DUPFD_CLOEXEC, 3);
  if (out < 0)
    return -1;
  int ref = fcntl(reference, F_DUPFD_CLOEXEC, 3);
  if (ref < 0) {
    close(out);
    return -1;
  }
  if (object_stat(out, &a, max) || object_stat(ref, &b, max) ||
      a.st_nlink < 2 || b.st_nlink < 2 || !same(&a, &b)) {
    close(out);
    close(ref);
    return fail();
  }
  c->output_fd = out;
  c->reference_fd = ref;
  c->id.device = (uint64_t)a.st_dev;
  c->id.inode = (uint64_t)a.st_ino;
  c->id.size = (uint64_t)a.st_size;
  return 0;
}
int e3_custody_match_exec(const struct e3_custody *c, int fd) {
  struct stat a, b;
  if (!c || c->reference_fd < 0 || fd < 0 ||
      object_stat(c->reference_fd, &a, c->id.size) ||
      object_stat(fd, &b, c->id.size) || !matches(c, &a) || !same(&a, &b))
    return fail();
  return 0;
}
int e3_custody_stream(const struct e3_custody *c, uint64_t max,
                      int (*consume)(const void *, size_t, void *),
                      void *context) {
  struct stat before, after;
  unsigned char chunk[16384];
  if (!c || c->reference_fd < 0 || !consume || c->id.size > max ||
      object_stat(c->reference_fd, &before, max) || !matches(c, &before))
    return fail();
  uint64_t offset = 0;
  while (offset < c->id.size) {
    size_t want = c->id.size - offset < sizeof(chunk)
                      ? (size_t)(c->id.size - offset)
                      : sizeof(chunk);
    ssize_t n = pread(c->reference_fd, chunk, want, (off_t)offset);
    if (n <= 0 || (size_t)n > want || consume(chunk, (size_t)n, context))
      return fail();
    offset += (uint64_t)n;
  }
  if (object_stat(c->reference_fd, &after, max) || !same(&before, &after) ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
      before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
      before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
    return fail();
  return 0;
}
void e3_custody_close(struct e3_custody *c) {
  if (!c)
    return;
  if (c->output_fd >= 0)
    close(c->output_fd);
  if (c->reference_fd >= 0)
    close(c->reference_fd);
  c->output_fd = c->reference_fd = -1;
}
int e3_check_process_restrictions(void) {
  uid_t r, e, s;
  gid_t gr, ge, gs;
  struct __user_cap_header_struct h = {.version = _LINUX_CAPABILITY_VERSION_3,
                                       .pid = 0};
  struct __user_cap_data_struct data[2] = {{0}};
  if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) || r != 65534 ||
      e != 65534 || s != 65534 || gr != 65534 || ge != 65534 || gs != 65534 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2 || syscall(SYS_capget, &h, data))
    return fail();
  for (unsigned i = 0; i < 2; i++)
    if (data[i].effective || data[i].permitted || data[i].inheritable)
      return fail();
  for (int cap = 0; cap <= CAP_LAST_CAP; cap++)
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0) != 0)
      return fail();
  return 0;
}
#else
/* Unsupported platforms cannot construct a qualifying channel or custody. */
int e3_channel_init(struct e3_channel *c, int fd, pid_t p, uid_t u, gid_t g,
                    unsigned t) {
  (void)c;
  (void)fd;
  (void)p;
  (void)u;
  (void)g;
  (void)t;
  errno = ENOTSUP;
  return -1;
}
int e3_channel_send(struct e3_channel *c, uint32_t t, const void *p, size_t n) {
  (void)c;
  (void)t;
  (void)p;
  (void)n;
  errno = ENOTSUP;
  return -1;
}
int e3_channel_receive(struct e3_channel *c, uint32_t *t, void *p, size_t n,
                       size_t *l) {
  (void)c;
  (void)t;
  (void)p;
  (void)n;
  (void)l;
  errno = ENOTSUP;
  return -1;
}
void e3_channel_close(struct e3_channel *c) { (void)c; }
int e3_custody_bind(struct e3_custody *c, int o, int r, uint64_t m) {
  (void)c;
  (void)o;
  (void)r;
  (void)m;
  errno = ENOTSUP;
  return -1;
}
int e3_custody_match_exec(const struct e3_custody *c, int f) {
  (void)c;
  (void)f;
  errno = ENOTSUP;
  return -1;
}
int e3_custody_stream(const struct e3_custody *c, uint64_t m,
                      int (*fn)(const void *, size_t, void *), void *x) {
  (void)c;
  (void)m;
  (void)fn;
  (void)x;
  errno = ENOTSUP;
  return -1;
}
void e3_custody_close(struct e3_custody *c) { (void)c; }
int e3_check_process_restrictions(void) {
  errno = ENOTSUP;
  return -1;
}
#endif
