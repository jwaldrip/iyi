# iyi: `<poll.h>`'s constants, added for the build daemon's single-fiber
# server loop (src/compiler/iyi/command/daemon.cr requires "c/poll" under
# -Dwithout_mt). The values are darwin's own and match POSIX; POLLRDHUP is
# absent because darwin has no such event — a peer's half-close arrives as
# POLLIN with a zero-byte read.
lib LibC
  POLLIN  =  1
  POLLOUT =  4
  POLLERR =  8
  POLLHUP = 16
end
