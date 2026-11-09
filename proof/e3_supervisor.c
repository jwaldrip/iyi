/*
 * E3 supervisor admission gate.
 *
 * This binary is deliberately not a launcher: the parent-ptrace topology,
 * private channel, descriptor custody and writer exclusion have not been
 * qualified in the intended cage.  In particular, PR_SET_DUMPABLE alone
 * cannot establish the required same-UID isolation.  It must not run a
 * payload or issue an origin receipt until those mechanisms are implemented
 * and independently reviewed.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  fputs("E3_SUPERVISOR_UNAVAILABLE: capability-free tracing, private "
        "channel and descriptor custody are not qualified; "
        "source attribution is unavailable\n",
        stderr);
  return EXIT_FAILURE;
}
