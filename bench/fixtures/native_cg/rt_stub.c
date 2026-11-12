/* TEST STAND-IN, NOT THE RUNTIME. The native backend calls these helpers for
 * memory intrinsics that are large or of variable length, and for 128-bit
 * division and remainder. The runtime-helpers slice defines them for real;
 * until it lands, the codegen gate links this file so that the fixtures can
 * run. Replace this file when that slice merges. */
#include <stdint.h>
#include <string.h>

/* A plain forward copy: on overlapping ranges it differs from memmove, so the
 * gate can tell the two apart. */
void __iyi_native_memcpy(void *dst, const void *src, int64_t n) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  for (int64_t i = 0; i < n; i++)
    d[i] = s[i];
}
void __iyi_native_memmove(void *dst, const void *src, int64_t n) {
  memmove(dst, src, (size_t)n);
}
void __iyi_native_memset(void *dst, int64_t value, int64_t n) {
  memset(dst, (int)value, (size_t)n);
}

/* The 128-bit division helpers, with C's truncating semantics as the IR's
 * sdiv/udiv/srem/urem have. */
__int128 __iyi_native_divti3(__int128 a, __int128 b) { return a / b; }
unsigned __int128 __iyi_native_udivti3(unsigned __int128 a,
                                       unsigned __int128 b) {
  return a / b;
}
__int128 __iyi_native_modti3(__int128 a, __int128 b) { return a % b; }
unsigned __int128 __iyi_native_umodti3(unsigned __int128 a,
                                       unsigned __int128 b) {
  return a % b;
}
