/* TEST STAND-IN, NOT THE RUNTIME. The native backend calls these three helpers
 * for memory intrinsics that are large or of variable length. The
 * runtime-helpers slice defines them for real; until it lands, the codegen gate
 * links this file so that the fixtures can run. Replace this file when that
 * slice merges. */
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
