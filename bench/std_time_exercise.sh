#!/usr/bin/env bash
# Exercises `std/time`: `Time` and `Time::Span`.
#
#     bash bench/std_time_exercise.sh
#
# Proves:
#   * Known-value table across calendar landmarks (Unix epoch, leap day, century
#     leap and non-leap years, boundary years 0001 and 9999).
#   * Gregorian leap-year rules and month lengths.
#   * Bidirectional round-trip between civil date and Unix timestamp across 5,000+
#     scattered days.
#   * Platform wall clock and monotonic clock readings.
#   * Span construction, accessors, operators (+, -, -@), and Time arithmetic.
#   * ISO 8601 / RFC 3339 serialization (fraction digits 0, 3, 6, 9) and parsing
#     with timezone offset conversions.
#   * Comparable trait implementation via `Std::Traits::Cmp`.
#   * Negative proofs: the exercise script breaks the leap-year rule, roundtrip
#     arithmetic, and RFC 3339 offset handling, asserting each is caught.
#   * Dependency floor: audits symbols and libraries to prove zero new dependencies.
#
# Needs `make` for bin/iyi, plus `nm`, and `otool` on Darwin or `readelf` on Linux.
# Exits non-zero if any check fails.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

# Ensure IYI_PATH can find std modules in src/ and samples/iyi/
export IYI_PATH="$REPO/src:$REPO/samples/iyi"

symbols() {
  nm -u "$1" 2>/dev/null |
    sed -e 's/^ *//' -e 's/^U  *//' -e 's/@.*$//' |
    awk '{ print $NF }' |
    sed -e 's/^_//' |
    grep -v '^$' |
    sort -u
}

libraries() {
  if command -v otool >/dev/null 2>&1; then
    otool -L "$1" 2>/dev/null | sed -n '2,$p' | awk '{ print $1 }' | sed 's|.*/||' | sort -u
  else
    readelf -d "$1" 2>/dev/null |
      sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' |
      sed 's|.*/||' | sort -u
  fi
}

unexpected() {
  local allowed="$1" found="$2" item keep ok
  for item in $found; do
    keep=no
    for ok in $allowed; do
      case "$item" in "$ok"*) keep=yes ;; esac
    done
    [ "$keep" = no ] && printf '%s\n' "$item"
  done
  return 0
}

build_and_run() {
  local label="$1" name="$2" source="$3"
  shift 3
  if ! "$IYI" build "$@" -o "$WORK/$name" "$source" >"$WORK/$name.build.log" 2>&1; then
    echo "$label: build failed"
    tail -12 "$WORK/$name.build.log"
    status=1
    return 1
  fi
  "$WORK/$name" >"$WORK/$name.out" 2>&1
  local exit_code=$?
  sed 's/^/  /' "$WORK/$name.out"
  if [ "$exit_code" -ne 0 ]; then
    echo "$label: exited $exit_code"
    status=1
    return 1
  fi
  return 0
}

echo "== the std/time exercise"
build_and_run "std_time" exercise-time "$REPO/bench/std_time_exercise.iyi"

echo
echo "== every time check reported"
for check in "known-value table" "leap-year rules" "scattered roundtrip" "platform clocks" "span construction" "RFC 3339" "time comparison" "ALL CHECKS PASSED"; do
  if ! grep -q "$check" "$WORK/exercise-time.out" 2>/dev/null; then
    echo "  MISSING: $check"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "  known-value table, leap-year rules, roundtrip, clocks, spans, RFC 3339 and Cmp all reported"

# ---------------------------------------------------------------------------
# Negative failure proofs
# ---------------------------------------------------------------------------

echo
echo "== negative proof: broken leap-year rule is caught"
mkdir -p "$WORK/patched_leap/std"
cp "$REPO/src/std/time.iyi" "$WORK/patched_leap/std/time.iyi"
python3 -c "
with open('$WORK/patched_leap/std/time.iyi') as f:
    content = f.read()
broken = content.replace('|| (year % 400 == 0)', '&& false')
with open('$WORK/patched_leap/std/time.iyi', 'w') as f:
    f.write(broken)
"
if (IYI_PATH="$WORK/patched_leap:$REPO/src:$REPO/samples/iyi" "$IYI" run "$REPO/bench/std_time_exercise.iyi" >"$WORK/leap-fail.out" 2>&1); then
  echo "  the exercise PASSED with a broken leap-year rule (it should have failed):"
  head -15 "$WORK/leap-fail.out" | sed 's/^/    /'
  status=1
else
  leap_exit=$?
  echo "  the broken leap-year rule was caught (exit $leap_exit)"
fi

echo
echo "== negative proof: broken civil roundtrip is caught"
mkdir -p "$WORK/patched_rt/std"
cp "$REPO/src/std/time.iyi" "$WORK/patched_rt/std/time.iyi"
python3 -c "
with open('$WORK/patched_rt/std/time.iyi') as f:
    content = f.read()
broken = content.replace('def to_unix : Int64\n    @seconds', 'def to_unix : Int64\n    @seconds + 1_i64')
with open('$WORK/patched_rt/std/time.iyi', 'w') as f:
    f.write(broken)
"
if (IYI_PATH="$WORK/patched_rt:$REPO/src:$REPO/samples/iyi" "$IYI" run "$REPO/bench/std_time_exercise.iyi" >"$WORK/rt-fail.out" 2>&1); then
  echo "  the exercise PASSED with broken roundtrip (it should have failed):"
  head -15 "$WORK/rt-fail.out" | sed 's/^/    /'
  status=1
else
  rt_exit=$?
  echo "  the broken civil roundtrip was caught (exit $rt_exit)"
fi

echo
echo "== negative proof: broken RFC 3339 timezone offset is caught"
mkdir -p "$WORK/patched_tz/std"
cp "$REPO/src/std/time.iyi" "$WORK/patched_tz/std/time.iyi"
python3 -c "
with open('$WORK/patched_tz/std/time.iyi') as f:
    content = f.read()
broken = content.replace('utc_sec = local_sec - offset_sec', 'utc_sec = local_sec')
with open('$WORK/patched_tz/std/time.iyi', 'w') as f:
    f.write(broken)
"
if (IYI_PATH="$WORK/patched_tz:$REPO/src:$REPO/samples/iyi" "$IYI" run "$REPO/bench/std_time_exercise.iyi" >"$WORK/tz-fail.out" 2>&1); then
  echo "  the exercise PASSED with broken timezone offset handling (it should have failed):"
  head -15 "$WORK/tz-fail.out" | sed 's/^/    /'
  status=1
else
  tz_exit=$?
  echo "  the broken RFC 3339 timezone offset was caught (exit $tz_exit)"
fi

# ---------------------------------------------------------------------------
# Dependency floor audit
# ---------------------------------------------------------------------------

echo
echo "== the dependency floor, measured against the std_time exercise binary"
case "$(uname -s)" in
  Linux)
    allowed_symbols="ITM_deregisterTMCloneTable ITM_registerTMCloneTable _cxa_finalize _gmon_start__ _libc_start_main"
    if ! command -v readelf >/dev/null 2>&1; then
      echo "  readelf is required on Linux to read NEEDED entries" >&2
      exit 2
    fi
    ;;
  *)
    # On Darwin, libSystem supplies clock_gettime_nsec_np, which concurrency already links
    allowed_symbols="__error _tlv_bootstrap accept bind chmod clock_gettime_nsec_np close connect exit getsockname kevent kqueue listen madvise mmap mprotect munmap open pipe pthread_create pthread_get_stackaddr_np pthread_kill pthread_self read recv send setsockopt sigaction socket sysctlbyname unlink write _dyld_get_image_header _dyld_get_image_vmaddr_slide"
    ;;
esac
allowed_libs="libSystem libc.so ld-linux libgcc_s"

if [ -x "$WORK/exercise-time" ]; then
  time_syms="$(symbols "$WORK/exercise-time")"
  time_libs="$(libraries "$WORK/exercise-time")"
  printf '  symbols   %s\n' "$(echo $time_syms)"
  printf '  libraries %s\n' "$(echo $time_libs)"

  extra_syms="$(unexpected "$allowed_symbols" "$(echo $time_syms)")"
  if [ -n "$extra_syms" ]; then
    echo "  std/time asks the machine for something new:"
    echo "$extra_syms" | sed 's/^/    /'
    echo "  Each is a dependency being taken on. If that is the decision, record it"
    echo "  here and in the commit (SPEC.md III.9)."
    status=1
  fi

  extra_libs="$(unexpected "$allowed_libs" "$(echo $time_libs)")"
  if [ -n "$extra_libs" ]; then
    echo "  std/time links something new:"
    echo "$extra_libs" | sed 's/^/    /'
    status=1
  fi
  [ -z "$extra_syms$extra_libs" ] && echo "  nothing new: std/time costs zero new symbols and zero new libraries"
else
  echo "  no exercise binary to audit"
  status=1
fi

echo
if [ "$status" -eq 0 ]; then
  echo "the std/time exercise holds"
else
  echo "the std/time exercise did not hold"
fi
exit $status
