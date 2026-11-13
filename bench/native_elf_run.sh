#!/bin/sh
# The Linux run half of the native ELF gate (SPEC 2.3 and 3.4, slice D3). It runs on a Linux host of the architecture
# it names, and needs nothing but a POSIX shell, `cc`, `timeout` and the files `bench/native_elf_exercise.sh --emit`
# wrote. It never builds anything with iyi.
#
#   sh bench/native_elf_run.sh DIR ARCH          run every program in DIR/ARCH/MANIFEST
#   sh bench/native_elf_run.sh --list DIR ARCH   print what would run, and every file it reads, without running
#
# ARCH is x86_64 or aarch64. For each MANIFEST line `NAME EXPECTED LINK_FLAGS...` (the flags are every word after
# the second, and there may be none):
#   1. The oracle binary is linked from DIR/ARCH/NAME.o with `cc`, using the hosted compiler's own link line
#      (`cc OBJECT -o EXE -rdynamic` for Linux, the line `iyi build --cross-compile` prints).
#   2. The oracle binary and DIR/ARCH/NAME.native run with the same standard input (DIR/ARCH/NAME.stdin when present,
#      otherwise /dev/null), the same arguments (none) and a time bound. Their stdout, stderr and exit status must be
#      equal to each other, and the exit status must equal EXPECTED when EXPECTED is a number.
#   3. A line whose EXPECTED is `random-address` is the address-randomisation fixture. It prints the address of its
#      own code, and it must print two different addresses across two runs of the native executable, and two
#      different addresses across two runs of the oracle binary. Its output is not compared with the oracle's.
#
# One verdict line is printed per program: `PASS ARCH NAME` or `FAIL ARCH NAME: reason`. The script exits 1 on any
# FAIL, on a file that is missing, when the manifest is missing or empty, and when zero programs ran.

set -u

usage() {
  echo "usage: sh bench/native_elf_run.sh [--list] DIR ARCH   (ARCH: x86_64 or aarch64)" >&2
  exit 2
}

list_only=0
if [ "${1:-}" = "--list" ]; then
  list_only=1
  shift
fi
[ "$#" -eq 2 ] || usage
dir="$1"
arch="$2"
case "$arch" in
  x86_64 | aarch64) ;;
  *) usage ;;
esac

set_dir="$dir/$arch"
manifest="$set_dir/MANIFEST"
bound=30

if [ "$list_only" -eq 1 ]; then
  if [ ! -f "$manifest" ]; then
    echo "missing manifest: $manifest" >&2
    exit 1
  fi
  echo "file $manifest"
  while read -r name expected flags; do
    [ -n "$name" ] || continue
    echo "file $set_dir/$name.o"
    echo "file $set_dir/$name.native"
    if [ -f "$set_dir/$name.stdin" ]; then
      echo "file $set_dir/$name.stdin"
    fi
    echo "run $arch $name: cc $set_dir/$name.o -o WORK/$name.oracle $flags; timeout $bound; expected=$expected"
  done <"$manifest"
  exit 0
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "cc is not on PATH: the oracle binaries are linked with it" >&2
  exit 1
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is not on PATH: every run is bounded by it" >&2
  exit 1
fi
if [ ! -f "$manifest" ]; then
  echo "missing manifest: $manifest" >&2
  exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/native_elf_run.XXXXXX")" || exit 1
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

ran=0
failures=0

# verdict_fail NAME REASON: records one failed program.
verdict_fail() {
  echo "FAIL $arch $1: $2"
  failures=$((failures + 1))
}

# run_one EXE STDIN OUTPREFIX: runs EXE with STDIN as standard input, bounded, writing OUTPREFIX.out, .err and .status.
run_one() {
  timeout "$bound" "$1" <"$2" >"$3.out" 2>"$3.err"
  echo "$?" >"$3.status"
}

# check_present NAME FILE: fails the program when FILE is missing.
check_present() {
  if [ ! -f "$2" ]; then
    verdict_fail "$1" "missing $2"
    return 1
  fi
  return 0
}

while read -r name expected flags; do
  [ -n "$name" ] || continue
  obj="$set_dir/$name.o"
  native="$set_dir/$name.native"
  stdin="$set_dir/$name.stdin"
  [ -f "$stdin" ] || stdin=/dev/null

  check_present "$name" "$obj" || continue
  check_present "$name" "$native" || continue

  oracle="$work/$name.oracle"
  # shellcheck disable=SC2086
  if ! cc "$obj" -o "$oracle" $flags >"$work/$name.link" 2>&1; then
    verdict_fail "$name" "the oracle object does not link with cc: $(head -n 1 "$work/$name.link")"
    continue
  fi

  if [ "$expected" = "random-address" ]; then
    run_one "$oracle" "$stdin" "$work/$name.oracle1"
    run_one "$oracle" "$stdin" "$work/$name.oracle2"
    run_one "$native" "$stdin" "$work/$name.native1"
    run_one "$native" "$stdin" "$work/$name.native2"
    ran=$((ran + 1))
    if [ "$(cat "$work/$name.native1.status")" != 0 ] || [ "$(cat "$work/$name.native2.status")" != 0 ]; then
      verdict_fail "$name" "the native executable exits non-zero: $(cat "$work/$name.native1.status") $(cat "$work/$name.native2.status")"
      continue
    fi
    if [ "$(cat "$work/$name.native1.out")" = "$(cat "$work/$name.native2.out")" ]; then
      verdict_fail "$name" "the native executable printed the same address twice: $(cat "$work/$name.native1.out")"
      continue
    fi
    if [ "$(cat "$work/$name.oracle1.out")" = "$(cat "$work/$name.oracle2.out")" ]; then
      verdict_fail "$name" "the oracle binary printed the same address twice: $(cat "$work/$name.oracle1.out")"
      continue
    fi
    echo "PASS $arch $name: native $(cat "$work/$name.native1.out") then $(cat "$work/$name.native2.out"); oracle differs too"
    continue
  fi

  run_one "$oracle" "$stdin" "$work/$name.oracle"
  run_one "$native" "$stdin" "$work/$name.native"
  ran=$((ran + 1))

  if ! cmp -s "$work/$name.oracle.out" "$work/$name.native.out"; then
    verdict_fail "$name" "stdout differs from the oracle's"
    continue
  fi
  if ! cmp -s "$work/$name.oracle.err" "$work/$name.native.err"; then
    verdict_fail "$name" "stderr differs from the oracle's"
    continue
  fi
  if [ "$(cat "$work/$name.oracle.status")" != "$(cat "$work/$name.native.status")" ]; then
    verdict_fail "$name" "exit status $(cat "$work/$name.native.status"), the oracle's is $(cat "$work/$name.oracle.status")"
    continue
  fi
  if [ "$expected" != "-" ] && [ "$(cat "$work/$name.native.status")" != "$expected" ]; then
    verdict_fail "$name" "exit status $(cat "$work/$name.native.status"), the manifest expects $expected"
    continue
  fi
  echo "PASS $arch $name: exit $(cat "$work/$name.native.status"), $(wc -c <"$work/$name.native.out" | tr -d ' ') bytes of stdout"
done <"$manifest"

if [ "$ran" -eq 0 ]; then
  echo "== NO PROGRAM RAN for $arch in $set_dir"
  exit 1
fi
if [ "$failures" -ne 0 ]; then
  echo "== $failures of $ran PROGRAMS FAILED for $arch"
  exit 1
fi
echo "== $ran PROGRAMS RAN AND MATCHED THE ORACLE for $arch"
exit 0
