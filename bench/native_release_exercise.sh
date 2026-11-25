#!/usr/bin/env bash
# Compare release programs from the hosted and both native register allocators.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd -P)
. "$REPO/bench/lib/host.sh" || exit 1
. "$REPO/bench/lib/mutation.sh" || exit 1
require_test_host || exit 1
[ -n "$PY" ] || { echo 'FAIL: a working Python interpreter is required' >&2; exit 1; }
export IYI_PATH="$(native_path "$REPO/src")"
unset IYI_OPTS IYI_NATIVE_REGALLOC
export LC_ALL=C
if [ "$HOST_OS" = darwin ]; then
  export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
  export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/native-release.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
IYI="$REPO/bin/iyi"
SOURCE="$REPO/src/compiler/stage1.iyi"
STAGE1="$WORK/iyi-stage1"
FIX="$REPO/bench/fixtures/native_release"
failed=0
fail() { echo "FAIL: $*" >&2; failed=1; }

build() {
  local compiler="$1" source="$2" output="$3" log="$4"
  "$compiler" build --release -o "$(native_path "$output")" "$(native_path "$source")" >"$log" 2>&1
}

# Status 1 means an observed stdout or exit-status difference. A timeout or
# inability to launch either program is a setup failure, not a mutation proof.
compare_twins() {
  "$PY" - "$1" "$2" <<'PY'
import subprocess, sys
try:
    hosted = subprocess.run([sys.argv[1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    native = subprocess.run([sys.argv[2]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
except (OSError, subprocess.TimeoutExpired) as exc:
    print('cannot run release twin:', exc, file=sys.stderr)
    sys.exit(2)
if hosted.stdout != native.stdout or hosted.returncode != native.returncode:
    print('decisive: hosted exit %s stdout %r, native exit %s stdout %r' %
          (hosted.returncode, hosted.stdout, native.returncode, native.stdout))
    sys.exit(1)
PY
}

check_wrong_code() {
  local mutant="$WORK/mutant-stage1" source name rc
  if ! build "$IYI" "$SOURCE" "$mutant" "$WORK/mutant-build.log"; then
    cat "$WORK/mutant-build.log"; return 2
  fi
  for source in "$FIX"/*.iyi; do
    [ -f "$source" ] || return 2
    name=$(basename "$source" .iyi)
    if ! IYI_NATIVE_REGALLOC=linear build "$mutant" "$source" "$WORK/$name.mutant" "$WORK/$name.mutant.log"; then
      cat "$WORK/$name.mutant.log"; return 2
    fi
    rc=0
    compare_twins "$WORK/$name.hosted" "$WORK/$name.mutant" || rc=$?
    [ "$rc" -ne 1 ] || return 1
    [ "$rc" -eq 0 ] || return 2
  done
  return 0
}

if [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited 'native release twins require macOS arm64'
  exit 0
fi

echo '== 1. build the self-hosted compiler'
if ! build "$IYI" "$SOURCE" "$STAGE1" "$WORK/stage1.log"; then
  fail 'hosted compiler could not build stage1'; cat "$WORK/stage1.log"
  exit 1
fi

echo '== 2. hosted and native release twins'
checked=0
for source in "$FIX"/*.iyi; do
  [ -f "$source" ] || { fail 'no native release fixtures'; break; }
  name=$(basename "$source" .iyi)
  if ! build "$IYI" "$source" "$WORK/$name.hosted" "$WORK/$name.hosted.log"; then
    fail "$name hosted build"; cat "$WORK/$name.hosted.log"; continue
  fi
  for allocator in linear pin; do
    if ! IYI_NATIVE_REGALLOC="$allocator" build "$STAGE1" "$source" "$WORK/$name.$allocator" "$WORK/$name.$allocator.log"; then
      fail "$name $allocator build"; cat "$WORK/$name.$allocator.log"; continue
    fi
    rc=0
    compare_twins "$WORK/$name.hosted" "$WORK/$name.$allocator" || rc=$?
    if [ "$rc" -ne 0 ]; then
      fail "$name $allocator twin differs or could not run (exit $rc)"
    else
      echo "  $name $allocator: stdout and exit match hosted"
      checked=$((checked + 1))
    fi
  done
done
echo "  checked $checked release twins"

echo '== 3. wrong-code mutation'
prove_mutation 'W0: signed less-than wrong code changes a release twin' "$REPO/src/compiler/native/aarch64/isel.iyi" \
  $'  elsif ordinal == 8_i64\n    return cond_lt' $'  elsif ordinal == 8_i64\n    return cond_le' \
  -- check_wrong_code || fail 'release twin wrong-code mutation was not caught'

if [ "$failed" -eq 0 ]; then
  echo 'ALL NATIVE RELEASE CHECKS PASSED!'
  exit 0
fi
echo 'SOME NATIVE RELEASE CHECKS FAILED'
exit 1
