#!/usr/bin/env bash
# Verify the call-site values in the emitted typed module and in an executable.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_PATH="$REPO/src"
IYI="$REPO/bin/iyi"
"$IYI" build -o "$WORK/native" "$REPO/src/compiler/tools/compile_native.iyi"
fixture="$REPO/bench/fixtures/bodies_magic_payload.iyi"
"$WORK/native" "$fixture" -o "$WORK/magic.ir" --pipeline typed --emit ir
grep -F 'call iyicc i32 (i32) @"*magic_line<Int32>:Int32"(i32 17)' "$WORK/magic.ir"
grep -F 'call iyicc i32 (i32) @"*magic_end<Int32>:Int32"(i32 20)' "$WORK/magic.ir"
grep -F "$fixture" "$WORK/magic.ir"
grep -F "$REPO/bench/fixtures\\00" "$WORK/magic.ir"
grep -F 'call iyicc ptr (ptr) @"*magic_file<String>:String"' "$WORK/magic.ir"
grep -F 'call iyicc ptr (ptr) @"*magic_dir<String>:String"' "$WORK/magic.ir"
fixture="$REPO/bench/fixtures/bodies_magic_output.iyi"
"$IYI" build --prelude empty -o "$WORK/hosted" "$fixture"
"$WORK/native" "$fixture" -o "$WORK/native-out" --pipeline typed
"$WORK/hosted" > "$WORK/hosted.out"
"$WORK/native-out" > "$WORK/native.out"
printf '\016\021' > "$WORK/expected.out"
cmp "$WORK/expected.out" "$WORK/hosted.out"
cmp "$WORK/hosted.out" "$WORK/native.out"
echo 'magic call-site literals and executable output match'
fixture="$REPO/bench/fixtures/bodies_union_magic_mismatch.iyi"
"$IYI" build -o "$WORK/typed" "$REPO/src/compiler/tools/typed_dump.iyi"
if "$WORK/typed" "$fixture" "$REPO/src" > "$WORK/union-typed.log" 2>&1; then
  echo "union magic defaults now type: remove this named waiting case"
  cat "$WORK/union-typed.log"
  exit 1
fi
if ! grep -F 'not ported: differing union call-site defaults' "$WORK/union-typed.log"; then
  echo "union magic defaults refused for a different reason:"
  cat "$WORK/union-typed.log"
  exit 1
fi
echo 'WAITING: differing union call-site defaults'
