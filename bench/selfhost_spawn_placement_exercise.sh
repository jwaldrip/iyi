#!/usr/bin/env bash
# Differential pool-placement checks. Unknown shapes must refuse, not silently run in_unit.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
export IYI_PATH="$REPO/src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"
status=0

spawn_check() {
  "$IYI" build -o "$WORK/stage1" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/stage.build" 2>&1 || return 1
  codesign -v --strict "$WORK/stage1" || return 1
  for n in same_unit_capture mutable_capture explicit_same pointer_capture tuple_capture; do
    f="$REPO/bench/fixtures/lowpool_$n.iyi"
    "$IYI" build --no-debug --emit llvm-ir -o "$WORK/$n-hosted" "$f" > "$WORK/$n.hosted.log" 2>&1 || return 1
    if grep -Eq '^define .*@__iyi_preempt\(' "$WORK/$n-hosted.ll"; then echo "$n: hosted reaches pool"; return 1; fi
    "$WORK/stage1" "$f" -o "$WORK/$n-native" --pipeline typed --prelude --probe-phase > "$WORK/$n.port.log" 2>&1 || return 1
    codesign -v --strict "$WORK/$n-native" || return 1
    "$WORK/$n-hosted" > "$WORK/$n.hosted.out" 2>&1; h=$?
    "$WORK/$n-native" > "$WORK/$n.native.out" 2>&1; p=$?
    [ "$h" = "$p" ] && cmp -s "$WORK/$n.hosted.out" "$WORK/$n.native.out" || return 1
    echo "$n: hosted/native output and exit agree"
  done
  for n in parallel_eligible explicit_new share_capture trusted_capture immutable_capture; do
    f="$REPO/bench/fixtures/lowpool_$n.iyi"
    "$IYI" build --no-debug --emit llvm-ir -o "$WORK/$n-hosted" "$f" > "$WORK/$n.hosted.log" 2>&1 || return 1
    grep -Eq '^define .*@__iyi_preempt\(' "$WORK/$n-hosted.ll" || { echo "$n: hosted did not reach pool"; return 1; }
    if "$WORK/stage1" "$f" -o "$WORK/$n-native" --pipeline typed --prelude --probe-phase > "$WORK/$n.port.log" 2>&1; then echo "$n: pool program was accepted"; return 1; fi
    grep -Eq 'spawn classification .*not ported.*classify_spawn|loop back-edge preemption checks are not ported' "$WORK/$n.port.log" || return 1
    echo "$n: hosted reaches pool, port refused by name"
  done
}
spawn_check || { echo 'FAIL: spawn placement baseline'; exit 1; }
prove_mutation 'unknown spawn is silently accepted' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  '    SpawnVerdict.new(SpawnTarget::Unproven, placement, reason, site)' \
  '    SpawnVerdict.new(SpawnTarget::AsWritten, placement, reason, site)' -- spawn_check || status=1
prove_mutation 'trusted type is structurally classified' "$REPO/src/compiler/semantic/share.iyi" \
  '      return nil if type.share_trusted || type.object_id == type.program.string_type.object_id' \
  '      return nil if type.object_id == type.program.string_type.object_id' -- spawn_check || status=1

prove_mutation 'raw pointer witness is dropped' "$REPO/src/compiler/semantic/share.iyi" \
  '      return "#{type} is raw memory, which no marker can vouch for"' \
  '      return nil' -- spawn_check || status=1
prove_mutation 'tuple member witness is dropped' "$REPO/src/compiler/semantic/share.iyi" \
  '          return "#{type} holds #{member}: #{why}"' \
  '          return nil' -- spawn_check || status=1
prove_mutation 'setter witness is dropped' "$REPO/src/compiler/semantic/share.iyi" \
  '      if setters.includes?(name)' \
  '      if false' -- spawn_check || status=1
exit "$status"