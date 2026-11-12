#!/bin/sh
# Native LLVM round-trip gate (SPEC 3.3, slice B2). It builds iyi-ir, round-trips every fixture that
# passes today, and proves the gate can fail with three mutations: dropping nsw in the translator,
# removing an intrinsic from the importer's accepted set, and a patch that changes nothing.
# Job: native-linux (the integrator adds it to iyi.yml). The matrix over the corpus is
# bench/native_llvm_matrix.sh, which is not part of this gate.
set -u

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root" || exit 1
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH
LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
export LIBRARY_PATH
CRYSTAL_CACHE_DIR=${CRYSTAL_CACHE_DIR:-/tmp/iyi-native-llvm-roundtrip-cache}
export CRYSTAL_CACHE_DIR

IY=./bin/iyi
TOOL=.build/iyi-ir
FX=bench/fixtures/llvm_roundtrip
SRC=src/compiler/tools/ir.iyi
failed=0

step() {
  echo "== $1. $2"
}

rebuild_tool() {
  "$IY" build -o "$TOOL" "$SRC" > .build/iyi-ir-build.log 2>&1
}

# prove_mutation LABEL FILE OLD NEW CHECK
# Replaces the first OLD in FILE with NEW, rebuilds the tool, and runs CHECK. A CHECK that still
# passes means the mutation was not caught. A patch whose OLD text is absent proves nothing and fails.
prove_mutation() {
  label=$1
  file=$2
  old=$3
  new=$4
  check=$5
  backup=$(mktemp)
  cp "$file" "$backup"
  python3 -c 'import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if old not in text:
    sys.exit(3)
open(path, "w").write(text.replace(old, new, 1))' "$file" "$old" "$new"
  status=$?
  if [ "$status" -eq 3 ]; then
    echo "PATCH CHANGED NOTHING: this proves nothing ($label)"
    rm -f "$backup"
    failed=1
    return
  fi
  if [ "$status" -ne 0 ]; then
    echo "patch for $label did not apply (python exit $status)"
    cp "$backup" "$file"
    rm -f "$backup"
    failed=1
    return
  fi
  rebuild_tool
  if sh -c "$check" > /dev/null 2>&1; then
    echo "NOT CAUGHT: $label"
    failed=1
  else
    echo "caught: $label"
  fi
  cp "$backup" "$file"
  rm -f "$backup"
}

step 1 "build iyi-ir"
if rebuild_tool; then
  echo "iyi-ir built: $TOOL"
else
  echo "iyi-ir did not build; see .build/iyi-ir-build.log"
  failed=1
fi

step 2 "every fixture that passes today round-trips identically"
count=0
for name in arith control probe_switch probe_phi memory consts calls sizeof; do
  verdict=$("$TOOL" roundtrip "$FX/$name.ll" 2>&1)
  if [ "$verdict" = "identical" ]; then
    count=$((count + 1))
    echo "identical: $name"
  else
    echo "NOT identical: $name: $(echo "$verdict" | head -1)"
    failed=1
  fi
done
echo "identical fixtures: $count of 8"

step 3 "mutation: drop nsw in the translator"
prove_mutation "drop nsw in translate" \
  src/compiler/backend/llvm/translate.iyi \
  "LibLLVM.set_nsw(result, 1) if (flags & 2_i64) != 0" \
  "LibLLVM.set_nsw(result, 0) if (flags & 2_i64) != 0" \
  "\"$TOOL\" roundtrip \"$FX/arith.ll\" | grep -qx identical"

step 4 "mutation: remove llvm.memcpy from the importer's accepted intrinsics"
prove_mutation "remove llvm.memcpy from the importer" \
  src/compiler/backend/llvm/import.iyi \
  "id = intrinsic_from_name(llvm_name)" \
  "id = llvm_name == \"llvm.memcpy.p0.p0.i64\" ? nil : intrinsic_from_name(llvm_name)" \
  "\"$TOOL\" roundtrip \"$FX/calls.ll\" | grep -qx identical"

step 5 "mutation: a patch that changes nothing is refused"
noop_out=$(prove_mutation "no-op patch" \
  src/compiler/backend/llvm/translate.iyi \
  "this text is in no file of the tree" \
  "replacement" \
  "true")
case "$noop_out" in
  *"PATCH CHANGED NOTHING"*) echo "refused: no-op patch" ;;
  *) echo "NOT refused: no-op patch"; failed=1 ;;
esac

step 6 "the tree is restored: iyi-ir is rebuilt from the committed sources"
if git diff --quiet -- src/compiler/backend/llvm src/compiler/tools/ir.iyi; then
  echo "sources match HEAD"
else
  echo "sources differ from HEAD after the mutations"
  failed=1
fi
rebuild_tool || failed=1

if [ "$failed" -eq 0 ]; then
  echo "== ALL NATIVE LLVM ROUNDTRIP CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE LLVM ROUNDTRIP CHECKS FAILED"
exit 1
