#!/bin/sh
# Native LLVM round-trip gate (SPEC 3.3, slice B2). It builds iyi-ir, round-trips every fixture that
# passes today, and proves the gate can fail with four mutations: dropping nsw in the translator, writing hidden as the
# default visibility, removing an intrinsic from the importer's accepted set, dropping the align on an intrinsic operand,
# and a patch that changes nothing.
# Job: native-linux (the integrator adds it to iyi.yml). The matrix over the corpus is
# bench/native_llvm_matrix.sh, which is not part of this gate.
set -u

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root" || exit 1
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH
LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
export LIBRARY_PATH

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

step 2 "every fixture round-trips identically, and the one the translator refuses is refused by name"
count=0
total=0
for name in arith control probe_switch probe_phi memory consts calls sizeof visibility wide_int overflow8_16 variadic flags_attrs memset_param_align int192 asm_unwind; do
  total=$((total + 1))
  verdict=$("$TOOL" roundtrip "$FX/$name.ll" 2>&1)
  if [ "$verdict" = "identical" ]; then
    count=$((count + 1))
    echo "identical: $name"
  else
    echo "NOT identical: $name: $(echo "$verdict" | head -1)"
    failed=1
  fi
done
verdict=$("$TOOL" roundtrip "$FX/dso_local.ll" 2>&1)
case "$verdict" in
  "refused by the translator: LLVM 22's C API cannot set dso_local"*) echo "refused by name: dso_local" ;;
  *) echo "NOT refused by name: dso_local: $(echo "$verdict" | head -1)"; failed=1 ;;
esac
echo "identical fixtures: $count of $total"

step 3 "mutation: drop nsw in the translator"
prove_mutation "drop nsw in translate" \
  src/compiler/backend/llvm/translate.iyi \
  "LibLLVM.set_nsw(result, 1) if (flags & 2_i64) != 0" \
  "LibLLVM.set_nsw(result, 0) if (flags & 2_i64) != 0" \
  "\"$TOOL\" roundtrip \"$FX/arith.ll\" | grep -qx identical"

step 3b "mutation: write hidden as default in the translator"
prove_mutation "write hidden as default in translate" \
  src/compiler/backend/llvm/translate.iyi \
  "LibLLVM.set_visibility(fn, visibility_number(f.visibility))" \
  "LibLLVM.set_visibility(fn, 0)" \
  "\"$TOOL\" roundtrip \"$FX/visibility.ll\" | grep -qx identical"

step 4 "mutation: remove llvm.memcpy from the importer's accepted intrinsics"
prove_mutation "remove llvm.memcpy from the importer" \
  src/compiler/backend/llvm/import.iyi \
  "found = intrinsic_match(llvm_name, @ir.types)" \
  "found = llvm_name == \"llvm.memcpy.p0.p0.i64\" ? nil : intrinsic_match(llvm_name, @ir.types)" \
  "\"$TOOL\" roundtrip \"$FX/calls.ll\" | grep -qx identical"

step 4c "mutation: drop the align on an intrinsic operand in the translator"
prove_mutation "drop align on an intrinsic operand in translate" \
  src/compiler/backend/llvm/translate.iyi \
  "LibLLVM.add_callsite_attribute(call, index, create_attribute(a))" \
  "LibLLVM.add_callsite_attribute(call, index, create_attribute(a)) if a.name != \"align\"" \
  "\"$TOOL\" roundtrip \"$FX/memset_param_align.ll\" | grep -qx identical"

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

step 7 "the coverage inventory of the fixtures and gap reproducers matches COVERAGE.md"
COV=$FX/COVERAGE.md
cov_tsv=.build/iyi-ir-coverage.tsv
"$TOOL" coverage "$FX"/*.ll "$FX"/gaps/*.ll > "$cov_tsv" 2>&1
{
  echo "# LLVM round-trip coverage: committed fixtures and gap reproducers"
  echo
  echo "Written by \`bench/native_llvm_roundtrip_exercise.sh\` from \`iyi-ir coverage\` over every fixture and gap reproducer. The gate fails when this file is stale; \`COVERAGE_WRITE=1\` rewrites it. The corpus inventory is written by \`bench/native_llvm_matrix.sh\`."
  echo
  echo '```'
  cat "$cov_tsv"
  echo '```'
} > .build/iyi-ir-COVERAGE.md
if [ "${COVERAGE_WRITE:-0}" = "1" ]; then
  cp .build/iyi-ir-COVERAGE.md "$COV"
  echo "COVERAGE.md written"
elif cmp -s .build/iyi-ir-COVERAGE.md "$COV"; then
  echo "COVERAGE.md is current"
else
  echo "COVERAGE.md is stale: rerun with COVERAGE_WRITE=1"
  failed=1
fi

if [ "$failed" -eq 0 ]; then
  echo "== ALL NATIVE LLVM ROUNDTRIP CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE LLVM ROUNDTRIP CHECKS FAILED"
exit 1
