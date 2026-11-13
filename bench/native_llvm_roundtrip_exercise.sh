#!/bin/sh
# Native LLVM round-trip gate (SPEC 3.3, slice B2). It builds iyi-ir, round-trips every fixture that
# passes today, drops the unwind edges of the oracle's handler module and compares what is left, and proves the gate can
# fail with six mutations: dropping nsw in the translator, writing hidden as the default visibility, removing an intrinsic
# from the importer's accepted set, dropping the align on an intrinsic operand, importing either name of the program's
# entry with the C convention, and a patch that changes nothing.
# Job: native-linux (the integrator adds it to iyi.yml). The matrix over the corpus is
# bench/native_llvm_matrix.sh, which is not part of this gate. The linked LLVM's major version is read through
# `iyi-ir version`. A fixture annotated `; needs-llvm: N` is reported as skipped, never as passed, when the linked major
# is below N. The COVERAGE.md comparison is reported as skipped when that file was written by a different LLVM major.
set -u

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root" || exit 1
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH
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

stop_gate() {
  echo "== NATIVE LLVM ROUNDTRIP GATE STOPPED: $1"
  exit 1
}

rebuild_tool() {
  if "$IY" build -o "$TOOL" "$SRC" > .build/iyi-ir-build.log 2>&1; then
    return 0
  fi
  echo "iyi-ir build failed; last 60 lines of .build/iyi-ir-build.log:"
  tail -n 60 .build/iyi-ir-build.log
  return 1
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
  if ! rebuild_tool; then
    cp "$backup" "$file"
    rm -f "$backup"
    stop_gate "iyi-ir did not build with the mutation $label; sources restored"
  fi
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
  stop_gate "iyi-ir did not build; the log is above"
fi
llvm_version=$("$TOOL" version 2>&1)
llvm_major=${llvm_version%%.*}
case "$llvm_major" in
  ''|*[!0-9]*) echo "cannot read the linked LLVM version: $llvm_version"; failed=1; llvm_major=0 ;;
  *) echo "linked LLVM: $llvm_version" ;;
esac

step 2 "every fixture round-trips identically, and the one the translator refuses is refused by name"
count=0
total=0
skipped=0
for name in arith control probe_switch probe_phi memory consts calls sizeof visibility wide_int overflow8_16 variadic flags_attrs memset_param_align int192 asm_unwind; do
  need=$(awk '/^; needs-llvm: /{ print $3; exit }' "$FX/$name.ll")
  if [ -n "$need" ] && [ "$llvm_major" -lt "$need" ]; then
    skipped=$((skipped + 1))
    echo "skipped: $name needs LLVM >= $need (linked LLVM $llvm_version)"
    continue
  fi
  total=$((total + 1))
  verdict=$("$TOOL" roundtrip "$FX/$name.ll" 2>&1)
  if [ "$verdict" = "identical" ]; then
    count=$((count + 1))
    echo "identical: $name"
  else
    echo "NOT identical: $name: $(echo "$verdict" | head -1)"
    # The rest of what the tool said: on a runner the log is all there is to read the difference from.
    echo "$verdict" | sed -n '2,12p' | sed 's/^/    /'
    failed=1
  fi
done
verdict=$("$TOOL" roundtrip "$FX/dso_local.ll" 2>&1)
case "$verdict" in
  "refused by the translator: the linked LLVM's C API cannot set dso_local"*) echo "refused by name: dso_local" ;;
  *) echo "NOT refused by name: dso_local: $(echo "$verdict" | head -1)"; failed=1 ;;
esac
echo "identical fixtures: $count of $total run; skipped: $skipped"

step 2b "the oracle's handler module with its unwind edges dropped is the normal path, and the program's entry is Iyi"
UNW=bench/fixtures/ir/unwind
if "$TOOL" drop-unwind "$UNW/entry.ll" > .build/iyi-ir-unwind.out 2>&1 && cmp -s .build/iyi-ir-unwind.out "$UNW/entry.expected"; then
  echo "identical: drop-unwind entry"
else
  echo "NOT identical: drop-unwind entry"
  diff .build/iyi-ir-unwind.out "$UNW/entry.expected" | sed -n '1,12p' | sed 's/^/    /'
  failed=1
fi

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

step 4d "mutation: the bare entry is imported with the C convention"
prove_mutation "import __crystal_main as C" \
  src/compiler/backend/llvm/import.iyi \
  "return CallConv::Iyi if name == \"__crystal_main\" || name == \"__iyi_main\"" \
  "return CallConv::Iyi if name == \"__iyi_main\"" \
  "\"$TOOL\" drop-unwind \"$UNW/entry.ll\" | cmp -s - \"$UNW/entry.expected\""

step 4e "mutation: the prelude's entry is imported with the C convention"
prove_mutation "import __iyi_main as C" \
  src/compiler/backend/llvm/import.iyi \
  "return CallConv::Iyi if name == \"__crystal_main\" || name == \"__iyi_main\"" \
  "return CallConv::Iyi if name == \"__crystal_main\"" \
  "\"$TOOL\" drop-unwind \"$UNW/entry.ll\" | cmp -s - \"$UNW/entry.expected\""

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
rebuild_tool || stop_gate "iyi-ir did not rebuild from the restored sources"

step 7 "the coverage inventory of the fixtures and gap reproducers matches COVERAGE.md"
COV=$FX/COVERAGE.md
cov_tsv=.build/iyi-ir-coverage.tsv
if ls "$FX"/gaps/*.ll > /dev/null 2>&1; then
  "$TOOL" coverage "$FX"/*.ll "$FX"/gaps/*.ll > "$cov_tsv" 2>&1
else
  "$TOOL" coverage "$FX"/*.ll > "$cov_tsv" 2>&1
fi
{
  echo "# LLVM round-trip coverage: committed fixtures and gap reproducers"
  echo
  echo "Linked LLVM: $llvm_version"
  echo
  echo "Written by \`bench/native_llvm_roundtrip_exercise.sh\` from \`iyi-ir coverage\` over every fixture and gap reproducer. The gate fails when this file is stale; \`COVERAGE_WRITE=1\` rewrites it. The corpus inventory is written by \`bench/native_llvm_matrix.sh\`."
  echo
  echo '```'
  cat "$cov_tsv"
  echo '```'
} > .build/iyi-ir-COVERAGE.md
cov_written=$(awk '/^Linked LLVM: /{ print $3; exit }' "$COV")
if [ "${COVERAGE_WRITE:-0}" = "1" ]; then
  cp .build/iyi-ir-COVERAGE.md "$COV"
  echo "COVERAGE.md written"
elif [ "${cov_written%%.*}" != "$llvm_major" ]; then
  cov_major=${cov_written%%.*}
  echo "skipped: COVERAGE.md was written with LLVM ${cov_major:-unknown}, this is LLVM $llvm_major (not compared)"
  skipped=$((skipped + 1))
elif cmp -s .build/iyi-ir-COVERAGE.md "$COV"; then
  echo "COVERAGE.md is current"
else
  echo "COVERAGE.md is stale: rerun with COVERAGE_WRITE=1"
  failed=1
fi
echo "skipped checks: $skipped (reported, never counted as passed)"

if [ "$failed" -eq 0 ]; then
  echo "== ALL NATIVE LLVM ROUNDTRIP CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE LLVM ROUNDTRIP CHECKS FAILED"
exit 1
