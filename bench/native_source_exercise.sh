#!/bin/bash
# Native source gate (SPEC 2.2, slice B3). Every compile_* and cg_* fixture is built FROM SOURCE by
# iyi-compile-native, which runs the compiler pipeline with the native backend: no LLVM is linked and no host tool
# runs (bench/lib/tripwire.sh logs and fails ld, cc, clang, gcc, codesign, dsymutil, llvm-config and as). Each program
# the native tool builds is run, and its stdout and exit status must equal the hosted compiler's build of the same
# program. A program the native backend cannot lower is listed by name with its reason and counted as refused, never as
# passing. A fixture the hosted compiler refuses must be refused by the native tool as well. Mutations prove that the
# comparison and the tripwire can each go red.
#
# Exit 0 only when every fixture is accounted for, the tripwire stayed silent, and every mutation was caught.

set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IYI="$REPO/bin/iyi"
TOOL_SRC="$REPO/src/compiler/tools/compile_native.iyi"
FIXTURES="$REPO/bench/fixtures"
. "$REPO/bench/lib/tripwire.sh"

WORK="$(mktemp -d /tmp/iyi-native-source.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

status=0

echo "== 1. build iyi-compile-native from source (no LLVM, no host tool)"
mkdir -p "$WORK/bin"
tool="$WORK/bin/iyi-compile-native"
if ! "$IYI" build -o "$tool" "$TOOL_SRC" >"$WORK/build.tool.log" 2>&1; then
  echo "FAIL: iyi-compile-native does not build (see $WORK/build.tool.log)"
  exit 1
fi
echo "   built $TOOL_SRC"

echo "== 2. the tool links libSystem alone and carries no LLVM symbol"
tool_libs=$(otool -L "$tool" | awk 'NR > 1 { print $1 }')
if [ "$tool_libs" = "/usr/lib/libSystem.B.dylib" ]; then
  echo "   only /usr/lib/libSystem.B.dylib"
else
  echo "FAIL: the tool links: $tool_libs"
  status=1
fi
llvm_syms=$(nm "$tool" 2>/dev/null | awk '/LibLLVM|llvm_|LLVM/ { n++ } END { print n + 0 }')
if [ "$llvm_syms" = "0" ]; then
  echo "   no LLVM symbol in the tool"
else
  echo "FAIL: the tool carries $llvm_syms LLVM symbols"
  status=1
fi

# compare_run REF NAT NAME: runs both executables, requires identical stdout and exit status, and checks the native
# one's signature and linked libraries. Returns 0 only on a full match; prints a line either way.
compare_run() {
  local ref="$1" nat="$2" name="$3" ref_out nat_out ref_rc nat_rc problems nlibs
  ref_out=$(timeout 30 "$ref" </dev/null 2>/dev/null)
  ref_rc=$?
  nat_out=$(timeout 30 "$nat" </dev/null 2>/dev/null)
  nat_rc=$?
  if [ "$ref_out" != "$nat_out" ] || [ "$ref_rc" != "$nat_rc" ]; then
    echo "FAIL: $name: native run diverged (native exit $nat_rc, hosted exit $ref_rc)"
    return 1
  fi
  problems=""
  codesign -v --strict "$nat" >/dev/null 2>&1 || problems="$problems codesign;"
  nlibs=$(otool -L "$nat" | awk 'NR > 1 { print $1 }')
  if [ "$nlibs" != "/usr/lib/libSystem.B.dylib" ]; then problems="$problems libs=$nlibs;"; fi
  if [ -n "$problems" ]; then
    echo "FAIL: $name:$problems"
    return 1
  fi
  echo "   PASS $name (exit $nat_rc)"
  return 0
}

echo "== 3. every fixture: source -> native under the tripwire, against the hosted compiler's build"
tripwire_setup "$WORK/tripwire" "$WORK/tripwire.log" || { echo "FAIL: tripwire setup"; exit 1; }
mkdir -p "$WORK/ref" "$WORK/nat"
total=0
built=0
refused=0
refused_by_both=0
failed=0
refusals="$WORK/refusals.txt"
: >"$refusals"

for f in "$FIXTURES"/compile_*.iyi "$FIXTURES"/cg_*.iyi; do
  [ -f "$f" ] || continue
  n=$(basename "$f" .iyi)
  total=$((total + 1))
  ref="$WORK/ref/$n"
  nat="$WORK/nat/$n"
  if "$IYI" build -o "$ref" "$f" >"$WORK/ref/$n.log" 2>&1; then ref_ok=1; else ref_ok=0; fi
  if PATH="$TRIPWIRE_PATH:$PATH" "$tool" "$f" -o "$nat" >"$WORK/nat/$n.log" 2>&1; then nat_ok=1; else nat_ok=0; fi

  if [ "$ref_ok" = 0 ] && [ "$nat_ok" = 0 ]; then
    refused_by_both=$((refused_by_both + 1))
    echo "   refused by both compilers: $n"
  elif [ "$ref_ok" = 1 ] && [ "$nat_ok" = 0 ]; then
    reason=$(awk 'NR == 1' "$WORK/nat/$n.log")
    refused=$((refused + 1))
    echo "$n: $reason" >>"$refusals"
    echo "   REFUSED $n: $reason"
  elif [ "$ref_ok" = 0 ] && [ "$nat_ok" = 1 ]; then
    failed=$((failed + 1))
    echo "FAIL: $n: the native tool built a program the hosted compiler refuses"
  else
    if compare_run "$ref" "$nat" "$n"; then
      built=$((built + 1))
    else
      failed=$((failed + 1))
    fi
  fi
done

if tripwire_fired "$WORK/tripwire.log"; then
  echo "FAIL: a host tool started during a native build:"
  echo "$(awk '{ print }' "$WORK/tripwire.log")"
  status=1
fi
echo "  Refusals by name ($refused):"
if [ -s "$refusals" ]; then
  awk '{ print "    " $0 }' "$refusals"
fi
if [ "$failed" -ne 0 ]; then status=1; fi

echo "== 4. mutations: the comparison and the tripwire must each go red"
mut_run=0
mut_caught=0
sample_ref="$WORK/ref/compile_arith"
sample_nat="$WORK/nat/compile_arith"

# (a) a native exit status off by one must be reported as a divergence.
mut_run=$((mut_run + 1))
printf '#!/bin/sh\n"%s"\nrc=$?\nexit $((rc + 1))\n' "$sample_nat" >"$WORK/mut_status"
chmod +x "$WORK/mut_status"
if ! compare_run "$sample_ref" "$WORK/mut_status" "mutation: native exit off by one" >/dev/null 2>&1; then
  mut_caught=$((mut_caught + 1))
  echo "   caught: native exit status off by one"
else
  status=1
  echo "FAIL: mutation not caught: native exit status off by one"
fi

# (b) extra native stdout must be reported as a divergence.
mut_run=$((mut_run + 1))
printf '#!/bin/sh\n"%s"\nrc=$?\necho extra-line\nexit $rc\n' "$sample_nat" >"$WORK/mut_stdout"
chmod +x "$WORK/mut_stdout"
if ! compare_run "$sample_ref" "$WORK/mut_stdout" "mutation: extra native stdout" >/dev/null 2>&1; then
  mut_caught=$((mut_caught + 1))
  echo "   caught: extra native stdout"
else
  status=1
  echo "FAIL: mutation not caught: extra native stdout"
fi

# (c) a host tool that ran during a native build must trip the wire.
mut_run=$((mut_run + 1))
: >"$WORK/tripwire.log"
echo "ld injected-by-mutation" >>"$WORK/tripwire.log"
if tripwire_fired "$WORK/tripwire.log"; then
  mut_caught=$((mut_caught + 1))
  echo "   caught: a host tool call in the tripwire log"
else
  status=1
  echo "FAIL: mutation not caught: host tool call in the tripwire log"
fi

echo "  Mutation summary: $mut_caught/$mut_run native-source mutations caught"
if [ "$mut_caught" -ne "$mut_run" ]; then status=1; fi

echo "  Native source summary: $built of $total fixtures built from source with no LLVM and no host tool and run equal to the hosted build; $refused refused by name; $refused_by_both refused by both compilers; $failed failed"
if [ "$built" -eq 0 ]; then
  echo "FAIL: no source program ran end to end with the native backend"
  status=1
fi

echo
if [ "$status" -eq 0 ]; then
  echo "ALL NATIVE SOURCE CHECKS PASSED!"
else
  echo "SOME NATIVE SOURCE CHECKS FAILED"
  exit 1
fi
