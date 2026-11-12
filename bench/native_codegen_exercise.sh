#!/usr/bin/env bash
# The aarch64 code generation gate (SPEC 2.2, 3.3, 3.5; slice C3). Each IR fixture under
# bench/fixtures/native_cg/ is compiled by the native backend to an object, linked with cc on this
# machine, and run; its exit status and stdout must equal those of the equivalent .iyi program built by the
# hosted compiler. Also checked: the driver links only libSystem, the 64 KiB frame's MIR dump shows
# page-by-page probes, the Linux variant of every fixture encodes (not executed here), and mutations of the
# backend are each caught.
#
#   bench/native_codegen_exercise.sh
#
# Jobs: native-darwin runs every step. The Linux variant is encoded on every host and is never executed by
# this gate; the native-linux job runs the encoder gate (bench/native_encode_exercise.sh) instead.
set -u
cd "$(dirname "$0")/.." || exit 1

WORK=$(mktemp -d "${TMPDIR:-/tmp}/native-codegen.XXXXXX")
RESTORE=()
restore_all() {
  for entry in "${RESTORE[@]+"${RESTORE[@]}"}"; do
    cp "${entry%%|*}" "${entry#*|}" 2>/dev/null
  done
  rm -rf "$WORK"
}
trap restore_all EXIT INT TERM

failed=0
fail() { echo "FAIL: $*"; failed=1; }

export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}

FIX=bench/fixtures/native_cg
DRV="$WORK/native_cg"

build_driver() { ./bin/iyi build -o "$1" src/compiler/tools/native_cg.iyi >"$WORK/build.$(basename "$1").log" 2>&1; }

# ---- 1. the driver -----------------------------------------------------------------------------
echo "== 1. build the driver with the hosted compiler"
if ! build_driver "$DRV"; then
  grep -v 'ld: warning' "$WORK/build.native_cg.log" | tail -20
  fail "the driver does not build"
  exit 1
fi

# ---- 2. the linkage floor ----------------------------------------------------------------------
echo "== 2. the driver links only libSystem"
if [ "$(uname -s)" = "Darwin" ]; then
  if [ "$(otool -L "$DRV" | tail -n +2 | wc -l | tr -d ' ')" = "1" ] && otool -L "$DRV" | grep -q '/usr/lib/libSystem.B.dylib'; then
    echo "libSystem only"
  else
    otool -L "$DRV"
    fail "the driver links more than libSystem"
  fi
else
  echo "skipped: not darwin"
fi

# ---- 3. fixtures: native object, linked with cc and run, equal to the hosted compiler's program ---
echo "== 3. every fixture runs as the hosted compiler's program does"
count=0
for ir in "$FIX"/*.ir; do
  base=$(basename "$ir" .ir)
  iy="$FIX/$base.iyi"
  if [ ! -f "$iy" ]; then
    fail "$base.ir has no equivalent $base.iyi"
    continue
  fi
  if ! "$DRV" obj "$ir" "$WORK/$base.o" >"$WORK/$base.obj.log" 2>&1; then
    cat "$WORK/$base.obj.log"
    fail "$base: the native backend refused the fixture"
    continue
  fi
  if ! cc "$WORK/$base.o" "$FIX/rt_stub.c" -o "$WORK/$base.native" >"$WORK/$base.link.log" 2>&1; then
    fail "$base: cc did not link the native object"
    continue
  fi
  "$WORK/$base.native" >"$WORK/$base.native.out" 2>/dev/null
  echo $? >"$WORK/$base.native.status"
  if ! ./bin/iyi build -o "$WORK/$base.hosted" "$iy" >"$WORK/$base.hosted.log" 2>&1; then
    grep -v 'ld: warning' "$WORK/$base.hosted.log" | tail -5
    fail "$base: the hosted compiler does not build $base.iyi"
    continue
  fi
  "$WORK/$base.hosted" >"$WORK/$base.hosted.out" 2>/dev/null
  echo $? >"$WORK/$base.hosted.status"
  if cmp -s "$WORK/$base.native.out" "$WORK/$base.hosted.out" && cmp -s "$WORK/$base.native.status" "$WORK/$base.hosted.status"; then
    echo "$base: stdout and status equal ($(tr -d '\n' <"$WORK/$base.native.status") exit)"
    count=$((count + 1))
  else
    echo "--- native $base"; cat "$WORK/$base.native.out"; echo "--- hosted $base"; cat "$WORK/$base.hosted.out"
    fail "$base: the native program differs from the hosted compiler's"
  fi
done
[ "$count" -gt 0 ] || fail "no fixture ran"
echo "ran $count fixtures against the hosted compiler"

# ---- 4. the 64 KiB frame: the MIR dump shows the probe page by page ----------------------------
echo "== 4. the 64 KiB frame is entered page by page"
probes=$("$DRV" mir "$FIX/frame64k.ir" big | grep -c 'ZeroSp')
if [ "$probes" -ge 16 ]; then
  echo "probes in the dump: $probes"
else
  fail "the frame dump shows $probes probes; a 65 KiB frame needs 16"
fi

# ---- 4b. each atomicrmw ordering selects the same load-exclusive and store-exclusive pair -------------
echo "== 4b. monotonic and seq_cst atomicrmw select the same instructions"
seq_mir=$("$DRV" mir "$FIX/rmw.ir" ord_seq | tail -n +2)
mono_mir=$("$DRV" mir "$FIX/rmw.ir" ord_mono | tail -n +2)
if [ -n "$seq_mir" ] && [ "$seq_mir" = "$mono_mir" ] && echo "$seq_mir" | grep -q 'Ldaxr' && echo "$seq_mir" | grep -q 'Stlxr'; then
  echo "monotonic and seq_cst both select Ldaxr and Stlxr, identically"
else
  fail "the two orderings select different instructions"
fi


# ---- 5. the Linux variant encodes; it is not executed here -------------------------------------
echo "== 5. aarch64-linux-gnu variant of each fixture encodes (not executed)"
linux_count=0
for ir in "$FIX"/*.ir; do
  base=$(basename "$ir" .ir)
  sed -e 's/^target triple = .*/target triple = "aarch64-unknown-linux-gnu"/' \
      -e 's/^target datalayout = .*/target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"/' \
      "$ir" >"$WORK/$base.linux.ir"
  if "$DRV" obj "$WORK/$base.linux.ir" "$WORK/$base.linux.o" >"$WORK/$base.linux.log" 2>&1; then
    linux_count=$((linux_count + 1))
  else
    cat "$WORK/$base.linux.log"
    fail "$base: the Linux variant does not encode"
  fi
done
echo "encoded $linux_count Linux variants; ELF writing is a later slice, so none was written or executed"

# ---- 6. mutation proofs ------------------------------------------------------------------------
# Applies one mutation to `file`, builds the driver from the mutated source, runs the check that must then
# fail, and restores the file. The text must occur exactly once, and the mutation must change it.
prove_mutation() {
  local name=$1 file=$2 old=$3 new=$4 check=$5
  local hits
  hits=$(python3 -c 'import sys; print(open(sys.argv[1]).read().count(sys.argv[2]))' "$file" "$old")
  if [ "$hits" != "1" ]; then
    fail "mutation $name: the text must occur exactly once (found $hits)"
    return
  fi
  if [ "$old" = "$new" ]; then
    echo "PATCH CHANGED NOTHING: this proves nothing"
    fail "mutation $name: the mutation changes nothing"
    return
  fi
  local backup="$WORK/backup.$RANDOM"
  cp "$file" "$backup"
  RESTORE+=("$file|$backup")
  python3 -c 'import sys; p,o,n=sys.argv[1:4]; s=open(p).read(); open(p,"w").write(s.replace(o,n,1))' "$file" "$old" "$new"
  local mut="$WORK/mutant.$RANDOM"
  if ! build_driver "$mut"; then
    cp "$backup" "$file"
    fail "mutation $name: the mutant does not build, so it proves nothing"
    return
  fi
  if "$check" "$mut" >/dev/null 2>&1; then
    cp "$backup" "$file"
    fail "mutation $name: NOT caught"
  else
    cp "$backup" "$file"
    echo "caught: $name"
  fi
}

# Checks against the expected outputs from step 3. Each returns non-zero when the driver's output differs.
check_fixture() {
  local drv=$1 base=$2
  "$drv" obj "$FIX/$base.ir" "$WORK/m.$base.o" >/dev/null 2>&1 || return 1
  cc "$WORK/m.$base.o" "$FIX/rt_stub.c" -o "$WORK/m.$base.bin" >/dev/null 2>&1 || return 1
  "$WORK/m.$base.bin" >"$WORK/m.$base.out" 2>/dev/null
  local status=$?
  cmp -s "$WORK/m.$base.out" "$WORK/$base.hosted.out" && [ "$status" = "$(tr -d '\n' <"$WORK/$base.hosted.status")" ]
}
check_arith() { check_fixture "$1" arith; }
check_recursion() { check_fixture "$1" control; }
check_iyiagg() { check_fixture "$1" iyiagg; }
check_byval() { check_fixture "$1" byval; }
check_rmw() { check_fixture "$1" rmw; }
check_mem() { check_fixture "$1" mem; }
check_wide() { check_fixture "$1" wide; }
check_probe() {
  local n
  n=$("$1" mir "$FIX/frame64k.ir" big | grep -c 'ZeroSp')
  [ "$n" -ge 16 ]
}

echo "== 6. mutations are each caught"
prove_mutation "isel: the subtraction's operands swap" \
  src/compiler/native/aarch64/isel.iyi \
  'bind_result(i, [canon(binop(kind, a, b), t)])' \
  'bind_result(i, [canon(binop(kind, b, a), t)])' \
  check_arith
prove_mutation "frame: callee-saved registers are not saved in the prologue" \
  src/compiler/native/frame.iyi \
  '    m = MInst.new(MOp::SpStore)' \
  '    m = MInst.new(MOp::Label)' \
  check_recursion
prove_mutation "frame: the stack probe is dropped" \
  src/compiler/native/frame.iyi \
  '    acc << MInst.new(MOp::ZeroSp)' \
  '    acc << MInst.new(MOp::Label)' \
  check_probe
prove_mutation "iyi convention: the second leaf of a split aggregate takes the wrong register" \
  src/compiler/native/lower.iyi \
  'locs << LeafLoc.new(0, desc.integer_args[gpr_next], -1_i64, bits, false, leaf)' \
  'locs << LeafLoc.new(0, desc.integer_args[gpr_next + k], -1_i64, bits, false, leaf)' \
  check_iyiagg
prove_mutation "byval: the caller passes its own object instead of a copy" \
  src/compiler/native/aarch64/isel.iyi \
  '    [dst]
  end

  # Copies' \
  '    [source]
  end

  # Copies' \
  check_byval
prove_mutation "atomicrmw max: the keep branch selects the smaller value" \
  src/compiler/native/aarch64/isel.iyi \
  'cond = signed ? cond_gt : cond_hi' \
  'cond = signed ? cond_lt : cond_hi' \
  check_rmw
prove_mutation "memmove: a large move calls the copy helper" \
  src/compiler/native/aarch64/isel.iyi \
  'overlap ? "__iyi_native_memmove" : "__iyi_native_memcpy"' \
  '"__iyi_native_memcpy"' \
  check_mem
prove_mutation "i128 add: the two halves of the sum are bound in reverse" \
  src/compiler/native/aarch64/isel.iyi \
  'bind_result(i, [lo, binop(MOp::Adc, a[1], b[1])])' \
  'bind_result(i, [binop(MOp::Adc, a[1], b[1]), lo])' \
  check_wide
prove_mutation "i128 add: the carry into the high half is dropped" \
  src/compiler/native/aarch64/isel.iyi \
  'bind_result(i, [lo, binop(MOp::Adc, a[1], b[1])])' \
  'bind_result(i, [lo, binop(MOp::Add, a[1], b[1])])' \
  check_wide
prove_mutation "i128 argument: the high half is passed in the low half's register" \
  src/compiler/native/lower.iyi \
  'LeafLoc.new(0, desc.integer_args[gpr_next + 1], -1_i64, 64, false, leaves[1][1])' \
  'LeafLoc.new(0, desc.integer_args[gpr_next], -1_i64, 64, false, leaves[1][1])' \
  check_wide
echo "a mutation that changes nothing is refused by the proof helper:"
if prove_mutation "no-op: the same text on both sides" \
    src/compiler/native/frame.iyi \
    '    m = MInst.new(MOp::SpStore)' \
    '    m = MInst.new(MOp::SpStore)' \
    check_probe | grep -q 'PATCH CHANGED NOTHING'; then
  echo "refused: the no-op proof does not pass"
else
  fail "the proof helper accepted a mutation that changes nothing"
fi

echo
if [ "$failed" -eq 0 ]; then
  echo "== THE NATIVE CODEGEN CHECKS PASS"
  exit 0
fi
echo "== SOME NATIVE CODEGEN CHECKS FAILED"
exit 1
