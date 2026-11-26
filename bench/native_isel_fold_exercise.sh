#!/usr/bin/env bash
# AArch64 selector folds: MIR shape, hosted execution parity and mutations.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd)
. bench/lib/host.sh || exit 1
require_test_host || exit 1
if [ -z "$PY" ]; then
  echo "a functional Python interpreter is required" >&2
  exit 1
fi
if [ "$HOST_OS" = darwin ]; then
  export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
  export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
fi
export IYI_PATH="$(native_path "$REPO/src")"
unset IYI_NATIVE_REGALLOC
WORK=$(mktemp -d "${TMPDIR:-/tmp}/native-isel-fold.XXXXXX") || exit 1
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
failed=0
fail() { echo "FAIL: $*"; failed=1; }
. bench/lib/native_signature.sh
. bench/lib/mutation.sh
export NATIVE_SIGNATURE_FAILURE_FILE="$WORK/signature-failure"
FIX=bench/fixtures/native_isel_fold
DRV="$WORK/native_cg$EXE"
export S10_DIVISION_IR="$WORK/division.ir"
if ! "$PY" "$(native_path "$FIX/division_table.py")" "$(native_path "$WORK")"; then
  echo "SOME NATIVE ISEL FOLD CHECKS FAILED"
  exit 1
fi

build_driver() {
  ./bin/iyi build -o "$(native_path "$1")" "$(native_path src/compiler/tools/native_cg.iyi)" >"$WORK/build.$(basename "$1").log" 2>&1
}

# Exit 1 denotes a timeout, 2 an unobservable execution.
bounded_run() {
  local exe=$1 prefix=$2 status
  rm -f "$prefix.timeout" "$prefix.exec-error" "$prefix.done" || return 2
  perl -e '
    my ($timeout, $error, $done, $exe) = @ARGV;
    my $pid = fork();
    defined($pid) or die "fork: $!";
    if ($pid == 0) {
      alarm 20;
      exec { $exe } $exe;
      open my $fh, ">", $error or die "exec and error marker failed: $!";
      print $fh "exec failed: $!\n";
      close $fh or die "error marker: $!";
      exit 127;
    }
    my $waited = waitpid($pid, 0);
    my $status = $?;
    $waited == $pid or die "waitpid: $!";
    if (($status & 127) == 14) {
      open my $fh, ">", $timeout or die "timeout marker: $!";
      close $fh or die "timeout marker: $!";
    }
    open my $fh, ">", $done or die "completion marker: $!";
    close $fh or die "completion marker: $!";
    exit (($status & 127) ? 128 + ($status & 127) : $status >> 8);
  ' "$prefix.timeout" "$prefix.exec-error" "$prefix.done" "$exe" </dev/null >"$prefix.out" 2>/dev/null
  status=$?
  echo "$status" >"$prefix.status" || return 2
  [ -e "$prefix.done" ] && [ ! -e "$prefix.exec-error" ] || return 2
  [ ! -e "$prefix.timeout" ] || return 1
  return 0
}

emit_obj() {
  local drv=$1 clean=$2 ir=$3 prefix=$4
  [ -x "$drv" ] && [ -f "$ir" ] || return 2
  rm -f "$prefix.o" || return 2
  IYI_NATIVE_MIR_CLEAN=$clean "$drv" obj "$(native_path "$ir")" "$(native_path "$prefix.o")" >"$prefix.obj.log" 2>&1 || return 2
  [ -s "$prefix.o" ] || return 2
}

run_obj() {
  local prefix=$1
  cc "$prefix.o" bench/fixtures/native_cg/rt_stub.c -o "$prefix.bin" >"$prefix.link.log" 2>&1 || return 2
  native_signature_ok "$prefix.bin" || return 2
  bounded_run "$prefix.bin" "$prefix"
}

# A mismatch or a timeout is a detected behavioral defect; setup failures are invalid.
check_output() {
  local drv=$1 clean=$2 key=$3 prefix="$WORK/check.$3.$2" rc ext ir="$FIX/$3.ir"
  [ "$key" != division ] || ir="$WORK/division.ir"
  [ -f "$WORK/expected.$key.out" ] && [ -f "$WORK/expected.$key.status" ] || return 2
  emit_obj "$drv" "$clean" "$ir" "$prefix" || { cat "$prefix.obj.log" 2>/dev/null || true; return 2; }
  run_obj "$prefix"
  rc=$?
  [ "$rc" -ne 1 ] || { echo "decisive: $key timed out"; return 1; }
  [ "$rc" -eq 0 ] || { cat "$prefix.link.log" 2>/dev/null || true; return 2; }
  for ext in out status; do
    cmp -s "$prefix.$ext" "$WORK/expected.$key.$ext"
    rc=$?
    [ "$rc" -ne 1 ] || { echo "decisive: $key $ext differs from the hosted twin"; return 1; }
    [ "$rc" -eq 0 ] || return 2
  done
  return 0
}

echo "== 1. build the native codegen driver"
if ! build_driver "$DRV"; then
  cat "$WORK/build.$(basename "$DRV").log"
  echo "SOME NATIVE ISEL FOLD CHECKS FAILED"
  exit 1
fi

echo "== 1b. check branch bounds and far-branch relaxation"
cat >"$WORK/branch_bounds.iyi" <<'IYI'
module branch_bounds

import compiler/native/mir::{MFunction, MBlock, MInst, MOp, Operand, OperandKind, FrameInfo}
import compiler/native/aarch64/encode::{Encoder, EncodedFunction, EncodeError, encode_function}

def check(op : MOp, delta : Int64, accepted : Bool) : Nil
  enc = Encoder.new(FrameInfo.new)
  branch = MInst.new(op.value.to_i32)
  branch.uses << Operand.new(OperandKind::Physical, 1)
  branch.target = 1
  enc.emit(branch)
  enc.finish([0_i64, delta])
  raise "branch range #{op} #{delta}" unless enc.failure.nil? == accepted
end
def check_long(bytes : Array(UInt8), pos : Int32, middle : UInt8, high : UInt8, target : Int64) : Nil
  raise "wrong inverse branch" unless bytes[pos] == 0x41_u8 && bytes[pos + 1] == 0_u8 && bytes[pos + 2] == middle && bytes[pos + 3] == high
  word = bytes[pos + 4].to_i64 | (bytes[pos + 5].to_i64 << 8) | (bytes[pos + 6].to_i64 << 16) | (bytes[pos + 7].to_i64 << 24)
  raise "missing long branch" unless (word & 0xFC000000_i64) == 0x14000000_i64
  delta = word & 0x3FFFFFF_i64
  delta = delta - 0x4000000_i64 if delta >= 0x2000000_i64
  raise "wrong long-branch target" unless (pos + 4).to_i64 + delta * 4_i64 == target
end

def check_relaxation : Nil
  fn = MFunction.new("relaxed")
  first = MBlock.new(0, "first")
  last = MBlock.new(1, "last")
  fn.blocks << first
  fn.blocks << last
  [MOp::Bcond, MOp::Cbz, MOp::Cbnz, MOp::Tbz, MOp::Tbnz].each do |op|
    branch = MInst.new(op.value.to_i32)
    branch.target = 1
    branch.imm = 5_i64
    branch.uses << Operand.new(OperandKind::Physical, 1)
    first.insts << branch
  end
  filler = MInst.new(MOp::Brk.value.to_i32)
  n = 0
  while n < 262144
    first.insts << filler
    n = n + 1
  end
  back = MInst.new(MOp::Tbz.value.to_i32)
  back.target = 0
  back.imm = 5_i64
  back.uses << Operand.new(OperandKind::Physical, 1)
  last.insts << back
  result = encode_function(fn)
  raise result.as(EncodeError).message if result.is_a?(EncodeError)
  encoded = result.as(EncodedFunction)
  target = encoded.block_offsets[1]
  check_long(encoded.bytes, 0, 0_u8, 0x54_u8, target)
  check_long(encoded.bytes, 8, 0_u8, 0xB5_u8, target)
  check_long(encoded.bytes, 16, 0_u8, 0xB4_u8, target)
  check_long(encoded.bytes, 24, 0x28_u8, 0x37_u8, target)
  check_long(encoded.bytes, 32, 0x28_u8, 0x36_u8, target)
  check_long(encoded.bytes, target.to_i32, 0x28_u8, 0x37_u8, 0_i64)
end


check(MOp::Cbz, 1048572_i64, true)
check(MOp::Cbz, 1048576_i64, false)
check(MOp::Cbnz, -1048576_i64, true)
check(MOp::Cbnz, -1048580_i64, false)
check(MOp::Bcond, 1048572_i64, true)
check(MOp::Bcond, 1048576_i64, false)
check(MOp::Tbz, 32764_i64, true)
check(MOp::Tbz, 32768_i64, false)
check(MOp::Tbnz, -32768_i64, true)
check(MOp::Tbnz, -32772_i64, false)
check_relaxation
puts "far branch relaxation: 5 forward forms and 1 backward form checked"
puts "branch displacement bounds: 10 checked"
IYI
if ! ./bin/iyi build -o "$(native_path "$WORK/branch_bounds$EXE")" "$(native_path "$WORK/branch_bounds.iyi")" >"$WORK/branch_bounds.log" 2>&1; then
  cat "$WORK/branch_bounds.log"
  fail "branch displacement check did not build"
elif ! "$WORK/branch_bounds$EXE"; then
  fail "branch displacement check failed"
fi

cat >"$WORK/check_mir.py" <<'PY'
import os
import re
import subprocess
import sys
from pathlib import Path

drv, fixture_dir = sys.argv[1:]
fixture_dir = Path(fixture_dir)
errors = []
defects = []
checks = 0

def dump(fixture, function, clean):
    env = dict(os.environ, IYI_NATIVE_MIR_CLEAN=str(clean))
    try:
        ir = Path(os.environ["S10_DIVISION_IR"]) if fixture == "division" else fixture_dir / (fixture + ".ir")
        proc = subprocess.run([drv, "mir", str(ir), function],
                              env=env, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"{function}: cannot run MIR driver: {exc}")
        return ""
    if proc.returncode or not proc.stdout.startswith("function " + function + "\n"):
        errors.append(f"{function}: invalid MIR: {proc.stderr.strip()}")
        return ""
    return proc.stdout

def expect(fixture, function, required, forbidden=(), clean=1):
    global checks
    text = dump(fixture, function, clean)
    if not text:
        return
    checks += 1
    for pattern in required:
        if not re.search(pattern, text, re.MULTILINE):
            defects.append(f"{function}: missing {pattern}")
    for pattern in forbidden:
        if re.search(pattern, text, re.MULTILINE):
            defects.append(f"{function}: unexpected {pattern}")

op = lambda name: r"^  " + name + r"/"
expect("branches", "compare", [op("CmpImm"), r"#imm=5", op("Bcond")], [op("Cset"), op("Cmp")])
expect("branches", "shared_cmp", [op("Cset")])
expect("branches", "null_eq", [op("Cbnz")], [op("Cset"), op("CmpImm")])
for fn, original, inverse in [("zero_eq", "Cbz", "Cbnz"), ("zero_ne", "Cbnz", "Cbz"),
                              ("bit_zero", "Tbz", "Tbnz"), ("bit_one", "Tbnz", "Tbz")]:
    absent = [op("Cset"), op("Cmp"), op("CmpImm"), op("And"), op("AndImm")]
    expect("branches", fn, [op(original) + r".*target=1"], absent, 0)
    expect("branches", fn, [op(inverse) + r".*target=2"], [op(original)] + absent, 1)
expect("memory", "frame", [r"StrFrame/64 .*slot0\+16", r"LdrFrame/64 .*slot0\+16"], [op("AddrFrame")])
expect("memory", "read_next", [r"Ldr/64 .*#imm=8"], [op("Add"), op("AddImm"), op("AddrFrame")])
expect("memory", "read_prev", [r"Ldr/64 .*#imm=-8"], [op("Add"), op("AddImm"), op("AddrFrame")])
expect("memory", "big_frame", [r"StrFrame/64 .*slot0\+65536", r"LdrFrame/64 .*slot0\+65536"], [op("AddrFrame")])
expect("immediates", "add_small", [op("AddImm"), r"#imm=4095"], [op("Add"), op("MovImm")])
expect("immediates", "add_negative", [op("SubImm"), r"#imm=37"], [op("Add"), op("MovImm")])
expect("immediates", "sub_negative", [op("AddImm"), r"#imm=42"], [op("Sub"), op("MovImm")])
expect("immediates", "add_large", [op("MovImm"), r"#imm=4096", op("Add")], [op("AddImm")])
expect("immediates", "logic", [op("AndImm"), op("OrrImm"), op("EorImm")], [op("And"), op("Orr"), op("Eor")])
expect("immediates", "repeat_mask", [op("EorImm")], [op("Eor"), op("MovImm")])
expect("immediates", "shifts", [op("LslImm"), op("LsrImm"), op("AsrImm")], [op("Lsl"), op("Lsr"), op("Asr")])
expect("immediates", "negative_compare", [op("CmnImm"), r"#imm=42", op("Bcond")], [op("Cmp"), op("Cset")])
expect("immediates", "large_compare", [op("MovImm"), r"#imm=4096", op("Cmp")], [op("CmpImm"), op("Cset")])
expect("immediates", "unsigned_narrow_compare", [op("CmpImm") + r".*#imm=200$", op("Bcond")], [op("CmnImm"), op("Cset")])
for fn, arithmetic in [("sadd64", "Adds"), ("ssub64", "Subs"), ("uadd64", "Adds"),
                       ("usub64", "Subs"), ("smul64", "Smulh"), ("umul64", "Umulh"),
                       ("sadd8", "Add"), ("uadd8", "Add")]:
    expect("overflow", fn, [op(arithmetic), op("Bcond")], [op("Cset")])
expect("overflow", "early_value", [op("Cset"), op("Cbz")])
for fn in ("overflow_zero", "overflow_narrow_zero"):
    expect("deferred", fn, [op("Bcond"), r"^  Cb(n)?z/"], [op("Tbz"), op("Tbnz"), op("Cset")])
expect("deferred", "overflow_compare", [op("Adds"), op("CmnImm"), op("Bcond")], [op("Cset")])
expect("deferred", "multi_bit", [op("AndImm"), r"^  Cb(n)?z/"], [op("Tbz"), op("Tbnz"), op("Cset")])
for fn in ("nested_compare", "hint_compare"):
    expect("deferred", fn, [op("Cset"), r"^  Cb(n)?z/"], [op("Tbz"), op("Tbnz")])
expect("deferred", "gep_other", [op("AddImm"), op("Ldr"), r"^  Cb(n)?z/"], [op("Tbz"), op("Tbnz")])
for fn in ("load64", "load32", "load16", "load8"):
    expect("indexed", fn, [op("LdrReg")], [op("Mul")])
for fn in ("store64", "store32", "store16", "store8"):
    expect("indexed", fn, [op("StrReg")], [op("Mul")])
expect("indexed", "wrong_scale", [op("Mul"), op("Ldr")], [op("LdrReg")])
expect("indexed", "shared_address", [op("Mul"), op("Ldr"), op("Str")], [op("LdrReg"), op("StrReg")])
for fn in ("s8_p3", "s16_m7", "s32_p10", "s64_p7", "u8_p3", "u16_p7", "u32_p10", "u64_p7"):
    expect("division", fn, [op("Umulh"), op("Msub")], [op("Sdiv"), op("Udiv")])
for fn in ("u8_p2", "u16_p64", "u32_p2", "u64_p64"):
    expect("division", fn, [op("LsrImm"), op("Msub")], [op("Sdiv"), op("Udiv"), op("Umulh")])
for fn in ("add_left", "add_right", "narrow"):
    expect("mulacc", fn, [op("Madd")], [op("Mul")])
expect("mulacc", "sub_left", [op("Neg"), op("Madd")], [op("Mul")])
expect("mulacc", "sub_right", [op("Msub")], [op("Mul")])
expect("mulacc", "shared_mul", [op("Mul")], [op("Madd"), op("Msub")])
expect("mulacc", "constant_add", [op("Mul"), op("AddImm")], [op("Madd"), op("Msub")])
expect("mulacc", "constant_sub", [op("Mul"), op("SubImm")], [op("Madd"), op("Msub")])
for fn in ("choose", "choose_hint"):
    expect("select", fn, [op("CmpImm"), op("Csel")], [op("Cset")])
expect("select", "choose_shared", [op("Cset"), op("Csel")])
for fn in ("float_ordered", "float_unordered"):
    expect("select", fn, [op("FCmp"), op("Csel")], [op("Cset")])
expect("select", "float_composite", [op("FCmp"), op("Cset"), op("Csel")])
for fn in ("load_pair", "interleaved", "reverse_pair", "narrow_pair", "float_pair"):
    expect("pairs", fn, [op("Ldp")], [op("Ldr")])
expect("pairs", "store_pair", [op("Stp")], [op("Str")])
for fn in ("load_gap", "different_bases"):
    expect("pairs", fn, [op("Ldr")], [op("Ldp")])
expect("leaf", "plain_leaf", [op("Ret")], [op("StpFpLr"), op("MovFp"), op("LdpFpLr"), op("SpAdjust")])
expect("leaf", "slot_leaf", [op("StpFpLr"), op("LdrFrame"), op("StrFrame"), op("LdpFpLr")])
expect("leaf", "stack_arg", [op("StpFpLr"), r"Ldr/64 .*x29", op("LdpFpLr")])
expect("leaf", "asm_leaf", [op("StpFpLr"), op("InlineAsm"), op("LdpFpLr")])
expect("leaf", "saved_leaf", [op("StpFpLr"), op("SpStore"), op("SpLoad"), op("LdpFpLr")])
expect("leaf", "nonleaf", [op("StpFpLr"), op("Bl"), op("LdpFpLr")])
# R6, narrow selection: a signed i32 checked add or subtract uses the 32-bit flag-setting form and branches on vs;
# nsw and unsigned constant division skip the canonicalising extension. The entry canonicalisation of the parameters
# comes before each operation, so each forbidden shape looks after the operation.
for clean in (0, 1):
    expect("narrow", "sadd32", [r"^  Adds/32 ", op("Bcond")], [r"^  Adds/64", op("Cmp"), op("Cset")], clean)
    expect("narrow", "ssub32", [r"^  Subs/32 ", op("Bcond")], [r"^  Subs/64", op("Cmp"), op("Cset")], clean)
    expect("narrow", "wrap_add32", [r"^  Add/64[\s\S]*^  Sbfm/"], [], clean)
    expect("narrow", "nsw_add32", [r"^  Add/64"], [r"^  Add/64[\s\S]*^  Sbfm/"], clean)
    expect("narrow", "nsw_mul16", [r"^  Mul/64"], [r"^  Mul/64[\s\S]*^  Sbfm/"], clean)
    expect("narrow", "nsw_sub8", [r"^  Sub/64"], [r"^  Sub/64[\s\S]*^  Sbfm/"], clean)
    expect("narrow", "urem7", [r"^  Msub/64"], [r"^  Msub/64[\s\S]*^  Sbfm/"], clean)
    expect("narrow", "udiv3", [r"^  Umulh/64"], [r"^  Umulh/64[\s\S]*^  Sbfm/"], clean)
    expect("narrow", "udiv1", [r"^  Ubfm/64[\s\S]*^  Sbfm/"], [], clean)
for problem in errors:
    print("INVALID: " + problem)
for problem in defects:
    print("decisive: " + problem)
print(f"MIR shape checks: {checks}")
if errors or checks == 0:
    sys.exit(2)
if defects:
    sys.exit(1)
PY

echo "== 2. assert folded and retained MIR shapes"
if ! "$PY" "$(native_path "$WORK/check_mir.py")" "$(native_path "$DRV")" "$(native_path "$FIX")"; then
  fail "MIR shape checks"
fi
# For each width, the shift must consume the zero-extension, not the signed input.
check_unsigned_shift_shape() {
  "$PY" - "$(native_path "$1")" "$(native_path "$FIX/unsigned_shift.ir")" <<'PY'
import os
import re
import subprocess
import sys

driver, fixture = sys.argv[1:]
checks = 0
for clean in ("0", "1"):
    for bits in (8, 16, 32):
        name = f"shift{bits}"
        try:
            proc = subprocess.run([driver, "mir", fixture, name],
                                  env=dict(os.environ, IYI_NATIVE_MIR_CLEAN=clean,
                                           IYI_NATIVE_REGALLOC="linear"),
                                  capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"INVALID {name}: {exc}")
            sys.exit(2)
        if proc.returncode or not proc.stdout.startswith(f"function {name}\n"):
            print(f"INVALID {name}: {proc.stderr or proc.stdout}")
            sys.exit(2)
        lines = proc.stdout.splitlines()
        shifts = [(index, re.fullmatch(r"  LsrImm/64 x\d+, (x\d+) #imm=1", line))
                  for index, line in enumerate(lines)]
        shifts = [(index, match) for index, match in shifts if match]
        if len(shifts) != 1:
            print(f"decisive: {name} clean={clean} expected one immediate shift")
            sys.exit(1)
        index, shift = shifts[0]
        expected = rf"  Ubfm/64 {shift.group(1)}, x\d+ #imm={bits}"
        if index == 0 or not re.fullmatch(expected, lines[index - 1]):
            print(f"decisive: {name} clean={clean} shift input is not zero-extended from {bits} bits")
            sys.exit(1)
        checks += 1
print(f"unsigned narrow shifts: {checks} zero-extension data-flow checks")
PY
}

if ! check_unsigned_shift_shape "$DRV"; then
  fail "unsigned immediate shift shape"
fi

if [ "$HOST_ID" = darwin-arm64 ]; then
  if ! ./bin/iyi build -o "$(native_path "$WORK/unsigned_shift.hosted$EXE")" \
      "$(native_path "$FIX/unsigned_shift.iyi")" >"$WORK/unsigned_shift.hosted.log" 2>&1; then
    cat "$WORK/unsigned_shift.hosted.log"
    fail "unsigned_shift: hosted twin did not build"
  elif ! bounded_run "$WORK/unsigned_shift.hosted$EXE" "$WORK/expected.unsigned_shift" ||
       [ "$(cat "$WORK/expected.unsigned_shift.status")" != 0 ]; then
    fail "unsigned_shift: hosted twin could not be observed"
  else
    for mode in 0 1; do
      if ! check_output "$DRV" "$mode" unsigned_shift; then
        fail "unsigned_shift: clean=$mode differs from hosted negative-input twin"
      else
        echo "parity: unsigned_shift negative inputs (clean=$mode)"
      fi
    done
  fi
fi


echo "== 3. compare native execution with hosted twins"
if [ "$HOST_ID" = darwin-arm64 ]; then
  for tool in cc perl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      fail "required runtime tool is missing: $tool"
      echo "SOME NATIVE ISEL FOLD CHECKS FAILED"
      exit 1
    fi
  done
  for key in branches memory immediates overflow deferred indexed division mulacc select pairs leaf; do
    source="$FIX/$key.iyi"
    [ "$key" != division ] || source="$WORK/division.iyi"
    if ! ./bin/iyi build -o "$(native_path "$WORK/$key.hosted$EXE")" "$(native_path "$source")" >"$WORK/$key.hosted.log" 2>&1; then
      cat "$WORK/$key.hosted.log"
      fail "$key: hosted twin did not build"
      continue
    fi
    if ! bounded_run "$WORK/$key.hosted$EXE" "$WORK/expected.$key"; then
      fail "$key: hosted twin could not be observed"
      continue
    fi
    if [ "$(cat "$WORK/expected.$key.status")" != 0 ]; then
      fail "$key: hosted twin exited nonzero"
      continue
    fi
    parity_ok=1
    for mode in 0 1; do
      if ! check_output "$DRV" "$mode" "$key"; then
        parity_ok=0
        fail "$key: clean=$mode differs from hosted"
      fi
      if [ "$key" = pairs ] && ! IYI_NATIVE_REGALLOC=pin check_output "$DRV" "$mode" "$key"; then
        parity_ok=0
        fail "$key: pin allocator clean=$mode differs from hosted"
      fi
    done
    [ "$parity_ok" -eq 0 ] || echo "parity: $key (clean=0,1)"
  done
  # R6: narrow overflow, wrap, nsw and unsigned constant division, against the hosted twin.
  if ! ./bin/iyi build -o "$(native_path "$WORK/narrow.hosted$EXE")" "$(native_path "$FIX/narrow.iyi")" >"$WORK/narrow.hosted.log" 2>&1; then
    cat "$WORK/narrow.hosted.log"
    fail "narrow: hosted twin did not build"
  elif ! bounded_run "$WORK/narrow.hosted$EXE" "$WORK/expected.narrow"; then
    fail "narrow: hosted twin could not be observed"
  elif [ "$(cat "$WORK/expected.narrow.status")" != 0 ]; then
    fail "narrow: hosted twin exited nonzero"
  else
    parity_ok=1
    for mode in 0 1; do
      if ! check_output "$DRV" "$mode" narrow; then
        parity_ok=0
        fail "narrow: clean=$mode differs from hosted"
      fi
    done
    [ "$parity_ok" -eq 0 ] || echo "parity: narrow (clean=0,1)"
  fi
else
  host_limited "Darwin objects cannot be linked or executed on $HOST_ID"
fi

MUTATION_INVALID="$WORK/mutation.invalid"
check_mutant() {
  local key=$1 mutant="$WORK/mutant$EXE" rc
  if ! build_driver "$mutant"; then
    cat "$WORK/build.$(basename "$mutant").log"
    touch "$MUTATION_INVALID"
    return 2
  fi
  if [ "$key" = deferred ]; then
    if ! "$mutant" mir "$(native_path "$FIX/deferred.ir")" overflow_zero >"$WORK/mutant.deferred.log" 2>&1; then
      if grep -q 'index 1 out of range for 1 elements' "$WORK/mutant.deferred.log"; then
        echo "decisive: deferred overflow leaf was mistaken for a bit test"
        return 1
      fi
      cat "$WORK/mutant.deferred.log"
      touch "$MUTATION_INVALID"
      return 2
    fi
  fi
  check_output "$mutant" 1 "$key"
  rc=$?
  if [ "$rc" -eq 2 ]; then
    touch "$MUTATION_INVALID"
    return 2
  fi
  return "$rc"
}

prove_fold_mutation() {
  local label=$1 file=$2 old=$3 new=$4 key=$5
  rm -f "$MUTATION_INVALID"
  if ! prove_mutation "$label" "$file" "$old" "$new" -- check_mutant "$key"; then
    fail "mutation was not caught: $label"
  fi
  [ ! -e "$MUTATION_INVALID" ] || fail "mutation check had invalid setup: $label"
}

check_unsigned_shift_mutant() {
  local mutant="$WORK/mutant.shift$EXE" rc=0
  if ! build_driver "$mutant"; then
    cat "$WORK/build.$(basename "$mutant").log"
    touch "$MUTATION_INVALID"
    return 0
  fi
  check_unsigned_shift_shape "$mutant" || rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    touch "$MUTATION_INVALID"
    return 0
  fi
  return "$rc"
}

if ! prove_mutation "unsigned immediate shift: omit zero-extension" \
    src/compiler/native/aarch64/isel.iyi \
    '    a = zext(a, i.type) if op == Op::LShr' \
    '    a = zext(a, i.type) if false' \
    -- check_unsigned_shift_mutant; then
  fail "unsigned immediate shift mutation was not caught"
fi
[ ! -e "$MUTATION_INVALID" ] || fail "unsigned immediate shift mutation had invalid setup"

echo "== 4. mutation proofs"
if [ "$HOST_ID" = darwin-arm64 ]; then
  prove_fold_mutation "fusion: wrong comparison condition" src/compiler/native/aarch64/isel.iyi '        bc.cond = int_cond(cmp.aux_int) # fold-compare-condition' '        bc.cond = cond_eq # fold-compare-condition' branches
  prove_fold_mutation "frame: dropped slot offset" src/compiler/native/aarch64/isel.iyi '      return {Operand.new(OperandKind::FrameSlot, slot, offset), 0_i64} # fold-frame-offset' '      return {Operand.new(OperandKind::FrameSlot, slot, 0_i64), 0_i64} # fold-frame-offset' memory
  prove_fold_mutation "immediate: accept an out-of-range value" src/compiler/native/aarch64/fold.iyi '  value >= -4095_i64 && value <= 4095_i64 # fold-immediate-range' '  value >= -4095_i64 && value <= 4096_i64 # fold-immediate-range' immediates
  prove_fold_mutation "inversion: leave zero branch unchanged" src/compiler/native/target.iyi '      inst.opcode = MOp::Cbnz.value.to_i32 # invert-zero-branch' '      inst.opcode = inst.opcode # invert-zero-branch' branches
  prove_fold_mutation "deferred: overflow leaf is not a bit test" src/compiler/native/aarch64/isel.iyi '          if other.is_a?(Inst) && @deferred[other]? == DeferredKind::BitTest && bit_test(other) >= 0 # deferred-bit-test' '          if other.is_a?(Inst) && @deferred.has_key?(other) # deferred-bit-test' deferred
  prove_fold_mutation "indexed: omit access-size scale" src/compiler/native/aarch64/encode.iyi '    base = base | 0x1000_i64 if inst.size > 8 # indexed-access-scale' '    base = base | 0_i64 if inst.size > 8 # indexed-access-scale' indexed
  prove_fold_mutation "division: reciprocal constant off by one" src/compiler/native/aarch64/fold.iyi '  multiplier = quotient &+ 1_u64 # division-magic' '  multiplier = quotient &+ 2_u64 # division-magic' division
  prove_fold_mutation "multiply-subtract: exchange the addend" src/compiler/native/aarch64/isel.iyi '    m.uses << vop(addend) # fused-mul-addend' '    m.uses << vop(a)
    a = addend # fused-mul-addend' mulacc
  prove_fold_mutation "select: exchange conditional arms" src/compiler/native/aarch64/isel.iyi '        regs << csel_cond(tv[k], fv[k], cond) # select-arms' '        regs << csel_cond(fv[k], tv[k], cond) # select-arms' select
  prove_fold_mutation "pair: accept the wrong second offset" src/compiler/native/aarch64/isel.iyi '    return false unless high == low + scale # pair-adjacent-offset' '    return false unless high == low + scale * 2_i64 # pair-adjacent-offset' pairs
  prove_fold_mutation "narrow overflow: branch on the wrong flag" src/compiler/native/aarch64/isel.iyi 'cond = cond_vs # narrow-overflow-cond' 'cond = cond_vc # narrow-overflow-cond' narrow
  prove_fold_mutation "narrow wrap: skip the extension of a plain add" src/compiler/native/aarch64/isel.iyi 'if (op == Op::Add || op == Op::Sub || op == Op::Mul) && i.aux_int & 2_i64 != 0_i64 && t.int? && (t.bits == 8 || t.bits == 16 || t.bits == 32) # nsw-skip-canon' 'if (op == Op::Add || op == Op::Sub || op == Op::Mul) # nsw-skip-canon' narrow
  prove_fold_mutation "leaf: discard a required slot frame" src/compiler/native/frame.iyi '  return false unless f.slots.empty? # frameless-no-slots' '  return false unless true # frameless-no-slots' leaf
else
  host_limited "runtime selector mutation proofs (macOS arm64)"
fi
[ ! -e "$NATIVE_SIGNATURE_FAILURE_FILE" ] || fail "a native executable failed signature verification"
echo
if [ "$failed" -eq 0 ]; then
  echo "ALL NATIVE ISEL FOLD CHECKS PASSED!"
  exit 0
fi
echo "SOME NATIVE ISEL FOLD CHECKS FAILED"
exit 1
