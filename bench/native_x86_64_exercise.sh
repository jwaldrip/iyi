#!/usr/bin/env bash
# The x86_64 back-end gate (SPEC 2.2 steps 6 and 7, x86_64; Phase D slice D2). Sections, each checked here:
#
#   1. encoder: every form the x86_64 selector produces is encoded by src/compiler/native/amd64/encode.iyi and
#      compared with the LLVM integrated assembler (llvm-mc, LLVM 22, the assembler the Crystal-hosted compiler
#      uses) for the same instruction text: the bytes exactly, and each relocation's kind, offset and addend.
#      The oracle is llvm-mc; llvm-objdump reads its object back at test time only, and the back end never
#      invokes either.
#   6. mutations: each patch to the encoder or the table tool must make the check above fail. A patch whose
#      text is absent, or that leaves the text unchanged, changes nothing and is refused.
#
# Sections are added as the slice lands: the ABI tables, the isel fixtures, the whole-program link on Linux,
# and the inline-assembler templates. Each carries its own mutation proofs here.
#
# Runs on any host: encoding is architecture-independent, so the same bytes are expected on macOS and on Linux.
# Exit 0 with "== ALL X86_64 CHECKS PASSED", or 1 with "== SOME X86_64 CHECKS FAILED".

set -u
cd "$(dirname "$0")/.." || exit 1
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
LLVM_MC=${LLVM_MC:-llvm-mc}
LLVM_OBJDUMP=${LLVM_OBJDUMP:-llvm-objdump}

work=$(mktemp -d "${TMPDIR:-/tmp}/native-x86_64.XXXXXX")
restore=""
trap '[ -n "$restore" ] && [ -f "$restore.bak" ] && cp "$restore.bak" "$restore"; rm -rf "$work"' EXIT INT TERM

failed=0
fail() {
  echo "FAIL: $*"
  failed=1
}

# The pinned mapping from our relocation kinds to the ELF relocation LLVM emits for the same operand. A movq from
# the GOT is the relaxable GOTPCRELX form, the one the object model's X86GotPcRel stands for.
cat >"$work/check_forms.py" <<'PY'
import re
import sys

work = sys.argv[1]
ELF_NAME = {
    "PcRel32": "R_X86_64_PC32",
    "X86Branch32": "R_X86_64_PLT32",
    "X86GotPcRel": "R_X86_64_REX_GOTPCRELX",
    "X86TpOff32": "R_X86_64_TPOFF32",
    "Abs64": "R_X86_64_64",
}

rows = []
for line in open(f"{work}/forms.tsv", encoding="utf-8"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 2:
        continue
    text, hexbytes = parts[0], parts[1]
    relocs = []
    if len(parts) > 2 and parts[2]:
        for item in parts[2].split(","):
            off, kind, addend = item.split(":")
            relocs.append((int(off), ELF_NAME[kind], int(addend)))
    rows.append((text, hexbytes, relocs))

with open(f"{work}/forms.s", "w", encoding="utf-8") as f:
    f.write("\t.text\n")
    for text, _, _ in rows:
        f.write(text + "\n")

if not rows:
    print("no forms were produced")
    sys.exit(1)

if len(sys.argv) > 2 and sys.argv[2] == "prepare":
    sys.exit(0)

instr = []   # (offset, hex bytes)
pending = None
relocs = []  # (offset, elf name, addend, symbol text)
ins_re = re.compile(r"^\s+([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*\t")
rel_re = re.compile(r"^\s*([0-9a-f]+):\s+(R_X86_64_\w+)\s+(\S+)\s*$")
for line in open(f"{work}/dis.txt", encoding="utf-8"):
    m = ins_re.match(line)
    if m:
        off = int(m.group(1), 16)
        bts = m.group(2).replace(" ", "")
        if pending is not None:
            # objdump prints a lock prefix as its own instruction: it belongs to the one after it.
            off, bts = pending[0], pending[1] + bts
            pending = None
        if line[m.end():].split() == ["lock"]:
            pending = (off, bts)
            continue
        instr.append((off, bts))
        continue
    m = rel_re.match(line)
    if m:
        expr = m.group(3)
        em = re.fullmatch(r"sym([+-]0x[0-9a-f]+)?", expr)
        if not em:
            print(f"unexpected relocation expression: {expr}")
            sys.exit(1)
        addend = int(em.group(1), 16) if em.group(1) else 0
        relocs.append((int(m.group(1), 16), m.group(2), addend, expr))

if len(instr) != len(rows):
    print(f"the oracle assembled {len(instr)} instructions for {len(rows)} forms: the forms are not one instruction each")
    sys.exit(1)

bad = 0
bytes_ok = 0
relocs_ok = 0
reloc_count = 0
for k, (text, hexbytes, ours) in enumerate(rows):
    start = instr[k][0]
    end = instr[k + 1][0] if k + 1 < len(instr) else None
    oracle_bytes = instr[k][1]
    if hexbytes == oracle_bytes:
        bytes_ok += 1
    else:
        bad += 1
        print(f"MISMATCH bytes {text}: encoder {hexbytes} oracle {oracle_bytes}")
        continue
    theirs = sorted(
        (off - start, name, addend)
        for off, name, addend, expr in relocs
        if off >= start and (end is None or off < end)
    )
    for _, _, _, expr in [r for r in relocs if r[0] >= start and (end is None or r[0] < end)]:
        if expr.split("sym")[0] != "" or not expr.startswith("sym"):
            print(f"MISMATCH symbol {text}: {expr}")
            bad += 1
    mine = sorted(ours)
    reloc_count += len(mine)
    if mine == theirs:
        relocs_ok += 1
    else:
        bad += 1
        print(f"MISMATCH relocations {text}: encoder {mine} oracle {theirs}")

print(f"compared {len(rows)} forms against the LLVM assembler: {bytes_ok} byte-identical, "
      f"{relocs_ok} with identical relocations ({reloc_count} relocations)")
sys.exit(1 if bad else 0)
PY

echo "== 0. build the x86_64 table tool"
if ! ./bin/iyi build -o "$work/native_amd64" src/compiler/tools/native_amd64.iyi >"$work/build.log" 2>&1; then
  awk '!/ld: warning/' "$work/build.log" | tail -n 20
  fail "the table tool does not build"
  echo "== SOME X86_64 CHECKS FAILED"
  exit 1
fi

check_encoder() {
  "$work/native_amd64" forms >"$work/forms.tsv" 2>"$work/forms.err" || return 1
  python3 "$work/check_forms.py" "$work" prepare >"$work/check.log" 2>&1 || return 1
  "$LLVM_MC" -triple=x86_64-linux-gnu -filetype=obj -o "$work/oracle.o" "$work/forms.s" >"$work/mc.log" 2>&1 || return 1
  "$LLVM_OBJDUMP" -dr "$work/oracle.o" >"$work/dis.txt" 2>&1 || return 1
  python3 "$work/check_forms.py" "$work" >"$work/check.log" 2>&1
}

echo "== 1. encoder: every form against the LLVM assembler"
if ! command -v "$LLVM_MC" >/dev/null 2>&1; then
  fail "llvm-mc is not on PATH: the oracle cannot run"
elif check_encoder; then
  cat "$work/check.log"
else
  cat "$work/check.log" 2>/dev/null
  cat "$work/forms.err" 2>/dev/null
  fail "the encoder does not match the LLVM assembler"
fi

# prove_mutation LABEL FILE OLD NEW: replaces the first OLD in FILE with NEW, rebuilds the table tool from the
# patched source, runs the encoder check, and requires it to fail. A patch whose OLD is absent, or whose NEW
# leaves the text unchanged, changes nothing and is refused.
prove_mutation() {
  label=$1
  file=$2
  old=$3
  new=$4
  cp "$file" "$file.bak" || return 1
  restore="$file"
  python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text or old == new:
  sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
  patched=$?
  if [ "$patched" -ne 0 ]; then
    cp "$file.bak" "$file"
    rm -f "$file.bak"
    restore=""
    if [ "$patched" -eq 3 ]; then
      fail "PATCH CHANGED NOTHING: '$label' found no text to change"
    else
      fail "could not apply '$label'"
    fi
    return 1
  fi
  if ./bin/iyi build -o "$work/mutant_amd64" src/compiler/tools/native_amd64.iyi >"$work/mutant.log" 2>&1; then
    cp "$work/mutant_amd64" "$work/native_amd64"
    if check_encoder; then
      fail "NOT caught: $label"
    else
      echo "   caught: $label"
    fi
  else
    fail "the mutant does not build, so it proves nothing: $label"
  fi
  cp "$file.bak" "$file"
  rm -f "$file.bak"
  restore=""
  ./bin/iyi build -o "$work/native_amd64" src/compiler/tools/native_amd64.iyi >"$work/build.log" 2>&1 || fail "the original tool does not rebuild after '$label'"
  return 0
}

echo "== 6. mutations are each caught"
prove_mutation "cvtt: cvttsd2si given the cvtsd2si opcode (2D, not 2C)" src/compiler/native/amd64/encode.iyi \
  "sse(double ? 0xF2 : 0xF3, 0x2C, size == 64, reg, rm)" \
  "sse(double ? 0xF2 : 0xF3, 0x2D, size == 64, reg, rm)"
prove_mutation "rex.b: the base register's extension bit is dropped from memory operands" src/compiler/native/amd64/encode.iyi \
  "rex_b = !m.rip && m.base >= 0 && hw(m.base) >= 8" \
  "rex_b = false"
prove_mutation "rip-relative addend: the four-byte pc correction is dropped" src/compiler/native/amd64/encode.iyi \
  "w.reloc(kind, sym, value - 4_i64 - after)" \
  "w.reloc(kind, sym, value - after)"

if [ "$failed" -eq 0 ]; then
  echo "== ALL X86_64 CHECKS PASSED"
  exit 0
fi
echo "== SOME X86_64 CHECKS FAILED"
exit 1
