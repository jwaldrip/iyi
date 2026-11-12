#!/usr/bin/env bash
# Fails when the iyi lowering of analysed types stops agreeing with the hosted typer.
#
# Each fixture (bench/fixtures/lowty_*.iyi) declares types and lists each one to
# lower as a `# type: <expr>` line. The hosted oracle
# (bench/selfhost_lower_types_oracle.cr) and the port's driver
# (bench/selfhost_lower_types_exercise.iyi) each print one block per type: its
# LLVM type, its wants_size type, its struct and offsets where it has one, its
# embedded type, size, alignment and by-value flag. The two outputs must be
# byte-identical for the same target triple.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the gate
# to fail. A patch that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_lower_types_exercise.sh
#   LOWER_TYPES_TARGET=x86_64-unknown-linux-gnu bash bench/selfhost_lower_types_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
TYPER_FILE="$REPO/src/compiler/lower/typer.iyi"
UNIONS_FILE="$REPO/src/compiler/lower/unions.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

. "$REPO/bench/lib/mutation.sh"

# The host triple both printers are given, so the layouts agree. The gate runs on
# the darwin arm64 and linux x86_64 runners; another host is named explicitly.
if [ -n "${LOWER_TYPES_TARGET:-}" ]; then
  TRIPLE="$LOWER_TYPES_TARGET"
else
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  TRIPLE="aarch64-apple-darwin" ;;
    Linux-x86_64)  TRIPLE="x86_64-unknown-linux-gnu" ;;
    Linux-aarch64) TRIPLE="aarch64-unknown-linux-gnu" ;;
    *) echo "no lowering target for $(uname -s)-$(uname -m); set LOWER_TYPES_TARGET"; exit 1 ;;
  esac
fi

echo "== 1. Building the hosted oracle and the port driver ($TRIPLE)"
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/oracle" "$REPO/bench/selfhost_lower_types_oracle.cr" >/dev/null 2>&1 || { echo "oracle build failed"; exit 1; }
"$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_types_exercise.iyi" || { echo "port driver build failed"; exit 1; }

echo
echo "== 2. Each fixture's blocks, hosted oracle against the port"
fixture_count=0
block_count=0
diverged=0
for fixture in "$REPO"/bench/fixtures/lowty_*.iyi; do
  name="$(basename "$fixture" .iyi)"
  if ! "$WORK/oracle" "$fixture" "$TRIPLE" > "$WORK/$name.oracle" 2> "$WORK/$name.oracle.err"; then
    echo "  $name: oracle failed: $(cat "$WORK/$name.oracle.err")"
    diverged=$((diverged + 1))
    continue
  fi
  if ! "$WORK/port" "$fixture" "$TRIPLE" > "$WORK/$name.port" 2> "$WORK/$name.port.err"; then
    echo "  $name: port driver failed: $(head -n 2 "$WORK/$name.port.err")"
    diverged=$((diverged + 1))
    continue
  fi
  if cmp -s "$WORK/$name.oracle" "$WORK/$name.port"; then
    fixture_count=$((fixture_count + 1))
    n=$(awk '/^== /{ n++ } END { print n + 0 }' "$WORK/$name.oracle")
    block_count=$((block_count + n))
  else
    echo "  $name: DIVERGES from the hosted oracle:"
    diff "$WORK/$name.oracle" "$WORK/$name.port" | head -n 20
    diverged=$((diverged + 1))
  fi
done
echo "  Parity summary: $fixture_count fixtures identical ($block_count types compared), $diverged diverged"
if [ "$fixture_count" -eq 0 ]; then
  echo "  no fixture was compared"
  status=1
fi
if [ "$diverged" -ne 0 ]; then
  status=1
fi

echo
echo "== 3. Guarded mutation proofs (patch, rebuild, the gate must fail)"
MUTATIONS_RUN=0

# A check fails (non-zero) when the mutated driver is detected: it does not build,
# it fails on a fixture, or any fixture's blocks differ from the hosted oracle's.
# It returns 0 only when every fixture still matches, which is the unmutated behaviour.
check_lowering_diverges() {
  "$IYI" build -o "$WORK/mut_port" "$REPO/bench/selfhost_lower_types_exercise.iyi" >/dev/null 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/lowty_*.iyi; do
    name="$(basename "$fixture" .iyi)"
    "$WORK/mut_port" "$fixture" "$TRIPLE" > "$WORK/mut.out" 2>/dev/null || return 1
    cmp -s "$WORK/$name.oracle" "$WORK/mut.out" || return 1
  done
  return 0
}

prove_mutation "Bool lowered to i8, not i1" "$TYPER_FILE" \
  "      return @table.int1" \
  "      return @table.int8" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "Char lowered to i16, not i32" "$TYPER_FILE" \
  "      return @table.int32" \
  "      return @table.int16" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "Float32 lowered to double" "$TYPER_FILE" \
  "      return primitive_bytes(type) == 4 ? @table.float(32) : @table.float(64)" \
  "      return @table.float(64)" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "enum lowered to Int64 whatever its base" "$TYPER_FILE" \
  "      return llvm_type(type.as(EnumType).base_type)" \
  "      return @table.int64" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "metaclass branch bypassed (metaclasses fall through to the raise)" "$TYPER_FILE" \
  "    if type.is_a?(MetaclassType) || type.is_a?(VirtualMetaclassType)" \
  "    if false" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "void alignment reported as 2 bytes" "$TYPER_FILE" \
  "    return 1 if t.void?" \
  "    return 2 if t.void?" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "Nil lowered to an i8 instead of the named empty struct" "$TYPER_FILE" \
  "      return nil_type" \
  "      return @table.int8" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "mixed union drops its type id word" "$UNIONS_FILE" \
  "  [table.int32, value_type]" \
  "  [value_type]" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "mixed union value area ignores its largest member" "$TYPER_FILE" \
  "      max_size = size if size > max_size" \
  "      max_size = max_size if size > max_size" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "mixed union aligned to 4 bytes, not the largest member" "$TYPER_FILE" \
  "    max_alignment = pointer_size.to_i32" \
  "    max_alignment = 4" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "mixed unions not passed by value" "$TYPER_FILE" \
  "|| type.is_a?(MixedUnionType)" \
  "|| false" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "indirect threshold above a 136-byte value" "$TYPER_FILE" \
  "    size_of(llvm_type(type)) > 128" \
  "    size_of(llvm_type(type)) > 136" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "closure context pointer not prepended" "$TYPER_FILE" \
  "    params << @table.ptr if closure" \
  "    params << @table.ptr if false" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "indirect result returned as int32, not void" "$TYPER_FILE" \
  "      return @table.func(params, @table.void)" \
  "      return @table.func(params, @table.int32)" \
  -- check_lowering_diverges || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "PASS: the iyi lowering of analysed types agrees with the hosted typer on every fixture, and every mutation is caught"
else
  echo "FAIL: the iyi lowering of analysed types diverges from the hosted typer, or a mutation was not caught"
fi
exit "$status"
