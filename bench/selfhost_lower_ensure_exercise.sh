#!/usr/bin/env bash
# Compare normal-path handler lowering with the hosted module after its unwind
# edges have been removed, then compare the executable's output and status.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"
. "$REPO/bench/lib/lower_oracle.sh"
status=0

# The empty-prelude ABI supplies a private main entry. The generated wrapper
# uses that ABI, while the checked-in prelude declares only the runtime stubs.
mkdir -p "$WORK/prelude"
awk '{print} END {
  print "lib LibEntry"
  print "  fun entry = __cry" "stal_main(argc : Int32, argv : UInt8**) : Void*"
  print "end"
  print "fun main(argc : Int32, argv : UInt8**) : Int32"
  print "  LibEntry.entry(argc, argv)"
  print "  0"
  print "end"
}' "$REPO/bench/fixtures/lowens_prelude/prelude.iyi" > "$WORK/prelude/prelude.iyi"

build_port() {
  "$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_lower_calls_exercise.iyi" > "$WORK/port.log" 2>&1
}

# Fixture functions reference no globals. Extract the complete function including
# its signature, blocks and closing brace from both printed modules identically.
extract_work() {
  awk '/^define / && index($0, "*work") { active = 1 } active { print } active && /^}$/ { found = 1; exit } END { if (!found) exit 1 }' "$1" > "$2"
}

check_fixture() {
  local name="$1" expected_code actual_code
  "$WORK/port" emit "$REPO/bench/fixtures/lowens_${name}.iyi" "$WORK/${name}.ll" > "$WORK/${name}.port.ir" 2> "$WORK/${name}.port.err" || return 1
  extract_work "$WORK/${name}.host.ir" "$WORK/${name}.host.work" || return 1
  extract_work "$WORK/${name}.port.ir" "$WORK/${name}.port.work" || return 1
  if ! cmp -s "$WORK/${name}.host.work" "$WORK/${name}.port.work"; then
    diff -u "$WORK/${name}.host.work" "$WORK/${name}.port.work" || true
    return 1
  fi
  "$WORK/native" "$WORK/${name}.port.ir" -o "$WORK/${name}.native" > "$WORK/${name}.native.log" 2>&1 || return 1
  "$WORK/${name}.host" > "$WORK/${name}.host.out" 2>&1
  expected_code=$?
  "$WORK/${name}.native" > "$WORK/${name}.native.out" 2>&1
  actual_code=$?
  [ "$expected_code" -eq "$actual_code" ] && cmp -s "$WORK/${name}.host.out" "$WORK/${name}.native.out"
}

mutation_check() {
  build_port && check_fixture "$1"
}

echo '== 1. Building comparison and native tools'
if ! build_port || ! "$IYI" build -o "$WORK/bridge" "$REPO/src/compiler/tools/ir.iyi" > "$WORK/bridge.log" 2>&1 || ! "$IYI" build -o "$WORK/native" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/native.log" 2>&1; then
  echo '  FAIL: tool build failed'
  for log in "$WORK/port.log" "$WORK/bridge.log" "$WORK/native.log"; do
    [ ! -f "$log" ] || awk 'NR <= 12 { print }' "$log"
  done
  exit 1
fi

echo '== 2. Hosted and port function bodies and native executions'
passed=0
for name in fallthrough return break next nested invoke; do
  if ! IYI_PATH="$WORK/prelude" "$IYI" build --prelude prelude --emit llvm-ir --no-debug -o "$WORK/${name}.host" "$REPO/bench/fixtures/lowens_${name}.iyi" > "$WORK/${name}.host.log" 2>&1; then
    echo "  FAIL: $name hosted compilation"
    awk 'NR <= 8 { print }' "$WORK/${name}.host.log"
    status=1
    continue
  fi
  if ! "$WORK/bridge" drop-unwind "$WORK/${name}.host.ll" > "$WORK/${name}.host.ir" 2> "$WORK/${name}.bridge.log"; then
    echo "  FAIL: $name unwind legalization"
    awk 'NR <= 8 { print }' "$WORK/${name}.bridge.log"
    status=1
    continue
  fi
  cp "$WORK/${name}.host.ll" "$WORK/${name}.ll"
  if check_fixture "$name"; then
    echo "  $name: identical and native output/status match"
    passed=$((passed + 1))
  else
    echo "  FAIL: $name differs or cannot run"
    for log in "$WORK/${name}.port.err" "$WORK/${name}.native.log"; do
      [ ! -f "$log" ] || awk 'NR <= 5 { print }' "$log"
    done
    status=1
  fi
done

echo '== 3. Mutation proofs'
if [ "$passed" -eq 6 ]; then
  file="$REPO/src/compiler/lower/ensure.iyi"
  prove_mutation 'fallthrough cleanup' "$file" 'visit_node(low, cleanup.as(ASTNode))' 'low.last = value' -- mutation_check fallthrough || status=1
  prove_mutation 'return cleanup' "$file" 'while low.ensure_nodes.size > stop' 'while low.ensure_nodes.size > low.ensure_nodes.size' -- mutation_check return || status=1
  prove_mutation 'break cleanup' "$file" 'while low.ensure_nodes.size > stop' 'while low.ensure_nodes.size > low.ensure_nodes.size' -- mutation_check break || status=1
  prove_mutation 'next cleanup' "$file" 'while low.ensure_nodes.size > stop' 'while low.ensure_nodes.size > low.ensure_nodes.size' -- mutation_check next || status=1
  prove_mutation 'nested cleanup order' "$file" 'visit_node(low, node.body)' 'visit_node(low, cleanup.as(ASTNode)); visit_node(low, node.body)' -- mutation_check nested || status=1
else
  echo '  NOT RUN: baseline fixtures did not all pass'
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo '== ALL LOWER ENSURE CHECKS PASSED'
else
  echo '== SOME LOWER ENSURE CHECKS FAILED'
fi
exit "$status"
