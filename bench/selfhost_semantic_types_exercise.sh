#!/usr/bin/env bash
# Fails when the iyi type model stops agreeing with the hosted type model.
#
# Each fixture (bench/fixtures/semty_*.iyi) declares types and lists operations
# as `# op <receiver>.<member>` lines. The hosted oracle
# (bench/selfhost_semantic_types_oracle.cr) and the port's driver
# (bench/selfhost_semantic_types_exercise.iyi) each print one line per
# operation, `<op> => <result>`, and the two outputs must be byte-identical.
#
# Mutation proofs patch the ported code, rebuild the driver, and require the
# gate to fail. A patch that changes nothing is refused by prove_mutation.
#
#   bash bench/selfhost_semantic_types_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
TYPES_FILE="$REPO/src/compiler/types/types.iyi"
MERGE_FILE="$REPO/src/compiler/types/merge.iyi"
INTERSECT_FILE="$REPO/src/compiler/types/intersect.iyi"
FILTERS_FILE="$REPO/src/compiler/types/filters.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

. "$REPO/bench/lib/mutation.sh"

echo "== 1. Building the hosted oracle and the port driver"
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/oracle" "$REPO/bench/selfhost_semantic_types_oracle.cr" || { echo "oracle build failed"; exit 1; }
"$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_semantic_types_exercise.iyi" || { echo "port driver build failed"; exit 1; }

echo
echo "== 2. Each fixture's operations, hosted oracle against the port"
compare_all() {
  local port_bin="$1"
  local fixture
  local out_status=0
  for fixture in "$REPO"/bench/fixtures/semty_*.iyi; do
    "$port_bin" "$fixture" > "$WORK/port.out" 2>/dev/null || { out_status=1; continue; }
    "$WORK/oracle" "$fixture" > "$WORK/oracle.out" 2>/dev/null || { out_status=1; continue; }
    diff -q "$WORK/port.out" "$WORK/oracle.out" >/dev/null || out_status=1
  done
  return $out_status
}

fixture_count=0
total_ops=0
diverged=0
for fixture in "$REPO"/bench/fixtures/semty_*.iyi; do
  fixture_name="bench/fixtures/$(basename "$fixture")"
  "$WORK/port" "$fixture" > "$WORK/port.out" 2>"$WORK/port.err" || {
    echo "  $fixture_name: port driver failed: $(head -n 1 "$WORK/port.err")"
    status=1
    continue
  }
  "$WORK/oracle" "$fixture" > "$WORK/oracle.out" 2>"$WORK/oracle.err" || {
    echo "  $fixture_name: hosted oracle failed: $(head -n 1 "$WORK/oracle.err")"
    status=1
    continue
  }
  if diff -u "$WORK/oracle.out" "$WORK/port.out" > "$WORK/diff.out"; then
    ops=$(awk 'END { print NR }' "$WORK/oracle.out")
    echo "  $fixture_name: identical ($ops operations)"
    fixture_count=$((fixture_count + 1))
    total_ops=$((total_ops + ops))
  else
    echo "  $fixture_name: DIVERGED from the hosted oracle"
    cat "$WORK/diff.out"
    diverged=$((diverged + 1))
    status=1
  fi
done
echo "  Parity summary: $fixture_count fixtures identical ($total_ops operations compared)"
if [ "$fixture_count" -eq 0 ]; then
  echo "  no fixtures compared: this proves nothing"
  status=1
fi

echo
echo "== 3. Guarded mutation proofs (patch, rebuild, the gate must fail)"
MUTATIONS_RUN=0

# A rebuild failure, or any divergence from the hosted oracle, is the catch.
check_type_queries_diverge() {
  "$IYI" build -o "$WORK/mut-port" "$REPO/bench/selfhost_semantic_types_exercise.iyi" >/dev/null 2>&1 || return 1
  compare_all "$WORK/mut-port"
}

prove_mutation "virtual_type leaf rule bypassed" "$TYPES_FILE" \
  "      return type if is_leaf && !is_abstract" \
  "      return type if false && is_leaf && !is_abstract" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "all_subclasses drops every later direct subclass" "$TYPES_FILE" \
  "    subclasses(type).each do |sub|" \
  "    subclasses(type).first(1).each do |sub|" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "reference_like? treats every generic instance as a reference" "$TYPES_FILE" \
  "      return !type.struct?" \
  "      return true" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "splat_index drops the generic class splat position" "$TYPES_FILE" \
  "      return type.as(GenericClassType).splat_index" \
  "      return nil" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "NoReturn elimination bypassed in merge_all" "$MERGE_FILE" \
  "kept << t unless TypeQueries.no_return?(t)" \
  "kept << t" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "base_descendent ignores declared parents" "$INTERSECT_FILE" \
  "    parents_of(t1).each do |parent|" \
  "    ([] of Type).each do |parent|" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "is_a? narrows to the tested value, not the target" "$FILTERS_FILE" \
  "        return TypeIntersect.common_descendent(program, other, target)" \
  "        return other" \
  -- check_type_queries_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL SELFHOST SEMANTIC TYPES CHECKS PASSED =="
else
  echo "== SELFHOST SEMANTIC TYPES CHECKS FAILED =="
fi
exit "$status"
