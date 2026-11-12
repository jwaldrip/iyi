#!/usr/bin/env bash
# Body-typing fixtures (bench/fixtures/sem_bodies_*.iyi), S1d: each fixture is analysed
# by the hosted compiler's oracle (bench/selfhost_typed_oracle.cr, built here) and by the
# port's typed dump (src/compiler/tools/typed_dump.iyi, built here). A fixture's matched
# count is the number of oracle lines the port prints identically. Its floor
# (bench/selfhost_bodies.floor) may only rise.
#
#   bash bench/selfhost_bodies_exercise.sh
#
# Environment:
#   BODIES_RAISE=1   write each floor up to the measured count (never lower)
#
# Exit status 0 when every fixture reaches its floor, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
FLOOR_FILE="$REPO/bench/selfhost_bodies.floor"
RAISE="${BODIES_RAISE:-0}"
WORK="$(mktemp -d)"
LC_ALL=C
export LC_ALL
export IYI_CACHE_DIR="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT INT TERM
ORACLE="$WORK/oracle"
TYPED="$WORK/typed_dump"
RESULTS="$WORK/results.tsv"
status=0
: > "$RESULTS"

echo "== 1. Building the hosted compiler's oracle and the port's typed dump"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$ORACLE" "$REPO/bench/selfhost_typed_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; echo "FAILED to build the oracle"; exit 1; }
"$IYI" build -o "$TYPED" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/typed_build.log" 2>&1 \
  || { cat "$WORK/typed_build.log"; echo "FAILED to build src/compiler/tools/typed_dump.iyi"; exit 1; }
echo "  built"

echo
echo "== 2. Each body fixture: the port's typed nodes against the oracle's"
for fixture in "$REPO"/bench/fixtures/sem_bodies_*.iyi; do
  rel="bench/fixtures/$(basename "$fixture")"
  if ! "$ORACLE" "$fixture" > "$WORK/o.txt" 2> "$WORK/o.err"; then
    printf '%s\t%s\t%s\n' "$rel" 0 "ORACLE: $(head -n 1 "$WORK/o.err")" >> "$RESULTS"
    continue
  fi
  sort "$WORK/o.txt" > "$WORK/o.sorted"
  nodes=$(wc -l < "$WORK/o.sorted" | tr -d ' ')
  if "$TYPED" "$fixture" "$REPO/src" > "$WORK/p.txt" 2> "$WORK/p.err"; then
    sort "$WORK/p.txt" > "$WORK/p.sorted"
    matched=$(comm -12 "$WORK/o.sorted" "$WORK/p.sorted" | wc -l | tr -d ' ')
  else
    matched=0
  fi
  printf '%s\t%s\t%s\n' "$rel" "$matched" "of $nodes oracle nodes" >> "$RESULTS"
done
awk -F'\t' '{ printf "  %-42s matched %4s  %s\n", $1, $2, $3 }' "$RESULTS"

echo
echo "== 3. Checking each fixture against its floor"
: > "$WORK/floor.new"
while IFS=$'\t' read -r rel matched note; do
  floor=$(awk -v r="$rel" '$1 == r { print $2 }' "$FLOOR_FILE" 2>/dev/null)
  floor=${floor:-0}
  if [ "$matched" -lt "$floor" ]; then
    echo "  BELOW FLOOR: $rel matched $matched, floor $floor. A regression: restore the typing or lower nothing."
    status=1
    keep=$floor
  elif [ "$matched" -gt "$floor" ]; then
    if [ "$RAISE" = 1 ]; then
      echo "  raised: $rel $floor to $matched"
      keep=$matched
    else
      echo "  RAISE THE FLOOR: $rel matched $matched, floor $floor (BODIES_RAISE=1)."
      status=1
      keep=$floor
    fi
  else
    keep=$floor
  fi
  case "$note" in ORACLE*)
    echo "  ORACLE: $rel: $note"
    status=1
    ;;
  esac
  printf '%s %s\n' "$rel" "$keep" >> "$WORK/floor.new"
done < "$RESULTS"

if [ "$RAISE" = 1 ]; then
  {
    echo "# body-typing fixture floors: <repo-relative fixture> <matched oracle nodes>."
    echo "# A count may only rise. Raise with: BODIES_RAISE=1 bash bench/selfhost_bodies_exercise.sh"
    sort "$WORK/floor.new"
  } > "$FLOOR_FILE"
fi

echo
echo "== 4. Mutation proofs: a patch to the port's body typing must drop a fixture below its floor"
. "$REPO/bench/lib/mutation.sh"
MUT_TD="$WORK/mut_typed_dump"
# Rebuilds the typed dump from the patched source and checks the lib-call and jump fixtures
# still reach their floors. Returns non-zero when a fixture falls below its floor.
bodies_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  for name in sem_bodies_jumps sem_bodies_libcall sem_bodies_self_return; do
    fixture="$REPO/bench/fixtures/$name.iyi"
    rel="bench/fixtures/$name.iyi"
    "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
    "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
    matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
    floor=$(awk -v r="$rel" '$1 == r { print $2 }' "$FLOOR_FILE" 2>/dev/null)
    [ "$matched" -ge "${floor:-0}" ] || return 1
  done
  return 0
}
MAIN_VISITOR="$REPO/src/compiler/semantic/main_visitor.iyi"
prove_mutation "lib call result type" "$MAIN_VISITOR" \
  "set_type(node, target.result_type.as(Type))" \
  "set_type(node, @program.nil_type)" -- bodies_at_floor || status=1
prove_mutation "next value joins the block type" "$MAIN_VISITOR" \
  "blk_type = merge_jump_values(child_type(blk.body), @next_types)" \
  "blk_type = child_type(blk.body)" -- bodies_at_floor || status=1
prove_mutation "return value joins the def type" "$MAIN_VISITOR" \
  "body_type = merge_jump_values(child_type(body.as(ASTNode)), @return_types)" \
  "body_type = child_type(body.as(ASTNode))" -- bodies_at_floor || status=1
prove_mutation "self in a declared type names the receiver" "$MAIN_VISITOR" \
  "return o.as(Type) unless o.is_a?(SemanticProgram)" \
  "return @program.lookup_type_node(node, @current_type) unless o.is_a?(SemanticProgram)" -- bodies_at_floor || status=1

if [ "$status" -eq 0 ]; then
  echo
  echo "== ALL BODY FIXTURES AT THEIR FLOORS"
else
  echo
  echo "== SOME BODY FIXTURE CHECKS FAILED"
fi
exit "$status"
