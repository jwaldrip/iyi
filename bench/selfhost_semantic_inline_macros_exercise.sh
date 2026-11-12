#!/usr/bin/env bash
# Burn-down gate for inline macro expansion in the declarations pass (specification
# S1b-M). The pass expands each `{% if %}`, `{% for %}` and `{{ }}` site at the top
# level and in type bodies with the macro engine, parses the output in the site's
# file and declares what it makes.
#
# Every file is analysed bare (no prelude), with the closure of what it imports and
# requires, by the hosted front end's top-level pass (the oracle,
# bench/selfhost_semantic_inline_macros_oracle.cr, which keeps what a macro declares) and by the iyi port
# (bench/selfhost_semantic_inline_macros_exercise.iyi). Both print one text dump of
# the declarations the file makes, and a record agrees when both sides print it
# identically. The gate counts agreeing records per file.
#
# It also accounts for the file's own macro sites: the sites the scan finds at the
# top level and in type bodies (def bodies belong to the bodies slice), and how the
# pass went with each one the port visited. A site is expanded, refused by the
# engine (with its reason), or not reached. A refusal is printed, never dropped.
#
#   bash bench/selfhost_semantic_inline_macros_exercise.sh
#
# Verifies:
#   1. The oracle and the port's driver build.
#   2. Every bench/fixtures/seminl_*.iyi is dumped byte-identical by both sides, and
#      the port's pass refuses none of its sites.
#   3-6. Corpora burn-down: the port's own source (src/compiler), the prelude
#        (src/iyi), std (src/std) and the samples (samples/iyi). Each file's
#        agreeing-record count is checked against the committed floor
#        (bench/selfhost_semantic_inline_macros.floor), which may only rise. A file
#        the oracle cannot analyse is reported ORACLE and is not measured. A file the
#        port rejects counts zero and is reported PORT.
#   7. Guarded mutation proofs on the fixtures (bench/lib/mutation.sh).
#
# Environment:
#   SEMINL_RAISE=1         write the floor up to the measured counts (never lower)
#   SEMINL_FILES=<f>       measure only the repo-relative paths listed in <f>
#   SEMINL_FLOOR=<f>       read and write this floor file instead of the default
#
# Exit status 0 when every check passes, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
export PWD="$REPO"
IYI="$REPO/bin/iyi"
CRYSTAL="$REPO/bin/crystal"
FLOOR_FILE="${SEMINL_FLOOR:-$REPO/bench/selfhost_semantic_inline_macros.floor}"
RAISE="${SEMINL_RAISE:-0}"
FILES_LIST="${SEMINL_FILES:-}"
WORK="$(mktemp -d)"
LC_ALL=C
export LC_ALL
export IYI_CACHE_DIR="$WORK/cache"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export LIBRARY_PATH="/opt/homebrew/opt/bdw-gc/lib:${LIBRARY_PATH:-}"
export IYI_PATH="$REPO/src"
trap 'rm -rf "$WORK"' EXIT INT TERM

ORACLE="$WORK/oracle"
PORT="$WORK/port"
RESULTS="$WORK/results.tsv"
REFUSALS="$WORK/refusals.tsv"
VERDICTS="$WORK/verdicts.tsv"
status=0
: > "$RESULTS"
: > "$REFUSALS"

. "$REPO/bench/lib/mutation.sh"

# Splits a dump into records, one per "Type:" or "Def:" header line, each with its
# own property lines, joined onto one line with the record separator \036.
records() {
  awk '
    function flush() { if (cur != "") print cur }
    /^ *(Type|Def): / { flush(); cur = $0; next }
    { if (cur != "") cur = cur "\036" $0 }
    END { flush() }
  ' "$1"
}

# Number of records of FILE that also occur in REFERENCE, counted with multiplicity.
agreeing() {
  records "$1" | sort > "$WORK/agree_a"
  records "$2" | sort > "$WORK/agree_b"
  comm -12 "$WORK/agree_a" "$WORK/agree_b" | wc -l | tr -d ' '
}

echo "== 1. Building the hosted declaration oracle and the port's driver"
CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$ORACLE" "$REPO/bench/selfhost_semantic_inline_macros_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; echo "FAILED to build the oracle"; exit 1; }
"$IYI" build -o "$PORT" "$REPO/bench/selfhost_semantic_inline_macros_exercise.iyi" > "$WORK/port_build.log" 2>&1 \
  || { cat "$WORK/port_build.log"; echo "FAILED to build the port's driver"; exit 1; }
echo "  built: oracle, port driver"

echo
echo "== 2. Fixtures: every declaration dumped identically, and no site refused"
fixture_count=0
fixture_bad=0
total_matched=0
for fixture in "$REPO"/bench/fixtures/seminl_*.iyi; do
  rel="bench/fixtures/$(basename "$fixture")"
  fixture_count=$((fixture_count + 1))
  if ! "$ORACLE" "$REPO/$rel" > "$WORK/fx_o.txt" 2> "$WORK/fx_oe.txt"; then
    echo "  $rel: ORACLE REJECTS: $(head -n 1 "$WORK/fx_oe.txt")"
    fixture_bad=$((fixture_bad + 1)); status=1; continue
  fi
  if ! "$PORT" "$REPO/$rel" > "$WORK/fx_p.txt" 2> "$WORK/fx_pe.txt"; then
    echo "  $rel: PORT REJECTS: $(head -n 1 "$WORK/fx_pe.txt")"
    fixture_bad=$((fixture_bad + 1)); status=1; continue
  fi
  if ! "$PORT" --ledger "$REPO/$rel" > "$WORK/fx_l.txt" 2> "$WORK/fx_le.txt"; then
    echo "  $rel: PORT LEDGER REJECTS: $(head -n 1 "$WORK/fx_le.txt")"
    fixture_bad=$((fixture_bad + 1)); status=1; continue
  fi
  refused=$(awk '$1 == "refused_total" { print $2 }' "$WORK/fx_l.txt")
  if [ "$refused" != "0" ]; then
    echo "  $rel: the port refuses $refused site(s):"
    awk '$1 == "refused" { print "    " $0 }' "$WORK/fx_l.txt"
    fixture_bad=$((fixture_bad + 1)); status=1; continue
  fi
  if cmp -s "$WORK/fx_o.txt" "$WORK/fx_p.txt"; then
    n=$(agreeing "$WORK/fx_o.txt" "$WORK/fx_p.txt")
    total_matched=$((total_matched + n))
    echo "  $rel: identical ($n declarations, $(awk '$1 == "expanded_total" { print $2 }' "$WORK/fx_l.txt") sites expanded)"
  else
    echo "  $rel: DECLARATIONS DIFFER"
    diff "$WORK/fx_o.txt" "$WORK/fx_p.txt" | head -n 20
    fixture_bad=$((fixture_bad + 1)); status=1
  fi
done
echo "  Parity summary: $((fixture_count - fixture_bad))/$fixture_count fixtures identical ($total_matched declarations compared)"

# One file: its declarations against the oracle's, and its macro sites by outcome.
# Writes one row to RESULTS and its refusals to REFUSALS.
measure() {
  corpus="$1"
  rel="$2"
  abs="$REPO/$2"
  sites=0; expanded=0; refused=0; not_reached=0
  if "$PORT" --sites "$abs" > "$WORK/s.txt" 2> "$WORK/s.err"; then
    sites=$(awk '$1 == "site" && ($2 == "top" || $2 == "class") { n++ } END { print n + 0 }' "$WORK/s.txt")
  fi
  if "$PORT" --ledger "$abs" > "$WORK/l.txt" 2> "$WORK/l.err"; then
    expanded=$(awk '$1 == "expanded_total" { print $2 }' "$WORK/l.txt")
    refused=$(awk '$1 == "refused_total" { print $2 }' "$WORK/l.txt")
    awk -v f="$rel" -v c="$corpus" '$1 == "refused" { print c "\t" f "\t" $0 }' "$WORK/l.txt" >> "$REFUSALS"
  fi
  not_reached=$((sites - expanded - refused))
  [ "$not_reached" -lt 0 ] && not_reached=0
  if "$ORACLE" "$abs" > "$WORK/o.txt" 2> "$WORK/o.err"; then
    nodes=$(records "$WORK/o.txt" | wc -l | tr -d ' ')
    if "$PORT" "$abs" > "$WORK/p.txt" 2> "$WORK/p.err"; then
      matched=$(agreeing "$WORK/o.txt" "$WORK/p.txt")
      note="-"
    else
      matched=0
      note="PORT: $(head -n 1 "$WORK/p.err" | tr '\t' ' ')"
    fi
  else
    nodes=0
    matched=0
    note="ORACLE: $(head -n 1 "$WORK/o.err" | tr '\t' ' ')"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$corpus" "$rel" "$nodes" "$matched" \
    "$sites" "$expanded" "$refused" "$not_reached" "$note" >> "$RESULTS"
}

echo
if [ -n "$FILES_LIST" ]; then
  echo "== 3. Measuring the files listed in $FILES_LIST"
  while IFS= read -r rel; do
    case "$rel" in
      ""|"#"*) continue ;;
    esac
    measure subset "$rel"
  done < "$FILES_LIST"
else
  echo "== 3. Measuring the port's source, the prelude, std and the samples"
  find "$REPO/src/compiler" -name '*.iyi' | sort | while IFS= read -r f; do measure compiler "${f#$REPO/}"; done
  for f in "$REPO"/src/iyi/*.iyi; do measure prelude "${f#$REPO/}"; done
  for f in "$REPO"/src/std/*.iyi; do measure std "${f#$REPO/}"; done
  for f in "$REPO"/samples/iyi/*.iyi; do measure samples "${f#$REPO/}"; done
fi
echo "  $(wc -l < "$RESULTS" | tr -d ' ') files measured"

echo
echo "== 4. Checking each file against its committed floor"
verdicts() {
awk -F'\t' -v floorfile="$FLOOR_FILE" '
  BEGIN {
    while ((getline line < floorfile) > 0) {
      if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
      split(line, a, /[ \t]+/)
      floor[a[1]] = a[2] + 0
    }
  }
  {
    corpus = $1; rel = $2; nodes = $3 + 0; matched = $4 + 0; note = $9
    if (note ~ /^ORACLE/) verdict = "ORACLE"
    else if (!(rel in floor)) verdict = "NO FLOOR"
    else if (matched < floor[rel]) verdict = "BELOW FLOOR"
    else if (matched > floor[rel]) verdict = "RAISE THE FLOOR"
    else verdict = "ok"
    fl = (rel in floor) ? floor[rel] : "-"
    printf "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", verdict, corpus, rel, nodes, matched, \
      (nodes > 0 ? sprintf("%.1f%%", 100 * matched / nodes) : "n/a"), fl, note
  }' "$RESULTS" > "$VERDICTS"
}
verdicts

fails=0
if [ "$RAISE" = 1 ]; then
  # Write each measured file's floor up to its count, never down; a file that is
  # not oracle-analysable keeps its old floor.
  awk -F'\t' -v floorfile="$FLOOR_FILE" '
    BEGIN {
      while ((getline line < floorfile) > 0) {
        if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
        split(line, a, /[ \t]+/)
        floor[a[1]] = a[2] + 0
      }
    }
    $9 !~ /^ORACLE/ { if (!($2 in floor) || $4 + 0 > floor[$2]) floor[$2] = $4 + 0 }
    END {
      for (k in floor) print k "\t" floor[k]
    }' "$RESULTS" | sort > "$WORK/floor.new"
  if [ -s "$WORK/floor.new" ]; then
    {
      echo "# Floor for bench/selfhost_semantic_inline_macros_exercise.sh: the agreeing declaration"
      echo "# records each file must keep. Only raise these (SEMINL_RAISE=1); never lower one."
      awk -F'\t' '{ printf "%s %s\n", $1, $2 }' "$WORK/floor.new"
    } > "$FLOOR_FILE"
    echo "  floor written to ${FLOOR_FILE#$REPO/}"
  fi
  verdicts
fi

awk -F'\t' '
  $1 == "BELOW FLOOR"     { printf "  BELOW FLOOR: %s matched %s, floor %s. A regression: restore the declaration or lower nothing.\n", $3, $5, $7; bad++ }
  $1 == "RAISE THE FLOOR" { printf "  RAISE THE FLOOR: %s matched %s, floor %s. Raise the floor (SEMINL_RAISE=1).\n", $3, $5, $7; bad++ }
  $1 == "NO FLOOR"        { printf "  NO FLOOR: %s has no floor entry. Add it (SEMINL_RAISE=1).\n", $3; bad++ }
  END { print bad + 0 }
' "$VERDICTS" > "$WORK/fails.txt"
awk -F'\t' '$1 == "BELOW FLOOR" || $1 == "RAISE THE FLOOR" || $1 == "NO FLOOR" { n++ } END { print n + 0 }' "$VERDICTS" > "$WORK/nfails.txt"
fails=$(cat "$WORK/nfails.txt")
awk '!/^[0-9]+$/' "$WORK/fails.txt"
echo "  $fails file(s) below or missing their floor"
if [ "$fails" -gt 0 ] && [ "$RAISE" != 1 ]; then
  status=1
fi

echo
echo "== 5. Per-file declaration parity and macro site accounting"
printf '  %-14s %-44s %6s %7s %6s %6s %8s %11s  %s\n' corpus file decls agree sites expd refused not_reached note
awk -F'\t' '{ printf "  %-14s %-44s %6s %7s %6s %6s %8s %11s  %s\n", $1, $2, $3, $4, $5, $6, $7, $8, substr($9, 1, 60) }' "$RESULTS" | sort

echo
echo "== 6. Corpus totals"
awk -F'\t' '
  {
    nodes[$1] += $3; matched[$1] += $4; count[$1] += 1
    sites[$1] += $5; expd[$1] += $6; refd[$1] += $7; nr[$1] += $8
    if ($9 ~ /^ORACLE/) oracle[$1] += 1
    if ($9 ~ /^PORT/) port[$1] += 1
  }
  END {
    n = 0
    for (k in nodes) keys[++n] = k
    for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (keys[j] < keys[i]) { t = keys[i]; keys[i] = keys[j]; keys[j] = t }
    for (i = 1; i <= n; i++) {
      k = keys[i]
      printf "  %-10s files %3d  oracle-failed %3d  port-failed %3d  declarations %6d agreeing %6d  sites top/class %4d expanded %4d refused %3d not reached %4d\n", \
        k, count[k], oracle[k] + 0, port[k] + 0, nodes[k], matched[k], sites[k], expd[k], refd[k], nr[k]
    }
  }' "$RESULTS"

echo
echo "== 6b. Refusals by reason (every refused site, with its file)"
if [ -s "$REFUSALS" ]; then
  awk -F'\t' '{
    split($3, parts, " ")
    reason = $3
    sub(/^refused [^ ]+ [0-9]+:[0-9]+ /, "", reason)
    count[reason] += 1
  }
  END { for (r in count) printf "  %4d  %s\n", count[r], r }' "$REFUSALS" | sort -rn
  awk -F'\t' '{ printf "  refused: %s %s\n", $2, $3 }' "$REFUSALS"
else
  echo "  none: the pass expanded every site it visited"
fi

check_inline_fixtures_diverge() {
  # Builds the port's driver as it now stands and compares every fixture. Returns
  # non-zero (caught) when the driver fails to build, or a fixture's dump differs
  # from the oracle's or a site is refused.
  local probe="$WORK/mut_port"
  "$IYI" build -o "$probe" "$REPO/bench/selfhost_semantic_inline_macros_exercise.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/seminl_*.iyi; do
    rel="bench/fixtures/$(basename "$fixture")"
    "$ORACLE" "$REPO/$rel" > "$WORK/mut_o.txt" 2>/dev/null || return 1
    "$probe" "$REPO/$rel" > "$WORK/mut_p.txt" 2>/dev/null || return 1
    cmp -s "$WORK/mut_o.txt" "$WORK/mut_p.txt" || return 1
    "$probe" --ledger "$REPO/$rel" 2>/dev/null | awk '$1 == "refused_total" && $2 != 0 { bad = 1 } END { exit bad }' || return 1
  done
  return 0
}

echo
echo "== 7. Mutation proofs: patches to the port's inline expansion the fixtures must catch"
MUT_INL="$REPO/src/compiler/semantic/inline_macros.iyi"
MUT_SEM="$REPO/src/compiler/semantic/top_level.iyi"
MUTATIONS_RUN=0

prove_mutation "an empty expansion is kept and a non-empty one dropped" "$MUT_INL" \
  "return nil if text.bytesize == 0" \
  "return nil if text.bytesize > 0" \
  -- check_inline_fixtures_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "the expansion is parsed with no file, so its declarations are not the file's" "$MUT_INL" \
  "parsed = Parser.new(text, filename).parse" \
  "parsed = Parser.new(text, \"\").parse" \
  -- check_inline_fixtures_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "the first inline site visited (a type body's or top-level if) is never declared" "$MUT_SEM" \
  "expanded.accept(self)" \
  "expanded.is_a?(ASTNode)" \
  -- check_inline_fixtures_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation_all "no inline macro site (if, for or expression) is ever declared" "$MUT_SEM" \
  "expanded.accept(self)" \
  "expanded.is_a?(ASTNode)" \
  -- check_inline_fixtures_diverge || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "PASS: inline macros gate green"
else
  echo "FAIL: inline macros gate red"
fi
exit "$status"
