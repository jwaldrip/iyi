#!/usr/bin/env bash
# Call census for the iyi call lookup, against the hosted semantic pass, over the
# compiler's own source and the prelude (slice S1c, step 1).
#
# Each file (src/compiler/**/*.iyi and src/iyi/*.iyi) is compiled by the hosted
# pass (bench/selfhost_semantic_calls_census_oracle.cr), which prints every call
# site of the file it reached with the receiver and argument types it typed and
# the hosted lookup result. The port's driver
# (bench/selfhost_semantic_calls_census_exercise.iyi) reads those lines and answers
# each typed site from the receiver and argument types alone. A site is identical
# when the two lookup results are byte-identical. Sites the hosted pass did not
# type (its receiver, an argument, a macro, super or previous_def, a splat, a block
# argument, a scope) are counted apart and are not in the total.
#
# The committed floor (bench/selfhost_semantic_calls.floor) holds each file's
# identical count; a count may only rise. The unresolved shapes the port could not
# answer are ranked at the end, by reason, method name and receiver shape.
#
#   bash bench/selfhost_semantic_calls_census.sh
#
# Environment:
#   CALLS_CENSUS_FILES=<f>  measure only the repo-relative paths listed in <f>
#   CALLS_CENSUS_RAISE=1    write the floor up to the measured counts (never lower)
#   CALLS_CENSUS_FLOOR=<f>  read and write this floor file instead of the default
#   CALLS_CENSUS_TABLE=<f>  also write the per-file table to this file
#
# Exit status 0 when every measured file is at or above its floor, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
FLOOR_FILE="${CALLS_CENSUS_FLOOR:-$REPO/bench/selfhost_semantic_calls.floor}"
FILES_LIST="${CALLS_CENSUS_FILES:-}"
RAISE="${CALLS_CENSUS_RAISE:-0}"
TABLE="${CALLS_CENSUS_TABLE:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
export IYI_PATH="$REPO/src"
LC_ALL=C
export LC_ALL
status=0

fatal() {
  echo "  $1"
  exit 1
}

echo "== 1. Building the hosted census oracle and the port's census driver"
CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$WORK/oracle" "$REPO/bench/selfhost_semantic_calls_census_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; fatal "FAILED to build the hosted census oracle"; }
"$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_semantic_calls_census_exercise.iyi" > "$WORK/port_build.log" 2>&1 \
  || { cat "$WORK/port_build.log"; fatal "FAILED to build the port census driver"; }
echo "  built: oracle, port driver"

if [ -n "$FILES_LIST" ]; then
  FILES="$(cat "$FILES_LIST")"
else
  FILES="$(cd "$REPO" && { find src/compiler -name '*.iyi'; find src/iyi -maxdepth 1 -name '*.iyi'; } | sort)"
fi

RESULTS="$WORK/results.tsv"
SHAPES="$WORK/shapes.txt"
: > "$RESULTS"
: > "$SHAPES"

echo
echo "== 2. Each file's call sites: hosted pass against the port"
measured=0
for rel in $FILES; do
  [ -f "$REPO/$rel" ] || continue
  dir="$(dirname "$rel")"
  # The prelude is required by a relative path from the file's own directory.
  IFS=/ read -r -a parts <<< "$dir"
  up=$(( ${#parts[@]} - 1 ))
  prefix=""
  i=0
  while [ "$i" -lt "$up" ]; do
    prefix="../$prefix"
    i=$((i + 1))
  done
  prelude_req="${prefix}iyi/prelude"
  mode=""
  corpus="compiler"
  case "$rel" in
    src/iyi/*) mode="--prelude-only"; corpus="prelude" ;;
  esac

  if ! "$WORK/oracle" "$REPO/$rel" $mode > "$WORK/dump.txt" 2> "$WORK/oerr.txt"; then
    printf '%s\t%s\t0\t0\t0\tORACLE: %s\n' "$corpus" "$rel" "$(head -n 1 "$WORK/oerr.txt" 2>/dev/null)" >> "$RESULTS"
    continue
  fi
  if ! "$WORK/port" "$REPO/$rel" "$WORK/dump.txt" "$prelude_req" $mode > "$WORK/port.txt" 2> "$WORK/perr.txt"; then
    printf '%s\t%s\t0\t0\t0\tPORT: %s\n' "$corpus" "$rel" "$(head -n 1 "$WORK/perr.txt" 2>/dev/null)" >> "$RESULTS"
    continue
  fi

  awk -F'\t' -v corpus="$corpus" -v rel="$rel" -v shapes="$SHAPES" '
    NR == FNR {
      if ($0 == "") next
      dump[FNR] = $0
      total += 1
      if ($2 == "T") typed += 1
      next
    }
    $0 == "" { next }
    {
      line = dump[FNR]
      split(line, cols, "\t")
      if (cols[2] != "T") next
      result = substr($0, index($0, "\t") + 1)
      if (result == cols[8]) identical += 1
      if (result ~ /^unresolved\|/) print result > shapes
    }
    END {
      printf "%s\t%s\t%d\t%d\t%d\t\n", corpus, rel, total + 0, typed + 0, identical + 0
    }' "$WORK/dump.txt" "$WORK/port.txt" >> "$RESULTS"
  measured=$((measured + 1))
done
echo "  $measured file(s) measured"

echo
echo "== 3. Checking each file against its committed floor"
fails=0
VERDICTS="$WORK/verdicts.tsv"
awk -F'\t' -v floorfile="$FLOOR_FILE" '
  BEGIN {
    while ((getline line < floorfile) > 0) {
      if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
      split(line, a, /[ \t]+/)
      floor[a[1]] = a[2] + 0
    }
  }
  {
    corpus = $1; rel = $2; total = $3 + 0; typed = $4 + 0; identical = $5 + 0; note = $6
    if (note ~ /^(ORACLE|PORT)/) verdict = note ~ /^ORACLE/ ? "ORACLE" : "PORT"
    else if (!(rel in floor)) verdict = "NO FLOOR"
    else if (identical < floor[rel]) verdict = "BELOW FLOOR"
    else if (identical > floor[rel]) verdict = "RAISE THE FLOOR"
    else verdict = "ok"
    fl = (rel in floor) ? floor[rel] : "-"
    printf "%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", verdict, corpus, rel, total, typed, identical, fl, note
  }' "$RESULTS" > "$VERDICTS"

if [ "$RAISE" = 1 ]; then
  {
    echo "# call census floors: <repo-relative file> <identical call sites>."
    echo "# A count may only rise. Raise with: CALLS_CENSUS_RAISE=1 bash bench/selfhost_semantic_calls_census.sh"
    awk -F'\t' -v floorfile="$FLOOR_FILE" '
      BEGIN {
        while ((getline line < floorfile) > 0) {
          if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
          split(line, a, /[ \t]+/)
          floor[a[1]] = a[2] + 0
        }
      }
      {
        rel = $2; identical = $5 + 0
        if ($6 ~ /^(ORACLE|PORT)/) { if (rel in floor) print rel, floor[rel]; next }
        cur = (rel in floor) && floor[rel] > identical ? floor[rel] : identical
        print rel, cur
      }' "$RESULTS" | sort
  } > "$WORK/floor.new"
  cp "$WORK/floor.new" "$FLOOR_FILE"
  echo "  floor written to ${FLOOR_FILE#$REPO/}"
fi

awk -F'\t' '
  $1 == "BELOW FLOOR"     { printf "  BELOW FLOOR: %s identical %s, floor %s. A regression: restore the lookup or lower nothing.\n", $3, $6, $7; bad = 1 }
  $1 == "RAISE THE FLOOR" { printf "  RAISE THE FLOOR: %s identical %s, floor %s. Raise the floor (CALLS_CENSUS_RAISE=1).\n", $3, $6, $7; bad = 1 }
  $1 == "NO FLOOR"        { printf "  NO FLOOR: %s has no floor entry. Add it (CALLS_CENSUS_RAISE=1).\n", $3; bad = 1 }
  END { exit bad ? 1 : 0 }' "$VERDICTS"
if [ $? -ne 0 ] && [ "$RAISE" != 1 ]; then
  status=1
fi
fails=$(awk -F'\t' '$1 == "BELOW FLOOR" || $1 == "NO FLOOR" { n += 1 } END { print n + 0 }' "$VERDICTS")
echo "  $fails file(s) below or missing their floor"

echo
echo "== 4. Per-file call census: sites, typed by the hosted pass, identical"
printf '  %-16s %-46s %7s %7s %9s %8s  %s\n' verdict file total typed identical fraction note
awk -F'\t' '{
  frac = ($4 > 0) ? sprintf("%.1f%%", 100 * $6 / $4) : "n/a"
  printf "  %-16s %-46s %7s %7s %9s %8s  %s\n", $1, $3, $4, $5, $6, frac, $8
}' "$VERDICTS"

echo
echo "== 5. Corpus totals (sites the hosted pass reached, and identical ones)"
awk -F'\t' '
  { total[$2] += $4; typed[$2] += $5; ident[$2] += $6; files[$2] += 1 }
  END {
    for (k in total) {
      printf "  %-10s files %4d  sites %8d  typed by hosted %8d  identical %8d  of typed %6.2f%%\n", \
        k, files[k], total[k], typed[k], ident[k], (typed[k] ? 100 * ident[k] / typed[k] : 0)
    }
  }' "$RESULTS"

echo
echo "== 6. Unresolved shapes, ranked (reason, method, receiver shape)"
if [ -s "$SHAPES" ]; then
  sort "$SHAPES" | uniq -c | sort -rn | awk 'NR <= 25 { printf "  %6d  %s\n", $1, substr($0, index($0, $2)) }'
else
  echo "  none"
fi

if [ -n "$TABLE" ]; then
  cp "$VERDICTS" "$TABLE"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "PASS: every measured file is at or above its floor"
else
  echo "FAIL: a file fell below its floor"
fi
exit "$status"
