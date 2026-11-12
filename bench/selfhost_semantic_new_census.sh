#!/usr/bin/env bash
# `new` census for the iyi semantic port, against the hosted semantic pass, over the
# compiler's own source and the prelude (slice S1n, step 2).
#
# Each file (src/compiler/**/*.iyi and src/iyi/*.iyi) is compiled as an entry (the prelude
# first, then the file) by the hosted pass (bench/selfhost_semantic_new_census_oracle.cr),
# which prints each `new` call of the file the hosted pass typed, with its receiver, its
# argument types, its result and its target def. The port's driver
# (bench/selfhost_semantic_new_census_exercise.iyi) analyses the same file the same way and
# prints each `new` call with the same key (line:col), or the reason the port could not
# type it. A site is identical when the two lines are byte-identical.
#
# The committed floor (bench/selfhost_semantic_new.floor) holds each file's identical
# count; a count may only rise. The misses are ranked at the end by reason, so the next
# form to port is the top row.
#
#   bash bench/selfhost_semantic_new_census.sh
#
# Environment:
#   NEW_CENSUS_FILES=<f>  measure only the repo-relative paths listed in <f>
#   NEW_CENSUS_RAISE=1    write the floor up to the measured counts (never lower)
#   NEW_CENSUS_FLOOR=<f>  read and write this floor file instead of the default
#   NEW_CENSUS_TABLE=<f>  also write the per-file table and the misses to this file
#
# Exit status 0 when every measured file is at or above its floor, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="$REPO/bin/iyi"
CRYSTAL="$REPO/bin/crystal"
FLOOR_FILE="${NEW_CENSUS_FLOOR:-$REPO/bench/selfhost_semantic_new.floor}"
FILES_LIST="${NEW_CENSUS_FILES:-}"
RAISE="${NEW_CENSUS_RAISE:-0}"
TABLE="${NEW_CENSUS_TABLE:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
export IYI_PATH="$REPO/src"
LC_ALL=C
export LC_ALL
status=0

fatal() {
  echo "$1"
  exit 1
}

echo "== 1. Building the hosted census oracle and the port's census driver"
CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$WORK/oracle" "$REPO/bench/selfhost_semantic_new_census_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; fatal "FAILED to build the hosted census oracle"; }
"$IYI" build -o "$WORK/port" "$REPO/bench/selfhost_semantic_new_census_exercise.iyi" > "$WORK/port_build.log" 2>&1 \
  || { cat "$WORK/port_build.log"; fatal "FAILED to build the port census driver"; }
echo "  built: oracle, port driver"

if [ -n "$FILES_LIST" ]; then
  FILES="$(cat "$FILES_LIST")"
else
  FILES="$(cd "$REPO" && { find src/compiler -name '*.iyi'; find src/iyi -maxdepth 1 -name '*.iyi'; } | sort)"
fi

RESULTS="$WORK/results.tsv"
MISSES="$WORK/misses.tsv"
: > "$RESULTS"
: > "$MISSES"

echo
echo "== 2. Each file's new calls: hosted pass against the port"
measured=0
for rel in $FILES; do
  [ -f "$REPO/$rel" ] || continue
  corpus="compiler"
  case "$rel" in src/iyi/*) corpus="prelude" ;; esac
  if ! "$WORK/oracle" "$REPO/$rel" > "$WORK/o.txt" 2> "$WORK/oe.txt"; then
    printf '%s\t%s\t0\t0\tORACLE: %s\n' "$corpus" "$rel" "$(head -n 1 "$WORK/oe.txt")" >> "$RESULTS"
    continue
  fi
  if ! "$WORK/port" "$REPO/$rel" > "$WORK/p.txt" 2> "$WORK/pe.txt"; then
    printf '%s\t%s\t%d\t0\tPORT: %s\n' "$corpus" "$rel" "$(wc -l < "$WORK/o.txt" | tr -d ' ')" "$(head -n 1 "$WORK/pe.txt")" >> "$RESULTS"
    continue
  fi
  measured=$((measured + 1))
  # Join the two sides on line:col. A site the port printed as untyped is a miss with its
  # reason; a site typed differently is a miss with both lines; a missing site is a miss.
  awk -F'\t' -v rel="$rel" -v corpus="$corpus" -v results="$RESULTS" -v misses="$MISSES" '
    FNR == NR {
      if ($0 ~ /^site /) { split($0, f, " "); pkey[f[2]] = $0 }
      next
    }
    /^site / {
      split($0, f, " ")
      key = f[2]; oline = $0; total += 1
      if (!(key in pkey)) {
        reason = "port printed no line for the site"; pl = "(none)"
      } else {
        pl = pkey[key]
        if (pl == oline) { identical += 1; next }
        if (index(pl, "untyped: ") > 0) { reason = substr(pl, index(pl, "untyped: ") + 9) }
        else { reason = "port types the call differently from the hosted pass" }
      }
      gsub(/[0-9]+/, "N", reason)
      gsub(/\047[^\047]*\047/, "X", reason)
      if (length(reason) > 110) reason = substr(reason, 1, 110)
      n = oline; sub(/^site [^ ]+ /, "", n)
      print reason "\t" rel "\t" key "\t" n "\t" pl >> misses
    }
    END {
      printf "%s\t%s\t%d\t%d\tok\n", corpus, rel, total + 0, identical + 0 >> results
    }' "$WORK/p.txt" "$WORK/o.txt"
done
echo "  $measured file(s) measured"

echo
echo "== 3. Checking each file against its committed floor"
VERDICTS="$WORK/verdicts.tsv"

# Writes the floor up to the measured counts: a count is only ever raised, and a file
# that did not measure keeps the floor it had.
if [ "$RAISE" = 1 ]; then
  awk -F'\t' -v floorfile="$FLOOR_FILE" '
    BEGIN {
      while ((getline line < floorfile) > 0) {
        if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
        split(line, a, /[ \t]+/)
        floor[a[1]] = a[2] + 0
      }
    }
    $5 == "ok" { if (!($2 in floor) || $4 + 0 > floor[$2]) floor[$2] = $4 + 0 }
    END { for (k in floor) printf "%s %d\n", k, floor[k] | "sort" }' "$RESULTS" > "$WORK/floor.new"
  cp "$WORK/floor.new" "$FLOOR_FILE"
  echo "  floor written to $FLOOR_FILE"
fi

awk -F'\t' -v floorfile="$FLOOR_FILE" '
  BEGIN {
    while ((getline line < floorfile) > 0) {
      if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
      split(line, a, /[ \t]+/)
      floor[a[1]] = a[2] + 0
    }
  }
  {
    corpus = $1; rel = $2; total = $3 + 0; identical = $4 + 0; note = $5
    if (note ~ /^ORACLE/) verdict = "ORACLE"
    else if (note ~ /^PORT/) verdict = "PORT"
    else if (!(rel in floor)) verdict = "NO FLOOR"
    else if (identical < floor[rel]) verdict = "BELOW FLOOR"
    else if (identical > floor[rel]) verdict = "RAISE THE FLOOR"
    else verdict = "ok"
    fl = (rel in floor) ? floor[rel] : "-"
    printf "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", verdict, corpus, rel, total, identical, fl, note
  }' "$RESULTS" > "$VERDICTS"

awk -F'\t' '
  $1 == "BELOW FLOOR"     { printf "  BELOW FLOOR: %s identical %s, floor %s. A regression: restore the port or lower nothing.\n", $3, $5, $6; bad = 1 }
  $1 == "RAISE THE FLOOR" { printf "  RAISE THE FLOOR: %s identical %s, floor %s. Raise the floor (NEW_CENSUS_RAISE=1).\n", $3, $5, $6; bad = 1 }
  $1 == "NO FLOOR"        { printf "  NO FLOOR: %s has no floor entry. Add it (NEW_CENSUS_RAISE=1).\n", $3; bad = 1 }
  $1 == "PORT"            { printf "  PORT: %s did not run in the port (not measured). Fix the port or the file.\n", $3; bad = 1 }
  $1 == "ORACLE"          { printf "  ORACLE: %s did not compile in the hosted pass (not measured).\n", $3 }
  END { exit bad ? 1 : 0 }' "$VERDICTS"
if [ $? -ne 0 ] && [ "$RAISE" != 1 ]; then
  status=1
fi
fails=$(awk -F'\t' '$1 == "BELOW FLOOR" || $1 == "NO FLOOR" || $1 == "PORT" { n += 1 } END { print n + 0 }' "$VERDICTS")
echo "  $fails file(s) below or missing their floor"

echo
echo "== 4. Per-file census: new calls the hosted pass typed, identical in the port"
printf '  %-16s %-46s %7s %9s %8s %6s  %s\n' verdict file sites identical fraction floor note
awk -F'\t' '{
  frac = ($4 > 0) ? sprintf("%.1f%%", 100 * $5 / $4) : "n/a"
  printf "  %-16s %-46s %7s %9s %8s %6s  %s\n", $1, $3, $4, $5, frac, $6, $7
}' "$VERDICTS"

echo
echo "== 5. Corpus totals"
awk -F'\t' '
  { total[$2] += $4; ident[$2] += $5; files[$2] += 1; all_t += $4; all_i += $5 }
  END {
    for (k in total) printf "  %-10s files %4d  sites %6d  identical %6d  fraction %6.2f%%\n", k, files[k], total[k], ident[k], (total[k] ? 100 * ident[k] / total[k] : 0)
    printf "  %-10s sites %6d  identical %6d  fraction %6.2f%%\n", "ALL", all_t, all_i, (all_t ? 100 * all_i / all_t : 0)
  }' "$VERDICTS"

echo
echo "== 6. Misses, ranked by reason (count, reason, one example: file, site, hosted line, port line)"
if [ -s "$MISSES" ]; then
  awk -F'\t' '
    { n[$1] += 1; if (!($1 in ex)) { ex[$1] = $2 ":" $3 "  hosted: " $4 "  port: " $5 } }
    END { for (r in n) printf "%7d\t%s\t%s\n", n[r], r, ex[r] }' "$MISSES" | sort -t "$(printf '\t')" -k1,1nr \
    | awk -F'\t' '{ printf "  %7d  %s\n           e.g. %s\n", $1, $2, $3 }'
else
  echo "  none"
fi

if [ -n "$TABLE" ]; then
  cp "$VERDICTS" "$TABLE"
  cp "$MISSES" "$TABLE.misses"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "NEW CENSUS PASSED: every measured file is at or above its floor"
else
  echo "NEW CENSUS FAILED: a file is below its floor, has no floor, or did not run"
fi
exit "$status"
