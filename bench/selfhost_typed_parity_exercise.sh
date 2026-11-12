#!/usr/bin/env bash
# Burn-down gate for typed parity between the iyi semantic port and the
# hosted front end (specification S0, section 3.6).
#
# Every file of the prelude (src/iyi), std (src/std), samples (samples/iyi) and
# the compiler's own source (src/compiler) is analysed twice: by the hosted front end's
# full semantic pass (bench/selfhost_typed_oracle.cr) and by the iyi
# port (src/compiler/tools/typed_dump.iyi). For each file the gate counts the
# expression nodes the oracle typed and how many the port typed to the same
# "line:col Kind type". The committed floor (bench/selfhost_typed_parity.floor)
# holds each file's matched count; a count may only rise.
#
#   bash bench/selfhost_typed_parity_exercise.sh
#
# Verifies:
#   1. The oracle, the port's dump and the contract trait build.
#   2. The contract trait names the same members as src/compiler/lower/CONTRACT.md.
#   3-5. Every file's matched count against its floor, a per-file table, the
#        corpus totals and the ten largest gaps. A file below its floor fails
#        with BELOW FLOOR; a file above it fails with RAISE THE FLOOR, so a
#        gain is locked in by raising the floor, never left silent. A file the
#        oracle cannot analyse is reported as ORACLE and is not measured.
#   6. Guarded mutation proofs on the sem_expr fixtures, analysed bare.
#
# Environment:
#   TYPED_PARITY_RAISE=1    write the floor up to the measured counts (never lower)
#   TYPED_PARITY_FILES=<f>  measure only the repo-relative paths listed in <f>
#   TYPED_PARITY_FLOOR=<f>  read and write this floor file instead of the default
#   TYPED_PARITY_BARE=1     analyse each file alone, without the prelude
#
# Exit status 0 when every check passes, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
FLOOR_FILE="${TYPED_PARITY_FLOOR:-$REPO/bench/selfhost_typed_parity.floor}"
CHILD="${TYPED_PARITY_CHILD:-0}"
BARE="${TYPED_PARITY_BARE:-0}"
RAISE="${TYPED_PARITY_RAISE:-0}"
FILES_LIST="${TYPED_PARITY_FILES:-}"
WORK="$(mktemp -d)"
MUTATED=""
LC_ALL=C
export LC_ALL
export IYI_CACHE_DIR="$WORK/cache"
trap 'if [ -n "$MUTATED" ]; then cp "$WORK/mutation.orig" "$MUTATED"; fi; rm -rf "$WORK"' EXIT INT TERM

ORACLE="$WORK/oracle"
TYPED="$WORK/typed_dump"
RESULTS="$WORK/results.tsv"
VERDICTS="$WORK/verdicts.tsv"
status=0
: > "$RESULTS"

fatal() {
  echo "  $1"
  exit 1
}

echo "== 1. Building the Crystal oracle, the port's typed dump and the contract trait"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$ORACLE" "$REPO/bench/selfhost_typed_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; fatal "FAILED to build the Crystal oracle"; }
"$IYI" build -o "$TYPED" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/typed_build.log" 2>&1 \
  || { cat "$WORK/typed_build.log"; fatal "FAILED to build src/compiler/tools/typed_dump.iyi"; }
"$IYI" build -o "$WORK/typed_trait" "$REPO/src/compiler/semantic/typed.iyi" > "$WORK/trait_build.log" 2>&1 \
  || { cat "$WORK/trait_build.log"; fatal "FAILED to build src/compiler/semantic/typed.iyi"; }
echo "  built: oracle, typed_dump, contract trait"

if [ "$CHILD" = 0 ]; then
  echo
  echo "== 2. The contract trait and CONTRACT.md name the same members"
  awk -F'|' 'NR > 2 && $2 ~ /^ *[0-9]+ *$/ {
      m = $3; t = $5
      gsub(/[ `]/, "", m); gsub(/[ `]/, "", t)
      if (t == "") t = m
      print t
    }' "$REPO/src/compiler/lower/CONTRACT.md" | sort > "$WORK/contract_names"
  sed -n 's/^  abstract def \(.*\)$/\1/p' "$REPO/src/compiler/semantic/typed.iyi" | sort > "$WORK/trait_names"
  n_members=$(wc -l < "$WORK/contract_names" | tr -d ' ')
  if [ "$n_members" -gt 0 ] && diff "$WORK/contract_names" "$WORK/trait_names" > "$WORK/contract.diff"; then
    echo "  $n_members members: the trait and the table agree"
  else
    echo "  CONTRACT MISMATCH (table has $n_members members):"
    cat "$WORK/contract.diff"
    status=1
  fi
fi

measure() {
  corpus="$1"
  rel="$2"
  flag=""
  if [ "$BARE" = 1 ]; then
    flag="--bare"
  elif [ "$corpus" = prelude ]; then
    flag="--prelude-only"
  fi
  if "$ORACLE" $flag "$rel" > "$WORK/o.txt" 2> "$WORK/o.err"; then
    sort "$WORK/o.txt" > "$WORK/o.sorted"
    nodes=$(wc -l < "$WORK/o.sorted" | tr -d ' ')
    if "$TYPED" "$rel" > "$WORK/p.txt" 2> "$WORK/p.err"; then
      sort "$WORK/p.txt" > "$WORK/p.sorted"
      matched=$(comm -12 "$WORK/o.sorted" "$WORK/p.sorted" | wc -l | tr -d ' ')
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
  printf '%s\t%s\t%s\t%s\t%s\n' "$corpus" "$rel" "$nodes" "$matched" "$note" >> "$RESULTS"
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
  echo "== 3. Measuring every file of the prelude, std, samples and the compiler's source"
  for f in "$REPO"/src/iyi/*.iyi; do measure prelude "${f#$REPO/}"; done
  for f in "$REPO"/src/std/*.iyi; do measure std "${f#$REPO/}"; done
  for f in "$REPO"/samples/iyi/*.iyi; do measure samples "${f#$REPO/}"; done
  find "$REPO/src/compiler" -name '*.iyi' | sort | while IFS= read -r f; do
    measure compiler "${f#$REPO/}"
  done
fi
echo "  $(wc -l < "$RESULTS" | tr -d ' ') files measured"

echo
echo "== 4. Checking each file against its committed floor"
awk -F'\t' -v floorfile="$FLOOR_FILE" '
  BEGIN {
    while ((getline line < floorfile) > 0) {
      if (line ~ /^[ \t]*#/ || line ~ /^[ \t]*$/) continue
      split(line, a, /[ \t]+/)
      floor[a[1]] = a[2] + 0
    }
  }
  {
    corpus = $1; rel = $2; nodes = $3 + 0; matched = $4 + 0; note = $5
    if (note ~ /^ORACLE/) verdict = "ORACLE"
    else if (!(rel in floor)) verdict = "NO FLOOR"
    else if (matched < floor[rel]) verdict = "BELOW FLOOR"
    else if (matched > floor[rel]) verdict = "RAISE THE FLOOR"
    else verdict = "ok"
    fl = (rel in floor) ? floor[rel] : "-"
    printf "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", verdict, corpus, rel, nodes, matched, \
      (nodes > 0 ? sprintf("%.1f%%", 100 * matched / nodes) : "n/a"), fl, note
  }' "$RESULTS" > "$VERDICTS"

if [ "$RAISE" = 1 ]; then
  python3 - "$VERDICTS" "$FLOOR_FILE" <<'PY'
import sys
verdicts, floor_path = sys.argv[1], sys.argv[2]
floor = {}
try:
    for line in open(floor_path, encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            path, count = line.split()
            floor[path] = int(count)
except FileNotFoundError:
    pass
raised = 0
for line in open(verdicts, encoding="utf-8"):
    cols = line.rstrip("\n").split("\t")
    verdict, rel, matched = cols[0], cols[2], int(cols[4])
    if verdict == "BELOW FLOOR":
        continue
    old = floor.get(rel, 0)
    if matched > old:
        floor[rel] = matched
        raised += 1
    elif rel not in floor:
        floor[rel] = old
with open(floor_path, "w", encoding="utf-8") as out:
    out.write("# typed parity floors: <repo-relative file> <matched nodes>.\n")
    out.write("# A count may only rise. Raise with: TYPED_PARITY_RAISE=1 bash bench/selfhost_typed_parity_exercise.sh\n")
    for rel in sorted(floor):
        out.write(f"{rel} {floor[rel]}\n")
print(f"  floor written: {len(floor)} entries, {raised} raised")
PY
  fails=$(awk -F'\t' '$1 == "BELOW FLOOR"' "$VERDICTS" | wc -l | tr -d ' ')
else
  fails=$(awk -F'\t' '$1 == "BELOW FLOOR" || $1 == "RAISE THE FLOOR" || $1 == "NO FLOOR"' "$VERDICTS" | wc -l | tr -d ' ')
fi
awk -F'\t' '
  $1 == "BELOW FLOOR"    { printf "  BELOW FLOOR: %s matched %s, floor %s. A regression: restore the typing or lower nothing.\n", $3, $5, $7 }
  $1 == "RAISE THE FLOOR" { printf "  RAISE THE FLOOR: %s matched %s, floor %s. Raise the floor in bench/selfhost_typed_parity.floor (TYPED_PARITY_RAISE=1).\n", $3, $5, $7 }
  $1 == "NO FLOOR"       { printf "  NO FLOOR: %s has no floor entry. Add it (TYPED_PARITY_RAISE=1).\n", $3 }
' "$VERDICTS"
echo "  $fails file(s) below or missing their floor"
if [ "$fails" -gt 0 ]; then
  status=1
fi

echo
echo "== 5. Per-file typed parity: oracle nodes, port matched, fraction, floor"
printf '  %-16s %-46s %7s %8s %8s %7s  %s\n' verdict file nodes matched fraction floor note
awk -F'\t' '{
  printf "  %-16s %-46s %7s %8s %8s %7s  %s\n", $1, $3, $4, $5, $6, $7, $8
}' "$VERDICTS"

echo
echo "== 6. Corpus totals"
awk -F'\t' '
  {
    nodes[$1] += $3; matched[$1] += $4; count[$1] += 1
    if ($5 ~ /^ORACLE/) oracle[$1] += 1
    if ($5 ~ /^PORT/) port[$1] += 1
    total_nodes += $3; total_matched += $4; total_files += 1
    if ($5 ~ /^ORACLE/) total_oracle += 1
    if ($5 ~ /^PORT/) total_port += 1
  }
  END {
    n = 0
    for (k in nodes) keys[++n] = k
    for (i = 1; i <= n; i++) for (j = i + 1; j <= n; j++) if (keys[j] < keys[i]) { t = keys[i]; keys[i] = keys[j]; keys[j] = t }
    for (i = 1; i <= n; i++) {
      k = keys[i]
      printf "  %-10s files %4d  oracle-failed %3d  port-failed %4d  oracle nodes %8d  matched %8d  fraction %6.2f%%\n", \
        k, count[k], oracle[k] + 0, port[k] + 0, nodes[k], matched[k], (nodes[k] ? 100 * matched[k] / nodes[k] : 0)
    }
    printf "  %-10s files %4d  oracle-failed %3d  port-failed %4d  oracle nodes %8d  matched %8d  fraction %6.2f%%\n", \
      "ALL", total_files, total_oracle + 0, total_port + 0, total_nodes, total_matched, (total_nodes ? 100 * total_matched / total_nodes : 0)
  }' "$RESULTS"

echo
echo "== 6b. Port failures by class (the port's first message, grouped; a file the port cannot analyse counts as zero matched)"
awk -F'\t' '
  $5 ~ /^PORT/ {
    r = substr($5, 7)
    c = "other"
    if (r ~ /undefined constant/) c = "undefined constant (top-level refuses a name it cannot resolve: no imports or prelude in the dump)"
    else if (r ~ /node has no type/) c = "BUG node has no type (a module header or annotation node the visitor does not type)"
    else if (r ~ /undefined local variable or method/) c = "undefined local variable or method"
    else if (r ~ /stack overflow/) c = "stack overflow"
    else if (r ~ /[Ss]yntax error/) c = "syntax error in a file the dump parses"
    else if (r ~ /alias|inherit|extend|already defined/) c = "declaration conflict (top-level pass)"
    cls[c]++
    total++
  }
  END {
    for (c in cls) printf "  %5d  %s\n", cls[c], c
    printf "  %5d  total port failures\n", total + 0
  }' "$RESULTS" | sort -k1,1nr
echo
echo "== 7. The ten largest gaps (oracle nodes the port did not type identically)"
awk -F'\t' '$4 > 0 || $3 > 0 { printf "%d\t%d\t%d\t%s\n", $3 - $4, $3, $4, $2 }' "$RESULTS" \
  | sort -t "$(printf '\t')" -k1,1nr -k4,4 | head -n 10 \
  | awk -F'\t' '{ printf "  gap %6d  oracle %6d  matched %6d  %s\n", $1, $2, $3, $4 }'

if [ "$CHILD" = 0 ]; then
  prove_mutation() {
    label="$1"
    file="$2"
    old="$3"
    new="$4"
    expect="$5"
    shift 6
    cp "$file" "$WORK/mutation.orig"
    MUTATED="$file"
    python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path, encoding="utf-8").read()
if old not in src:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(src.replace(old, new, 1))
PY
    rc=$?
    if [ "$rc" -eq 3 ]; then
      cp "$WORK/mutation.orig" "$file"
      MUTATED=""
      echo "  $label: PATCH CHANGED NOTHING: this proves nothing"
      return 1
    fi
    "$@" > "$WORK/mutation.out" 2>&1
    crc=$?
    cp "$WORK/mutation.orig" "$file"
    MUTATED=""
    if [ "$crc" -ne 0 ] && grep -qF "$expect" "$WORK/mutation.out"; then
      echo "  $label: caught ($expect)"
      return 0
    fi
    echo "  $label: NOT CAUGHT (exit $crc, expected $expect)"
    return 1
  }

  child_gate() {
    floor="$1"
    shift
    env TYPED_PARITY_CHILD=1 TYPED_PARITY_BARE=1 TYPED_PARITY_RAISE=0 TYPED_PARITY_FILES="$PROOF_LIST" \
      TYPED_PARITY_FLOOR="$floor" "$@" bash "$REPO/bench/selfhost_typed_parity_exercise.sh"
  }

  echo
  echo "== 8. Guarded mutation proofs (the sem_expr fixtures, analysed bare)"
  PROOF_LIST="$WORK/proof_files.txt"
  printf '%s\n' \
    bench/fixtures/sem_expr_literals.iyi \
    bench/fixtures/sem_expr_control.iyi \
    bench/fixtures/sem_expr_vars.iyi \
    bench/fixtures/sem_expr_calls.iyi > "$PROOF_LIST"
  PROOF_FLOOR="$WORK/proof.floor"
  child_gate "$PROOF_FLOOR" TYPED_PARITY_RAISE=1 > "$WORK/proof_raise.log" 2>&1
  if child_gate "$PROOF_FLOOR" > "$WORK/proof_base.log" 2>&1; then
    echo "  baseline: the proof subset passes at its own floors"
  else
    echo "  baseline FAILED: the proof subset does not pass at its floors:"
    cat "$WORK/proof_base.log"
    status=1
  fi

  prove_mutation "the port prints a wrong type for one node kind" \
    "$REPO/src/compiler/tools/typed_dump.iyi" \
    "  t.full_name" \
    '  if node_class_name(node) == "NumberLiteral"
    "Float64"
  else
    t.full_name
  end' \
    "BELOW FLOOR" -- child_gate "$PROOF_FLOOR" || status=1

  LOWERED="$WORK/lowered.floor"
  python3 - "$PROOF_FLOOR" "$LOWERED" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
rows = [line.split() for line in open(src, encoding="utf-8") if line.strip() and not line.startswith("#")]
for row in rows:
    if int(row[1]) > 0:
        row[1] = str(int(row[1]) - 1)
        break
with open(dst, "w", encoding="utf-8") as out:
    for row in rows:
        out.write(" ".join(row) + "\n")
PY
  if child_gate "$LOWERED" > "$WORK/lowered.log" 2>&1; then
    echo "  a floor lowered by hand: NOT CAUGHT (the gate passed)"
    status=1
  elif grep -qF "RAISE THE FLOOR" "$WORK/lowered.log"; then
    echo "  a floor lowered by hand: caught (RAISE THE FLOOR)"
  else
    echo "  a floor lowered by hand: NOT CAUGHT (no RAISE THE FLOOR)"
    status=1
  fi

  NOOP="$WORK/noop.iyi"
  printf 'x\n' > "$NOOP"
  if (prove_mutation "a mutation that changes nothing" "$NOOP" "no such text" "y" "x" -- true) > "$WORK/noop.log" 2>&1; then
    echo "  a mutation that changes nothing: NOT REFUSED"
    status=1
  elif grep -qF "PATCH CHANGED NOTHING" "$WORK/noop.log"; then
    echo "  a mutation that changes nothing: refused (PATCH CHANGED NOTHING)"
  else
    echo "  a mutation that changes nothing: NOT REFUSED"
    status=1
  fi
fi

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL TYPED PARITY CHECKS PASSED"
else
  echo "== SOME TYPED PARITY CHECKS FAILED"
fi
exit "$status"
