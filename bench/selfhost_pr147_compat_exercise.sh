#!/usr/bin/env bash
# Forward-compatibility gate for upstream PR #147 (native stale testing).
#
# PR #147 edits src/iyi/{concurrency,file,float,prelude,thread}.iyi and the
# src/std files listed in bench/fixtures/pr147/. Line B's front end must accept
# those files before #147 merges, or that merge turns line B red.
#
#   bash bench/selfhost_pr147_compat_exercise.sh
#   bash bench/selfhost_pr147_compat_exercise.sh --probes-only
#
# For each changed file, probes the version at this tree and the #147 copy under
# bench/fixtures/pr147/ (read-only, source SHA in its README):
# 1. Phase probe (iyi-compile --probe-phase --single-file), the same invocation
#    bench/selfhost_prelude_exercise.sh uses. The #147 copy must be accepted by the
#    front end (phase parse or later) and must reach at least the phase the current
#    version reaches. A rejection prints the first error the probe reported.
# 2. Lexer and parser differential against the Crystal-hosted front end, using the
#    dumpers that bench/selfhost_lexer_exercise.sh and
#    bench/selfhost_parser_exercise.sh use (extracted from those scripts, unchanged).
#    A token stream or tree that differs from Crystal's, where Crystal accepts the
#    file, fails. A file is reported UNMEASURED, with its reason, where the existing
#    dumpers cannot represent it (module headers, imports, annotations). It is never passed silently.
#    bench/fixtures/pr147/gaps/ holds one snippet per front-end gap this slice fixed; each is parity-checked.
# 3. Two guarded mutation proofs: reverting a front-end fix must make the probes
#    fail, and the mutation helper must refuse a patch that changes nothing.
#
# Flags:
#   --probes-only   build .build/iyi-compile and run only step 1 (the mutation
#                   proofs run this mode).
#
set -u
status=0
probes_only=0
[ "${1:-}" = "--probes-only" ] && probes_only=1

REPO="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$REPO/bench/fixtures/pr147"
IYI="$REPO/bin/iyi"
CRYSTAL="$REPO/bin/crystal"
COMPILE="$REPO/.build/iyi-compile"
WORK="$(mktemp -d)"
MUT_FILE=""

cleanup() {
  # A mutation proof restores its file here if the run is interrupted.
  if [ -n "$MUT_FILE" ] && [ -f "$WORK/mutation.orig" ]; then
    cp "$WORK/mutation.orig" "$MUT_FILE"
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export LIBRARY_PATH="/opt/homebrew/opt/bdw-gc/lib:${LIBRARY_PATH:-}"
export CRYSTAL_CACHE_DIR="${CRYSTAL_CACHE_DIR:-/tmp/iyi-pr147-cache}"

SOURCE_SHA="$(grep -o '[0-9a-f]\{40\}' "$FIX/README.md" | head -1)"

phase_rank() {
  case "$1" in
    absent|none) echo 0 ;;
    parse)       echo 1 ;;
    semantic)    echo 2 ;;
    codegen)     echo 3 ;;
    object)      echo 4 ;;
    link)        echo 5 ;;
    *)           echo -1 ;;
  esac
}

probe_log() { echo "$WORK/probe_$(echo "$1" | tr '/' '_').log"; }

probe_phase() {
  local target="$1" log
  log="$(probe_log "$target")"
  "$COMPILE" --probe-phase --single-file "$target" > "$log" 2>&1
  if grep -qF "[phase] link: pass" "$log"; then echo link
  elif grep -qF "[phase] object: pass" "$log"; then echo object
  elif grep -qF "[phase] codegen: pass" "$log"; then echo codegen
  elif grep -qF "[phase] semantic: pass" "$log"; then echo semantic
  elif grep -qF "[phase] parse: pass" "$log"; then echo parse
  else echo none
  fi
}

# First reason the probe reported for a file it did not accept.
probe_reason() {
  grep -m1 -E 'SYNTAX ERROR|panic' "$(probe_log "$1")" | cut -c1-150
}

# Copies the Crystal dumper heredoc out of an existing gate script, unchanged.
extract_oracle() {
  awk "/^cat <<'CRYSTAL_GOLDEN_SCRIPT'/{f=1; next} /^CRYSTAL_GOLDEN_SCRIPT\$/{f=0} f" "$1"
}

# Replaces the first occurrence of OLD in FILE with NEW. Exit 3 when OLD is absent.
replace_first() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
}

# prove_mutation LABEL FILE OLD NEW
# Copies FILE aside, replaces the first OLD with NEW, runs the probes-only gate, and
# requires it to fail ("caught"). It restores FILE through the EXIT trap. A patch
# that changes nothing is refused: it proves nothing.
prove_mutation() {
  local label="$1" file="$2" old="$3" new="$4" rc
  cp "$file" "$WORK/mutation.orig"
  MUT_FILE="$file"
  replace_first "$file" "$old" "$new"
  rc=$?
  if [ "$rc" -eq 3 ]; then
    cp "$WORK/mutation.orig" "$file"; MUT_FILE=""
    echo "  [$label] PATCH CHANGED NOTHING: the text is absent, so this proves nothing"
    return 3
  fi
  if [ "$rc" -ne 0 ]; then
    cp "$WORK/mutation.orig" "$file"; MUT_FILE=""
    echo "  [$label] PATCH FAILED to apply (exit $rc)"
    return 1
  fi
  if bash "$REPO/bench/selfhost_pr147_compat_exercise.sh" --probes-only > "$WORK/mutation.log" 2>&1; then
    cp "$WORK/mutation.orig" "$file"; MUT_FILE=""
    echo "  [$label] NOT CAUGHT: the probes still pass with the fix reverted"
    return 1
  fi
  cp "$WORK/mutation.orig" "$file"; MUT_FILE=""
  echo "  [$label] caught: $(grep -m1 -E 'REJECTED|REGRESSION|FAILED' "$WORK/mutation.log" | sed 's/^ *//' | cut -c1-120)"
  return 0
}

echo "== 1. Building self-host compile tool"
cd "$REPO"
rm -f "$COMPILE"
if ! make iyi-compile > "$WORK/make.log" 2>&1; then
  tail -20 "$WORK/make.log"
  echo "ERROR: make iyi-compile failed"
  exit 1
fi
[ -x "$COMPILE" ] || { echo "ERROR: $COMPILE was not built"; exit 1; }
echo "  built .build/iyi-compile; #147 fixtures from source $SOURCE_SHA"

changed=()
while IFS= read -r f; do changed+=("$f"); done < <(cd "$FIX" && find src -name '*.iyi' | sort)
# Snippets that reproduce each front-end gap this slice fixed. Parity-checked below.
gaps=()
while IFS= read -r f; do gaps+=("$f"); done < <(cd "$FIX" && find gaps -name '*.iyi' | sort)

echo
echo "== 2. Phase probes: current tree vs #147 copy"
printf "  %-24s %-10s %-10s %s\n" "File" "Current" "#147" "Status"
printf "  %-24s %-10s %-10s %s\n" "------------------------" "----------" "----------" "------"
phase_failures=0
for rel in "${changed[@]}"; do
  cur="$REPO/$rel"
  new="$FIX/$rel"
  if [ -f "$cur" ]; then cur_phase="$(probe_phase "$cur")"; else cur_phase="absent"; fi
  new_phase="$(probe_phase "$new")"
  cur_rank="$(phase_rank "$cur_phase")"
  new_rank="$(phase_rank "$new_phase")"
  if [ "$new_rank" -lt 1 ]; then
    verdict="REJECTED"
    phase_failures=$((phase_failures + 1))
  elif [ "$new_rank" -lt "$cur_rank" ]; then
    verdict="REGRESSION"
    phase_failures=$((phase_failures + 1))
  elif [ "$new_rank" -gt "$cur_rank" ]; then
    verdict="ADVANCES"
  else
    verdict="matched"
  fi
  printf "  %-24s %-10s %-10s %s\n" "$rel" "$cur_phase" "$new_phase" "$verdict"
  if [ "$verdict" = REJECTED ]; then
    echo "    reason: $(probe_reason "$new")"
  fi
done
echo "  Phase summary: $(( ${#changed[@]} - phase_failures ))/${#changed[@]} #147 files accepted and at least the current phase ($phase_failures failing)"
[ "$phase_failures" -eq 0 ] || status=1

if [ "$probes_only" -eq 0 ]; then
  echo
  echo "== 3. Lexer and parser differential against the Crystal front end"
  extract_oracle "$REPO/bench/selfhost_lexer_exercise.sh" > "$WORK/dump_lex.cr"
  extract_oracle "$REPO/bench/selfhost_parser_exercise.sh" > "$WORK/dump_ast.cr"
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -o "$WORK/dump_crystal_tokens" "$WORK/dump_lex.cr" > "$WORK/oracle.log" 2>&1 || { tail -20 "$WORK/oracle.log"; echo "ERROR: Crystal lexer oracle failed to build"; exit 1; }
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -o "$WORK/dump_crystal_ast" "$WORK/dump_ast.cr" >> "$WORK/oracle.log" 2>&1 || { tail -20 "$WORK/oracle.log"; echo "ERROR: Crystal parser oracle failed to build"; exit 1; }
  "$IYI" build --release -o "$WORK/lexer_exercise" "$REPO/bench/selfhost_lexer_exercise.iyi" > "$WORK/build_lex.log" 2>&1 || { tail -20 "$WORK/build_lex.log"; echo "ERROR: lexer exercise failed to build"; exit 1; }
  "$IYI" build -o "$WORK/parser_exercise" "$REPO/bench/selfhost_parser_exercise.iyi" > "$WORK/build_ast.log" 2>&1 || { tail -20 "$WORK/build_ast.log"; echo "ERROR: parser exercise failed to build"; exit 1; }

  # A tree is measured only when the existing dumpers name every node it holds: the
  # Crystal dump prints Iyi::<Node> for kinds it does not name, and the iyi dump prints
  # ASTNode or Annotation for kinds it does not name (module headers, imports, annotations).
  unmeasured_marker='^[[:space:]]*(Iyi::[A-Za-z]+|ASTNode|Annotation)([[:space:]]|$)'

  printf "  %-24s %-10s %-10s %s\n" "File" "Lexer" "Parser" "Result"
  printf "  %-24s %-10s %-10s %s\n" "------------------------" "----------" "----------" "------"
  parity_failures=0
  unmeasured=0
  oracle_rejects=0
  for rel in "${changed[@]}" "${gaps[@]}"; do
    target="$FIX/$rel"
    name="$(echo "$rel" | tr '/' '_')"
    "$WORK/dump_crystal_tokens" "$target" > "$WORK/cr_tok_$name" 2>/dev/null; cr_lex=$?
    "$WORK/lexer_exercise" "$target" > "$WORK/iy_tok_$name" 2>/dev/null; iy_lex=$?
    "$WORK/dump_crystal_ast" "$target" > "$WORK/cr_ast_$name" 2>/dev/null; cr_ast=$?
    "$WORK/parser_exercise" "$target" > "$WORK/iy_ast_$name" 2>/dev/null; iy_ast=$?

    # Lexer: token streams must be identical wherever Crystal accepts the file.
    if [ "$cr_lex" -eq 0 ] && [ "$iy_lex" -eq 0 ] && cmp -s "$WORK/cr_tok_$name" "$WORK/iy_tok_$name"; then
      lex_state="identical"
    elif [ "$cr_lex" -ne 0 ] && [ "$iy_lex" -ne 0 ]; then
      lex_state="both-reject"
    else
      lex_state="DIFF"
    fi

    # Parser: trees must be identical wherever Crystal accepts the file and the dumpers name every node.
    if [ "$cr_ast" -ne 0 ] && [ "$iy_ast" -eq 0 ]; then
      ast_state="oracle-rejects"
    elif [ "$cr_ast" -ne 0 ] && [ "$iy_ast" -ne 0 ]; then
      ast_state="both-reject"
    elif [ "$cr_ast" -eq 0 ] && [ "$iy_ast" -ne 0 ]; then
      ast_state="DIFF"
    elif cmp -s "$WORK/cr_ast_$name" "$WORK/iy_ast_$name"; then
      ast_state="identical"
    elif grep -qE "$unmeasured_marker" "$WORK/cr_ast_$name" "$WORK/iy_ast_$name"; then
      ast_state="unmeasured"
    else
      ast_state="DIFF"
    fi

    result="pass"
    if [ "$lex_state" = DIFF ] || [ "$ast_state" = DIFF ]; then
      result="FAIL"
      parity_failures=$((parity_failures + 1))
      status=1
    elif [ "$ast_state" = unmeasured ]; then
      result="UNMEASURED (dumpers do not name a node in this file)"
      unmeasured=$((unmeasured + 1))
    elif [ "$ast_state" = oracle-rejects ]; then
      result="UNMEASURED (Crystal front end rejects the file; iyi accepts it)"
      oracle_rejects=$((oracle_rejects + 1))
    fi
    printf "  %-24s %-10s %-10s %s\n" "$rel" "$lex_state" "$ast_state" "$result"
  done
  echo "  Parity summary: $parity_failures files with a token or tree mismatch; $unmeasured unmeasured (dumper coverage); $oracle_rejects unmeasured (oracle rejects)"
fi

if [ "$probes_only" -eq 0 ]; then
  echo
  echo "== 4. Guarded mutation proofs"
  mutations_caught=0
  mutations_run=0
  prove_mutation "reverted: keyword before '/' ends the value in the lexer" \
    "$REPO/src/compiler/syntax/lexer.iyi" \
    $'    @wants_regex = true\n    @slash_is_regex = false\n    if ident_part_or_end?(peek_next_char)' \
    $'    if ident_part_or_end?(peek_next_char)' && mutations_caught=$((mutations_caught + 1))
  mutations_run=$((mutations_run + 1))

  prove_mutation "reverted: leading '::name' parsed as a global call" \
    "$REPO/src/compiler/syntax/parser.iyi" \
    "        parse_var_or_call(location, true)" \
    "        parse_const(true, location)" && mutations_caught=$((mutations_caught + 1))
  mutations_run=$((mutations_run + 1))

  prove_mutation "guard: a no-op patch is refused" \
    "$REPO/src/compiler/syntax/parser.iyi" \
    "this text is not in the parser" "unused" > /dev/null
  guard_rc=$?
  if [ "$guard_rc" -eq 3 ]; then
    echo "  [guard: a no-op patch is refused] refused, as required"
    mutations_caught=$((mutations_caught + 1))
  else
    echo "  [guard: a no-op patch is refused] NOT refused (exit $guard_rc)"
  fi
  mutations_run=$((mutations_run + 1))
  echo "  Mutation summary: $mutations_caught/$mutations_run proofs hold"
  [ "$mutations_caught" -eq "$mutations_run" ] || status=1

  # The mutation proofs left .build/iyi-compile built from the last mutated source.
  make iyi-compile > "$WORK/make_restore.log" 2>&1 || { echo "ERROR: could not rebuild .build/iyi-compile after mutation proofs"; status=1; }
fi

echo
if [ "$status" -eq 0 ]; then
  echo "PR147 FORWARD-COMPAT CHECKS PASSED SUCCESSFULLY!"
else
  echo "PR147 FORWARD-COMPAT CHECKS FAILED"
fi
exit $status
