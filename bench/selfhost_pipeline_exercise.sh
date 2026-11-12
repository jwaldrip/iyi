#!/usr/bin/env bash
# The typed pipeline, one program at a time (SPEC 2.1, S3): the tool built from source with
# `--pipeline typed` (src/compiler/compiler.iyi `compile_typed`, src/compiler/lower/program.iyi),
# measured against the hosted compiler on the fixtures the four lowering gates read.
#
# For each fixture (bench/fixtures/lower_*, lowcall_*, lowprim_*, lowglob_*):
#   - the tool runs with --probe-phase and reaches a phase: parse, declarations, bodies, lower,
#     verify, native, link. A refusal names its phase on stdout and exits 1 with no output file.
#   - a fixture that reaches link is run; its stdout and exit status must equal the hosted
#     compiler's executable for the same fixture (built with --prelude empty). That is run-equal.
#   - a fixture that reaches link and differs is a failure. A refused fixture must exit nonzero
#     and write no output.
# The floor (bench/selfhost_pipeline.floor) records the phase each fixture reaches. A phase may
# only rise; SELFHOST_PIPELINE_RAISE=1 writes the measured phases. The rows under ROOTS are the
# prelude programs and the compiler's own tools, measured with --prelude and the iyi prelude on
# IYI_PATH; they are recorded and must not fall.
#
# Mutation proofs patch the tool's own code (the typed branch, the program assembly, the tool's
# refusal path), rebuild the tool, and require the check to fail. prove_mutation refuses a patch
# that changes nothing.
#
#   bash bench/selfhost_pipeline_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
. "$REPO/bench/lib/mutation.sh"
WORK="$(mktemp -d /tmp/iyi-pipeline.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
FLOOR="$REPO/bench/selfhost_pipeline.floor"
TOOL_SRC="$REPO/src/compiler/tools/compile_native.iyi"
PROGRAM_SRC="$REPO/src/compiler/lower/program.iyi"
COMPILER_SRC="$REPO/src/compiler/compiler.iyi"
ROOTS="samples/iyi/hello.iyi src/compiler/tools/parse.iyi src/compiler/tools/compile_native.iyi"

rank() {
  case "$1" in
    none) echo 0 ;; parse) echo 1 ;; declarations) echo 2 ;; bodies) echo 3 ;; lower) echo 4 ;;
    verify) echo 5 ;; native) echo 6 ;; link) echo 7 ;; run-equal) echo 8 ;; *) echo -1 ;;
  esac
}

# The phase a tool probe reached: the last `reached:` line. A refusal that exits the process (refuse_port)
# prints no `reached:` line, so the last passed phase is read instead.
probe_phase() {
  awk '/^reached:/ { r = $2; found = 1 } /^\[phase\] [a-z]+: pass$/ { p = $2; sub(":", "", p) } END { if (found) print r; else print p }' "$1"
}

# Builds the tool from the given source, with the hosted compiler, into $2.
build_tool() {
  "$IYI" build -o "$2" "$1" > "$2.build.log" 2>&1
}

echo "== 1. The tool builds from source with bin/iyi and links no LLVM"
if ! build_tool "$TOOL_SRC" "$WORK/tool"; then
  echo "  FAIL: the tool does not build (see $WORK/tool.build.log)"
  exit 1
fi
if otool -L "$WORK/tool" | awk '/LLVM|llvm/ { found = 1 } END { exit !found }'; then
  echo "  FAIL: the tool links LLVM"
  exit 1
fi
echo "  the tool builds and links no LLVM"

echo
echo "== 2. Each fixture: the typed pipeline against the hosted executable"
declare -A measured
run_equal=0
refused=0
failed=0
total=0
fixtures=""
for g in lower_ lowcall_ lowprim_ lowglob_; do
  for f in "$REPO"/bench/fixtures/${g}*.iyi; do
    [ -f "$f" ] && fixtures="$fixtures $f"
  done
done
for fixture in $fixtures; do
  name="$(basename "$fixture" .iyi)"
  rel="bench/fixtures/$name.iyi"
  total=$((total + 1))
  out="$WORK/$name"
  "$WORK/tool" "$fixture" -o "$out" --pipeline typed --probe-phase > "$WORK/$name.probe" 2> "$WORK/$name.err"
  ts=$?
  reached="$(probe_phase "$WORK/$name.probe")"
  if [ "$ts" -eq 0 ] && [ "$reached" = "link" ]; then
    if ! "$IYI" build --prelude empty -o "$WORK/$name.hosted" "$fixture" > "$WORK/$name.hosted.log" 2>&1; then
      echo "  $name: FAILED, the hosted compiler does not build the fixture"
      failed=$((failed + 1)); measured[$rel]="link"; continue
    fi
    timeout 30 "$out" > "$WORK/$name.typed.out" 2>&1; tstat=$?
    timeout 30 "$WORK/$name.hosted" > "$WORK/$name.hosted.out" 2>&1; hstat=$?
    if [ "$tstat" = "$hstat" ] && cmp -s "$WORK/$name.typed.out" "$WORK/$name.hosted.out"; then
      echo "  $name: run-equal (status $hstat, stdout identical)"
      run_equal=$((run_equal + 1)); measured[$rel]="run-equal"
    else
      echo "  $name: FAILED, the typed executable exits $tstat, the hosted $hstat, or the stdout differs"
      failed=$((failed + 1)); measured[$rel]="link"
    fi
  elif [ "$ts" -ne 0 ] && [ "$reached" != "link" ] && [ ! -e "$out" ]; then
    refusal="$(awk '/: fail: / { print; exit }' "$WORK/$name.probe" | cut -c1-140)"
    [ -z "$refusal" ] && refusal="$(awk 'NR==1' "$WORK/$name.err" | cut -c1-140)"
    echo "  $name: refused after $reached, exit $ts, no output: $refusal"
    refused=$((refused + 1)); measured[$rel]="$reached"
  else
    echo "  $name: FAILED, exit $ts, reached $reached, output file present: $([ -e "$out" ] && echo yes || echo no)"
    failed=$((failed + 1)); measured[$rel]="${reached:-none}"
  fi
done
echo "  fixtures: $run_equal run-equal of $total, $refused refused with no output, $failed failed"

echo
echo "== 3. The prelude programs and the compiler's own tools: the phase each reaches"
for root in $ROOTS; do
  rel="$root"
  name="$(basename "$root" .iyi)"
  IYI_PATH="$REPO/src" "$WORK/tool" "$REPO/$root" -o "$WORK/$name.root" --pipeline typed --prelude --probe-phase > "$WORK/$name.root.probe" 2> "$WORK/$name.root.err"
  rphase="$(probe_phase "$WORK/$name.root.probe")"
  [ -e "$WORK/$name.root" ] && rphase="$rphase (output written: unexpected)"
  echo "  $root: reached ${rphase:-none}"
  measured[$rel]="${rphase%% *}"
done

echo
echo "== 4. The floor: no phase falls"
if [ "${SELFHOST_PIPELINE_RAISE:-0}" = "1" ]; then
  : > "$FLOOR.new"
  echo "# selfhost pipeline floor: <repo file> <phase reached>. A phase may only rise." >> "$FLOOR.new"
  echo "# Raise with SELFHOST_PIPELINE_RAISE=1 bash bench/selfhost_pipeline_exercise.sh (keeps the higher phase)." >> "$FLOOR.new"
  for k in $(printf '%s\n' "${!measured[@]}" | sort); do
    echo "$k ${measured[$k]}" >> "$FLOOR.new"
  done
  mv "$FLOOR.new" "$FLOOR"
  echo "  floor written: $(printf '%s\n' "${!measured[@]}" | wc -l | awk '{print $1}') rows"
fi
floor_bad=0
while read -r key phase; do
  case "$key" in ""|\#*) continue ;; esac
  want=$(rank "$phase")
  got_phase="${measured[$key]:-missing}"
  got=$(rank "$got_phase")
  if [ "$got" -lt "$want" ]; then
    echo "  $key: FALLS below the floor ($got_phase < $phase)"
    floor_bad=$((floor_bad + 1))
  fi
done < "$FLOOR"
if [ "$floor_bad" -gt 0 ]; then
  status=1
else
  echo "  every measured phase is at or above the floor"
fi
for k in "${!measured[@]}"; do
  if [ "$(rank "${measured[$k]}")" -ge 0 ] && ! awk -v k="$k" '$1 == k { found = 1 } END { exit !found }' "$FLOOR" 2>/dev/null; then
    echo "  $k: not in the floor (raise the floor with SELFHOST_PIPELINE_RAISE=1)"
    status=1
  fi
done
if [ "$failed" -gt 0 ] || [ "$run_equal" -eq 0 ]; then
  echo "  FAIL: $failed fixture(s) failed, $run_equal run-equal"
  status=1
fi

echo
echo "== 5. Mutation proofs: the gate must catch each patch"
# The check rebuilds the tool from the patched source and requires: one fixture that links and runs equal, a
# fixture that must exit nonzero and write nothing (the refusal), and the typed build of a program with its
# top-level code. It returns 0 only on the unmutated behaviour.
pipeline_check() {
  if ! build_tool "$TOOL_SRC" "$WORK/mut_tool"; then return 1; fi
  local a="$REPO/bench/fixtures/lower_exit.iyi"
  local b="$REPO/bench/fixtures/lowprim_checked.iyi"
  rm -f "$WORK/mut_a" "$WORK/mut_b"
  "$WORK/mut_tool" "$a" -o "$WORK/mut_a" --pipeline typed > /dev/null 2>&1; local sa=$?
  [ "$sa" -eq 0 ] || return 1
  timeout 30 "$WORK/mut_a" > /dev/null 2>&1; [ "$?" -eq 42 ] || return 1
  "$WORK/mut_tool" "$b" -o "$WORK/mut_b" --pipeline typed > /dev/null 2>&1; local sb=$?
  [ "$sb" -ne 0 ] || return 1
  [ ! -e "$WORK/mut_b" ] || return 1
  return 0
}
echo "  the mutation check passes on the unmutated code:"
if pipeline_check; then
  echo "    unmutated: pass"
else
  echo "    unmutated: FAIL (the mutation check cannot prove anything)"
  status=1
fi
prove_mutation "a refusal exits 0 and writes nothing" "$COMPILER_SRC" \
  '@refusal = "#{phase}: #{message}"' '@refusal = nil' -- pipeline_check || status=1
prove_mutation "the program's top-level code is dropped" "$PROGRAM_SRC" \
  "top_level.each { |t| nodes << t }" "nodes << Nop.new" -- pipeline_check || status=1
prove_mutation "the tool falls back to the codegen pipeline when the typed one refuses" "$TOOL_SRC" \
  "fail(refusal.as(String))" "compiler.config.typed_pipeline = false; compiler.refusal = nil; compiler.compile(input)" -- pipeline_check || status=1

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL CHECKS PASSED"
else
  echo "== SOME CHECKS FAILED"
fi
exit "$status"
