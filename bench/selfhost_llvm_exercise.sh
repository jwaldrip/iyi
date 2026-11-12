#!/usr/bin/env bash
# Exercises the self-hosting LLVM backend: bindings, wrappers, IR construction,
# pass manager optimization, and native object emission.
#
#   bash bench/selfhost_llvm_exercise.sh
#
# Verifies:
# 1. Plain compilation and execution of selfhost LLVM exercise
# 2. --release compilation and execution
# 3. Native object file emission, linking with C driver, and execution (add_numbers(40, 2) == 42)
# 4. Guarded mutation proofs verifying that checks catch injected LLVM builder/type defects
#

set -eu

REPO="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO/bench/lib/mutation.sh"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT
if command -v brew >/dev/null 2>&1; then
  LIBRARY_PATH="$(brew --prefix bdw-gc)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"; export LIBRARY_PATH
fi

status=0
mkdir -p "$WORK/plain_out" "$WORK/release_out" "$WORK/mut_out" "$WORK/final_out"

echo "== 1. Building and running selfhost LLVM exercise (plain mode)"
"$IYI" build -o "$WORK/exercise-plain" "$REPO/bench/selfhost_llvm_exercise.iyi"
# The exercise's own output names the check that failed: print it before stopping, or the gate's log ends at the
# heading above and says nothing.
if ! "$WORK/exercise-plain" "$WORK/plain_out" > "$WORK/plain.out" 2>&1; then
  cat "$WORK/plain.out"
  echo "FAILED: the plain exercise exited non-zero"
  exit 1
fi
cat "$WORK/plain.out"

echo
echo "== Checking reported verification sections in plain mode"
for phrase in \
  "== 1. Target initialization & identification" \
  "== 2. Context & Type system" \
  "== 3. Constants & Values" \
  "== 4. Module construction, globals & functions" \
  "== 5. Verification" \
  "== 6. Optimization passes (PassBuilder)" \
  "== 7. Object, Assembly, Bitcode emission" \
  "ALL SELFHOST LLVM CHECKS PASSED SUCCESSFULLY!"; do
  if ! grep -qF "$phrase" "$WORK/plain.out"; then
    echo "FAILED: missing '$phrase'"
    exit 1
  fi
done

echo
echo "== 2. Building and running selfhost LLVM exercise (--release mode)"
"$IYI" build --release -o "$WORK/exercise-release" "$REPO/bench/selfhost_llvm_exercise.iyi"
if ! "$WORK/exercise-release" "$WORK/release_out" > "$WORK/release.out" 2>&1; then
  cat "$WORK/release.out"
  echo "FAILED: the release exercise exited non-zero"
  exit 1
fi
cat "$WORK/release.out"

if ! grep -qF "ALL SELFHOST LLVM CHECKS PASSED SUCCESSFULLY!" "$WORK/release.out"; then
  echo "FAILED: release mode did not pass checks"
  exit 1
fi

echo
echo "== 3. Verifying native object emission, linking, and execution"
if [ ! -f "$WORK/plain_out/selfhost_llvm_test.o" ]; then
  echo "FAILED: object file not found at $WORK/plain_out/selfhost_llvm_test.o"
  exit 1
fi

# Say what kind of object it is. The CI container has no `file`, and the gate
# died there with 127 on a line that only describes: the link and the run below
# are what check the object, so this prints the magic bytes where `file` is absent.
if command -v file >/dev/null 2>&1; then
  file "$WORK/plain_out/selfhost_llvm_test.o"
else
  echo "object magic: $(od -An -tx1 -N4 "$WORK/plain_out/selfhost_llvm_test.o" | tr -d ' \n')"
fi

# Create C driver to link against emitted object
cat <<'C_RUNNER' > "$WORK/driver.c"
#include <stdio.h>
#include <stdlib.h>

extern int add_numbers(int a, int b);
extern int factorial(int n);

int main() {
    int sum = add_numbers(40, 2);
    if (sum != 42) {
        fprintf(stderr, "FAIL: add_numbers(40, 2) = %d, expected 42\n", sum);
        return 1;
    }
    printf("add_numbers(40, 2) = %d [OK]\n", sum);

    int fact5 = factorial(5);
    if (fact5 != 120) {
        fprintf(stderr, "FAIL: factorial(5) = %d, expected 120\n", fact5);
        return 2;
    }
    printf("factorial(5) = %d [OK]\n", fact5);

    printf("EMITTED OBJECT EXECUTION VERIFIED SUCCESSFULLY!\n");
    return 0;
}
C_RUNNER

CC_BIN="$(command -v clang || command -v cc || command -v gcc || true)"
if [ -z "$CC_BIN" ]; then
  echo "FAILED: no C compiler found (clang, cc or gcc) on PATH"
  exit 1
fi
"$CC_BIN" "$WORK/driver.c" "$WORK/plain_out/selfhost_llvm_test.o" -o "$WORK/test_runner"
"$WORK/test_runner" > "$WORK/driver.out"
cat "$WORK/driver.out"

if ! grep -qF "EMITTED OBJECT EXECUTION VERIFIED SUCCESSFULLY!" "$WORK/driver.out"; then
  echo "FAILED: emitted object execution failed"
  exit 1
fi

echo
echo "== 4. Guarded mutation proofs (verify patch applies, exercise fails, revert passes)"

# Each mutant runs the exercise on the mutated source. Non-zero (exercise failed) = caught.
llvm_exercise_mutant() {
  "$IYI" run "$REPO/bench/selfhost_llvm_exercise.iyi" -- "$WORK/mut_out"
}

prove_mutation "corrupting build_and in builder.iyi" \
  "$REPO/src/compiler/llvm/builder.iyi" \
  "LibLLVM.build_and" \
  "LibLLVM.build_or" \
  -- llvm_exercise_mutant || status=1

prove_mutation "corrupting int_width in values.iyi" \
  "$REPO/src/compiler/llvm/values.iyi" \
  "LibLLVM.get_int_type_width(@unwrap)" \
  "LibLLVM.get_int_type_width(@unwrap) + 1" \
  -- llvm_exercise_mutant || status=1

prove_mutation "corrupting Target.init_target in target.iyi" \
  "$REPO/src/compiler/llvm/target.iyi" \
  'when "aarch64", "arm64"' \
  'when "never_match_target"' \
  -- llvm_exercise_mutant || status=1

prove_mutation "corrupting verify_safely in module.iyi" \
  "$REPO/src/compiler/llvm/module.iyi" \
  "{false, err}" \
  '{true, ""}' \
  -- llvm_exercise_mutant || status=1

prove_mutation "corrupting build_xor in builder.iyi" \
  "$REPO/src/compiler/llvm/builder.iyi" \
  "LibLLVM.build_xor" \
  "LibLLVM.build_or" \
  -- llvm_exercise_mutant || status=1

echo
echo "== 5. Confirming clean state verification"
"$WORK/exercise-release" "$WORK/final_out" >/dev/null
echo "  Clean state confirmed: all self-host LLVM checks pass!"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST LLVM BENCHMARK & MUTATION CHECKS PASSED!"
  exit 0
fi
echo "== SOME CHECKS FAILED!"
exit 1
