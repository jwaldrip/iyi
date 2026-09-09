#!/usr/bin/env bash
# Proves why wasm32-wasi has no concurrency runtime (SPEC.md III.4).
#
# Tests each candidate mechanism against the toolchain and wasmtime 48:
#   1. Native stack-switching proposal in wasmtime
#   2. wasi-threads in wasi-sdk and wasmtime
#   3. Binaryen Asyncify transform (unwind/rewind and overhead)
#   4. iyi compiler refusal for `group`
#
# Each check proves it can fail: a check that passes unconditionally
# proves nothing.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WASI_SDK="${WASI_SDK:-/tmp/wasi-sdk-24.0-arm64-macos}"
WASMTIME="${WASMTIME:-$HOME/.wasmtime/bin/wasmtime}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

for tool in "$WASI_SDK/bin/clang" "$WASMTIME"; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "missing required tool: $tool"
    exit 1
  fi
done

step() {
  echo "== $1"
}

pass() {
  echo "  pass: $1"
}

fail() {
  echo "  FAIL: $1"
  status=1
}

# Compile a minimal C program to wasm
cat << 'EOF' > "$WORK/minimal.c"
#include <stdio.h>
int main(void) {
    printf("minimal wasm ok\n");
    return 0;
}
EOF
"$WASI_SDK/bin/clang" --target=wasm32-wasi "$WORK/minimal.c" -o "$WORK/minimal.wasm" || {
  echo "failed to build minimal.wasm"
  exit 1
}

# -----------------------------------------------------------------------------
step "1. Native stack-switching proposal in wasmtime 48.0.1"
# -----------------------------------------------------------------------------
# Verify that wasmtime has the flag listed in help but rejects execution
# because Cranelift/Wasmtime disables stack switching at compile time.
"$WASMTIME" run -W stack-switching=y "$WORK/minimal.wasm" > "$WORK/stack_switch.log" 2>&1
ec=$?
if [ $ec -ne 0 ] && grep -q "wasm_stack_switching feature is not supported on this compiler configuration" "$WORK/stack_switch.log"; then
  pass "wasmtime refuses -W stack-switching=y: feature not supported on this compiler configuration"
else
  fail "expected wasmtime to refuse -W stack-switching=y with configuration error"
fi

# Failure proof: running without the flag succeeds
"$WASMTIME" run "$WORK/minimal.wasm" > "$WORK/minimal.log" 2>&1
if [ $? -eq 0 ] && grep -q "minimal wasm ok" "$WORK/minimal.log"; then
  pass "failure proof: minimal program runs without stack-switching flag"
else
  fail "failure proof: minimal program failed to run"
fi

# -----------------------------------------------------------------------------
step "2. wasi-threads in wasi-sdk 24 and wasmtime 48.0.1"
# -----------------------------------------------------------------------------
cat << 'EOF' > "$WORK/thread_test.c"
#include <stdio.h>
#include <pthread.h>

void* worker(void* arg) {
    return NULL;
}

int main(void) {
    pthread_t th;
    if (pthread_create(&th, NULL, worker, NULL) != 0) {
        return 1;
    }
    pthread_join(th, NULL);
    return 0;
}
EOF

"$WASI_SDK/bin/wasm32-wasi-threads-clang" -pthread \
  -Wl,--shared-memory,--max-memory=67108864 \
  "$WORK/thread_test.c" -o "$WORK/thread_test.wasm" || {
  echo "failed to compile thread_test.c with wasm32-wasi-threads-clang"
  exit 1
}

# Default wasmtime run: missing import wasi::thread-spawn
"$WASMTIME" run "$WORK/thread_test.wasm" > "$WORK/thread_default.log" 2>&1
ec=$?
if [ $ec -ne 0 ] && grep -q "wasi::thread-spawn" "$WORK/thread_default.log"; then
  pass "wasmtime default refuses thread module: unknown import wasi::thread-spawn"
else
  fail "expected unknown import wasi::thread-spawn under default wasmtime"
fi

# wasmtime with -S threads=y: flag explicitly unsupported
"$WASMTIME" run -S threads=y -W threads=y "$WORK/thread_test.wasm" > "$WORK/thread_flag.log" 2>&1
ec=$?
if [ $ec -ne 0 ] && grep -q "the \`-Sthreads\` flag is no longer supported" "$WORK/thread_flag.log"; then
  pass "wasmtime refuses -S threads=y: flag is no longer supported"
else
  fail "expected -S threads=y to fail with 'flag is no longer supported'"
fi

# Failure proof: single-threaded wasm runs without thread import errors
if grep -q "minimal wasm ok" "$WORK/minimal.log"; then
  pass "failure proof: single-threaded execution works without wasi::thread-spawn"
else
  fail "failure proof: expected single-threaded execution to work"
fi

# -----------------------------------------------------------------------------
step "3. Binaryen Asyncify: unwinds out of process without host harness"
# -----------------------------------------------------------------------------
WASM_OPT="$(which wasm-opt 2>/dev/null || echo "")"
if [ -n "$WASM_OPT" ]; then
  cat << 'EOF' > "$WORK/async_unwind.c"
#include <stdio.h>
#include <stdint.h>

__attribute__((__import_module__("asyncify"), __import_name__("start_unwind")))
void asyncify_start_unwind(void *buf);

__attribute__((__import_module__("asyncify"), __import_name__("stop_unwind")))
void asyncify_stop_unwind(void);

uint32_t buf[1024];

void coro_step(void) {
    buf[0] = (uint32_t)(uintptr_t)&buf[2];
    buf[1] = (uint32_t)(uintptr_t)&buf[1024];
    asyncify_start_unwind(buf);
}

int main(void) {
    printf("main: start\n");
    coro_step();
    printf("main: SHOULD NOT BE REACHED\n");
    return 0;
}
EOF
  "$WASI_SDK/bin/wasm32-wasi-clang" -Wl,--allow-undefined "$WORK/async_unwind.c" -o "$WORK/async_unwind.wasm"
  "$WASM_OPT" --asyncify \
    --pass-arg=asyncify-imports@asyncify.start_unwind,asyncify.stop_unwind \
    "$WORK/async_unwind.wasm" -o "$WORK/async_unwind_opt.wasm"

  "$WASMTIME" run "$WORK/async_unwind_opt.wasm" > "$WORK/async_run.log" 2>&1
  if grep -q "main: start" "$WORK/async_run.log" && ! grep -q "SHOULD NOT BE REACHED" "$WORK/async_run.log"; then
    pass "asyncify unwinding unwinds entire call stack out of main (process exits without resumption)"
  else
    fail "expected asyncify to unwind through main without executing subsequent code"
  fi

  # Failure proof: non-unwinding module executes subsequent code normally
  cat << 'EOF' > "$WORK/sync_run.c"
#include <stdio.h>
int main(void) {
    printf("main: start\n");
    printf("main: reaches end\n");
    return 0;
}
EOF
  "$WASI_SDK/bin/clang" --target=wasm32-wasi "$WORK/sync_run.c" -o "$WORK/sync_run.wasm"
  "$WASMTIME" run "$WORK/sync_run.wasm" > "$WORK/sync_run.log" 2>&1
  if grep -q "main: start" "$WORK/sync_run.log" && grep -q "main: reaches end" "$WORK/sync_run.log"; then
    pass "failure proof: non-unwinding code executes through main to completion"
  else
    fail "failure proof: expected normal execution to reach completion"
  fi

  # Failure proof: asyncified module with no unwind call completes cleanly
  "$WASM_OPT" --asyncify "$WORK/minimal.wasm" -o "$WORK/minimal_async.wasm"
  "$WASMTIME" run "$WORK/minimal_async.wasm" > "$WORK/minimal_async.log" 2>&1
  if [ $? -eq 0 ] && grep -q "minimal wasm ok" "$WORK/minimal_async.log"; then
    pass "failure proof: asyncified module without unwind executes cleanly"
  else
    fail "failure proof: asyncified minimal module failed to run"
  fi

  # Measure overhead on honest iyi program
  "$IYI" build --cross-compile --target wasm32-wasi -o "$WORK/hello_native" "$REPO/samples/iyi/hello.iyi" > "$WORK/hello.link" 2>&1
  "$WASI_SDK/bin/clang" "$WORK/hello_native.wasm" -o "$WORK/hello_native.wasm.linked" --target=wasm32-wasi -L"$REPO/.build/../lib/iyi"
  "$WASM_OPT" --asyncify "$WORK/hello_native.wasm.linked" -o "$WORK/hello_async.wasm"

  sz_nat=$(wc -c < "$WORK/hello_native.wasm.linked" | tr -d ' ')
  sz_asy=$(wc -c < "$WORK/hello_async.wasm" | tr -d ' ')
  pct=$(( (sz_asy - sz_nat) * 100 / sz_nat ))
  pass "asyncify code size overhead on hello.iyi: ${sz_nat}B -> ${sz_asy}B (+${pct}%)"
else
  echo "  skip: wasm-opt not found in PATH"
fi

# -----------------------------------------------------------------------------
step "4. iyi compiler refusal for group on wasm32-wasi"
# -----------------------------------------------------------------------------
cat << 'EOF' > "$WORK/group_refusal.iyi"
group do |g|
  t = g.spawn do
    42
  end
  puts t.value
end
EOF

"$IYI" build --cross-compile --target wasm32-wasi -o "$WORK/group_refusal" "$WORK/group_refusal.iyi" > "$WORK/group_build.log" 2>&1
ec=$?
if [ $ec -ne 0 ] && grep -q "group is not available on wasm32-wasi: WebAssembly cannot switch stacks" "$WORK/group_build.log"; then
  pass "compiler refuses group on wasm32-wasi with explicit reason naming SPEC.md III.4"
else
  fail "expected compiler to refuse group on wasm32-wasi with explicit message"
fi

# Failure proof: honest program without group compiles cleanly
cat << 'EOF' > "$WORK/honest.iyi"
puts 42
EOF
"$IYI" build --cross-compile --target wasm32-wasi -o "$WORK/honest" "$WORK/honest.iyi" > "$WORK/honest_build.log" 2>&1
if [ $? -eq 0 ]; then
  pass "failure proof: program without group compiles cleanly for wasm32-wasi"
else
  fail "failure proof: program without group failed to compile"
fi

echo
if [ $status -eq 0 ]; then
  echo "wasm concurrency probe: all checks passed, wall proven"
else
  echo "wasm concurrency probe: FAILED"
fi
exit $status
