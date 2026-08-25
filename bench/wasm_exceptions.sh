#!/usr/bin/env bash
# Checks that `begin`/`rescue` works on wasm32-wasi, by running the same program
# natively and in a wasm engine and comparing what it prints.
#
#     bash bench/wasm_exceptions.sh
#
# The program is three lines and it is the whole point:
#
#     puts "before"
#     begin
#       raise "boom"
#     rescue ex
#       puts "rescued: #{ex.message}"
#     end
#     puts "after"
#
# Before wasm exception handling existed in this compiler, the wasm run printed
# "EXITING: Attempting to raise:" and stopped, because `src/raise.cr` on wasm32
# printed the exception and called `LibC.exit(1)`. There was no unwinding, so
# `rescue` did not run on that target at all.
#
# The engine is node's `node:wasi`, a JavaScript WASI implementation on V8 —
# the same engine a browser runs — rather than a native runtime, because the
# reason any of this exists is a compiler that runs in a browser.
#
# Needs: a built compiler (`make crystal`), a wasi-sdk sysroot for the link, and
# node. Set WASI_SDK to point at the sdk; it defaults to /tmp/wasi-sdk.
#
# On a laptop without wasi-sdk this skips with status 0, because a machine that
# cannot build the module cannot answer the question either way. **In CI that
# skip is a green check covering nothing**, so CI sets
# `WASM_EXCEPTIONS_REQUIRE=1` and every skip below becomes a failure. Exits
# non-zero whenever the answer is no.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CRYSTAL="${CRYSTAL_BIN:-$REPO/.build/crystal}"
WASI_SDK="${WASI_SDK:-/tmp/wasi-sdk}"
SYSROOT="$WASI_SDK/share/wasi-sysroot"
REQUIRE="${WASM_EXCEPTIONS_REQUIRE:-}"
WORK="$(mktemp -d)"

# Absent toolchain: a skip where a person is asking, a failure where a check is
# claiming to have run.
missing() {
  if [ -n "$REQUIRE" ]; then
    echo "FAILED: $1, and WASM_EXCEPTIONS_REQUIRE is set, so this check has to run"
    exit 1
  fi
  echo "skipped: $1"
  exit 0
}

for needed in "$CRYSTAL" "$WASI_SDK/bin/wasm-ld" "$SYSROOT/lib/wasm32-wasi/crt1.o"; do
  [ -e "$needed" ] || missing "$needed is not here (set WASI_SDK, or run make crystal)"
done

command -v node >/dev/null 2>&1 || missing "no node to run the module in"

BUILTINS="$(ls "$WASI_SDK"/lib/clang/*/lib/wasi/libclang_rt.builtins-wasm32.a 2>/dev/null | head -1)"
[ -n "$BUILTINS" ] || missing "no wasm32 compiler-rt builtins in $WASI_SDK"

echo "engine: node $(node --version), V8 $(node -p 'process.versions.v8')"

cat > "$WORK/exc.cr" <<'PROGRAM'
puts "before"
begin
  raise "boom"
rescue ex
  puts "rescued: #{ex.message}"
end
puts "after"
PROGRAM

# A JS WASI host, which is what a browser would supply. `returnOnExit` so a
# non-zero status is a value rather than a thrown error.
cat > "$WORK/run.mjs" <<'RUNNER'
import { WASI } from "node:wasi";
import { readFile } from "node:fs/promises";
const file = process.argv[2];
const wasi = new WASI({ version: "preview1", args: [file], env: {}, returnOnExit: true });
const inst = await WebAssembly.instantiate(
  await WebAssembly.compile(await readFile(file)),
  wasi.getImportObject(),
);
process.exitCode = wasi.start(inst);
RUNNER

export IYI_PATH="$REPO/src"
export CRYSTAL_PATH="$REPO/src"

status=0

if ! "$CRYSTAL" run --no-color "$WORK/exc.cr" > "$WORK/native.txt" 2> "$WORK/native.log"; then
  echo "the native run failed"
  tail -5 "$WORK/native.log"
  exit 1
fi

if ! "$CRYSTAL" build --cross-compile --target wasm32-wasi -o "$WORK/exc" "$WORK/exc.cr" > "$WORK/cross.log" 2>&1; then
  echo "cross-compiling for wasm32-wasi failed"
  tail -12 "$WORK/cross.log"
  exit 1
fi

# The link the compiler itself prints, with wasi-sdk's linker rather than a
# `cc` that may not have a wasm target. No `-nostartfiles`: `crt1.o` owns
# `_start` and the stdlib no longer defines a second one.
if ! "$WASI_SDK/bin/wasm-ld" -L"$SYSROOT/lib/wasm32-wasi" \
    "$SYSROOT/lib/wasm32-wasi/crt1.o" "$WORK/exc.wasm" -lc "$BUILTINS" \
    -o "$WORK/exc.linked.wasm" > "$WORK/link.log" 2>&1; then
  echo "linking for wasm32-wasi failed"
  tail -12 "$WORK/link.log"
  exit 1
fi

if ! node "$WORK/run.mjs" "$WORK/exc.linked.wasm" > "$WORK/wasm.txt" 2> "$WORK/wasm.log"; then
  echo "the wasm run failed"
  tail -12 "$WORK/wasm.log"
  cat "$WORK/wasm.txt"
  exit 1
fi

if diff -q "$WORK/native.txt" "$WORK/wasm.txt" > /dev/null; then
  echo "same output natively and on wasm32-wasi:"
  sed 's/^/  /' "$WORK/wasm.txt"
else
  echo "OUTPUT DIFFERS"
  diff "$WORK/native.txt" "$WORK/wasm.txt"
  status=1
fi

# A tag definition rather than an import, and no unwinder: what the module asks
# the host for is WASI and nothing else. If `__cpp_exception` ever shows up here
# as an import, the module has stopped being self-contained.
imports="$(node -e '
  const fs = require("fs");
  const mod = new WebAssembly.Module(fs.readFileSync(process.argv[1]));
  const names = WebAssembly.Module.imports(mod).map((i) => i.module);
  console.log([...new Set(names)].sort().join(" "));
' "$WORK/exc.linked.wasm")"

if [ "$imports" = "wasi_snapshot_preview1" ]; then
  echo "imports only wasi_snapshot_preview1"
else
  echo "UNEXPECTED IMPORTS: $imports"
  status=1
fi

echo "workdir $WORK"
exit $status
