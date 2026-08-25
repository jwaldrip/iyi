#!/usr/bin/env bash
# Runs iyi's front end as a wasm module in V8 and checks it reports the same
# diagnostic as the native front end, for the same source.
#
#     bash bench/wasm_front_end.sh
#
# This is the demo the website is pointed at: parsing, semantic analysis and
# iyi's real errors, in the visitor's browser, with no server and no backend of
# any kind. What it prints for a trait-bound violation is
#
#     In bad.iyi:11:6
#
#      11 | puts announce(42)
#                ^-------
#     Error: Int32 does not implement Samples::Bad::Greet, required by `T` in `announce`
#
# location, source line, caret and message, and it has to be the same bytes as
# the native run or the demo is showing something the compiler does not say.
#
# The front-end binary is the one built by `make crystal-front`: no LLVM, and
# `-Dwithout_llvm` selects a second entry point rather than a second build of
# the same one. Cross-compiled here for wasm32-wasi, linked with wasi-sdk's
# linker, and run under node's `node:wasi` on V8, the engine a browser has.
#
# Statuses, as in bench/wasm_exceptions.sh: 0 the two agree, 1 they do not, 2
# the question could not be asked. `WASM_FRONT_END_ALLOW_SKIP=1` turns a missing
# toolchain into exit 0 and the caller owns that.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CRYSTAL="${CRYSTAL_BIN:-$REPO/.build/crystal}"
WASI_SDK="${WASI_SDK:-/tmp/wasi-sdk}"
SYSROOT="$WASI_SDK/share/wasi-sysroot"
ALLOW_SKIP="${WASM_FRONT_END_ALLOW_SKIP:-}"
WORK="$(mktemp -d)"

missing() {
  if [ -n "$ALLOW_SKIP" ]; then
    echo "skipped: $1"
    exit 0
  fi
  echo "CANNOT CHECK: $1"
  exit 2
}

for needed in "$CRYSTAL" "$WASI_SDK/bin/wasm-ld" "$SYSROOT/lib/wasm32-wasi/crt1.o"; do
  [ -e "$needed" ] || missing "$needed is not here (set WASI_SDK, or run make crystal)"
done
command -v node >/dev/null 2>&1 || missing "no node to run the module in"
BUILTINS="$(ls "$WASI_SDK"/lib/clang/*/lib/wasi/libclang_rt.builtins-wasm32.a 2>/dev/null | head -1)"
[ -n "$BUILTINS" ] || missing "no wasm32 compiler-rt builtins in $WASI_SDK"

echo "engine: node $(node --version), V8 $(node -p 'process.versions.v8')"

# A trait-bound violation, which is the error iyi exists to give: `Int32` is
# handed to a method whose type parameter is bound by a trait it does not
# implement.
cat > "$WORK/bad.iyi" <<'PROGRAM'
module samples/bad

trait Greet
  abstract def hello : String
end

def announce(value : T) : String forall T : Greet
  value.hello
end

puts announce(42)
PROGRAM

cat > "$WORK/run.mjs" <<'RUNNER'
import { WASI } from "node:wasi";
import { readFile } from "node:fs/promises";
const [, , file, ...args] = process.argv;
const wasi = new WASI({
  version: "preview1",
  args: ["crystal-front", ...args],
  env: { IYI_PATH: process.env.IYI_PATH ?? "" },
  preopens: { "/": "/" },
  returnOnExit: true,
});
const inst = await WebAssembly.instantiate(
  await WebAssembly.compile(await readFile(file)),
  wasi.getImportObject(),
);
process.exitCode = wasi.start(inst);
RUNNER

export IYI_PATH="$REPO/src"
export CRYSTAL_PATH="$REPO/src"

# The host triple and the LLVM version are baked in from the compiler that has
# LLVM, because a front end has none to ask. Same as the Makefile's rule.
export IYI_CONFIG_TARGET="$("$CRYSTAL" --version | sed -n 's/^Default target: //p')"
export IYI_CONFIG_LLVM_VERSION="$("$CRYSTAL" --version | sed -n 's/^LLVM: //p')"

FRONT_FLAGS="-Dwithout_llvm -Dwithout_openssl -Dwithout_zlib -Dwithout_iconv"

if ! "$CRYSTAL" build $FRONT_FLAGS -o "$WORK/front" \
    "$REPO/src/compiler/crystal_front.cr" > "$WORK/native-build.log" 2>&1; then
  echo "building the native front end failed"
  tail -12 "$WORK/native-build.log"
  exit 1
fi

if ! "$CRYSTAL" build --cross-compile --target wasm32-wasi $FRONT_FLAGS \
    -o "$WORK/cfront" "$REPO/src/compiler/crystal_front.cr" \
    > "$WORK/cross.log" 2>&1; then
  echo "cross-compiling the front end for wasm32-wasi failed"
  tail -12 "$WORK/cross.log"
  exit 1
fi

if ! "$WASI_SDK/bin/wasm-ld" -L"$SYSROOT/lib/wasm32-wasi" \
    "$SYSROOT/lib/wasm32-wasi/crt1.o" "$WORK/cfront.wasm" -lc "$BUILTINS" \
    -o "$WORK/cfront.linked.wasm" > "$WORK/link.log" 2>&1; then
  echo "linking the front end for wasm32-wasi failed"
  tail -12 "$WORK/link.log"
  exit 1
fi

# `--no-warnings` because node prints an ExperimentalWarning about WASI to
# stderr, and this comparison is about what the compiler said.
"$WORK/front" "$WORK/bad.iyi" > "$WORK/native.txt" 2>&1
node --no-warnings "$WORK/run.mjs" "$WORK/cfront.linked.wasm" "$WORK/bad.iyi" > "$WORK/wasm.txt" 2>&1

status=0

if diff -q "$WORK/native.txt" "$WORK/wasm.txt" > /dev/null; then
  echo "the wasm front end says what the native one says:"
  sed 's/^/  /' "$WORK/wasm.txt"
else
  echo "DIAGNOSTICS DIFFER"
  diff "$WORK/native.txt" "$WORK/wasm.txt"
  status=1
fi

# The diagnostic, not just any output: a location, a caret and the trait name.
# Without these three the check would pass on two identical crashes, or on two
# empty files.
for expected in 'bad\.iyi:11:6' '\^-------' 'does not implement .*Greet'; do
  if ! grep -Eq "$expected" "$WORK/wasm.txt"; then
    echo "the wasm output has no /$expected/"
    status=1
  fi
done

echo "module: $(wc -c < "$WORK/cfront.linked.wasm") bytes (debug build)"
echo "workdir $WORK"
exit $status
