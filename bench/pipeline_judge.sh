#!/usr/bin/env bash
# The judge of the pipeline lane, on one commit. Run from the checkout it judges (cwd), after `make` so that ./bin/iyi
# is the hosted compiler built from this checkout. Writes everything under $OUT (default /tmp/iyi-pipeline-judge).
#
#   bash bench/pipeline_judge.sh
#   OUT=/tmp/somewhere bash bench/pipeline_judge.sh
#
# The hosted IR comes from the hosted compiler in this checkout, so both sides of the coverage line are built from
# the same commit. Prints, for each root (samples/iyi/hello.iyi and src/compiler/tools/compile_native.iyi): the
# coverage line, the frontier's status line, the breakdown by name shape and by owner, and the frontier's top 12
# refusals beside the clean callers that never asked for a hosted callee.
set -u
OUT="${OUT:-/tmp/iyi-pipeline-judge}"
mkdir -p "$OUT"
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin LIBRARY_PATH=/opt/homebrew/opt/bdw-gc/lib
ROOT="$(pwd -P)"
echo "checkout $ROOT head $(git rev-parse --short HEAD)"
echo "== 1. port tool from this commit (the hosted compiler builds it)"
./bin/iyi build -o "$OUT/tool" src/compiler/tools/compile_native.iyi > "$OUT/tool.build.log" 2>&1
echo "tool_build_rc=$?"
echo "== 2. hosted IR, hello and the compiler's own root"
./bin/iyi build --no-debug --emit llvm-ir -o "$OUT/hello-hosted" samples/iyi/hello.iyi > "$OUT/hello-hosted.log" 2>&1
echo "hello_hosted_rc=$?"
./bin/iyi build --no-debug --emit llvm-ir -o "$OUT/cn-hosted" src/compiler/tools/compile_native.iyi > "$OUT/cn-hosted.log" 2>&1
echo "cn_hosted_rc=$?"
hosted_ll() { if [ -f "$1.ll" ]; then echo "$1.ll"; else echo "$1"; fi; }
HELLO_LL="$(hosted_ll "$OUT/hello-hosted")"
CN_LL="$(hosted_ll "$OUT/cn-hosted")"
echo "== 3. port: the names and the refusal sidecar, under --keep-going"
IYI_PATH="$ROOT/src" "$OUT/tool" samples/iyi/hello.iyi -o "$OUT/hello-port" --pipeline typed --prelude --probe-phase --keep-going > "$OUT/hello.probe" 2> "$OUT/hello.err"
echo "hello_port_rc=$?"
IYI_PATH="$ROOT/src" "$OUT/tool" src/compiler/tools/compile_native.iyi -o "$OUT/cn-port" --pipeline typed --prelude --probe-phase --keep-going > "$OUT/cn.probe" 2> "$OUT/cn.err"
echo "cn_port_rc=$?"
echo "== 4. coverage line, the frontier and the breakdown"
python3 bench/pipeline_coverage.py "$HELLO_LL" "$OUT/hello-port.names" samples/iyi/hello.iyi > "$OUT/hello.coverage" 2>&1
python3 bench/pipeline_coverage.py "$CN_LL" "$OUT/cn-port.names" src/compiler/tools/compile_native.iyi > "$OUT/cn.coverage" 2>&1
python3 bench/pipeline_frontier.py "$HELLO_LL" "$OUT/hello-port.names" "$OUT/hello-port.refusals" hello 12 > "$OUT/hello.frontier" 2>&1
python3 bench/pipeline_frontier.py "$CN_LL" "$OUT/cn-port.names" "$OUT/cn-port.refusals" compile_native 12 > "$OUT/cn.frontier" 2>&1
python3 bench/pipeline_breakdown.py "$HELLO_LL" "$OUT/hello-port.names" "$OUT/hello-port.refusals" hello > "$OUT/hello.breakdown" 2>&1
python3 bench/pipeline_breakdown.py "$CN_LL" "$OUT/cn-port.names" "$OUT/cn-port.refusals" compile_native > "$OUT/cn.breakdown" 2>&1
awk '/^table:/ && !/missing:/' "$OUT/hello.coverage" "$OUT/cn.coverage"
awk '/^frontier:/ && !/clean-caller=/' "$OUT/hello.breakdown" "$OUT/cn.breakdown"
awk '/^frontier:/ && !/clean-caller=/' "$OUT/hello.frontier" "$OUT/cn.frontier"
awk '/^breakdown:/' "$OUT/hello.breakdown" "$OUT/cn.breakdown" > "$OUT/breakdown.txt"
echo "judge_done"
