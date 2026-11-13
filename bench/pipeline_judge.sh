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
# A port-tool run on a compiler root is stopped above 6 GiB resident (PORT_RSS_LIMIT_KIB overrides).
# The memory guard is not the bound. The rc line is runaway when this script stops the process.
run_port() {
  rc_name="$1"
  out="$2"
  err="$3"
  shift 3
  IYI_PATH="$ROOT/src" "$OUT/tool" "$@" > "$out" 2> "$err" &
  pid=$!
  limit="${PORT_RSS_LIMIT_KIB:-$((6 * 1024 * 1024))}"
  runaway=0
  while kill -0 "$pid" 2>/dev/null; do
    rss=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1}')
    if [ -n "${rss:-}" ] && [ "$rss" -gt "$limit" ]; then
      kill -9 "$pid" 2>/dev/null || true
      runaway=1
      break
    fi
    sleep 0.5
  done
  wait "$pid" 2>/dev/null
  rc=$?
  if [ "$runaway" -eq 1 ]; then
    echo "${rc_name}=runaway"
  else
    echo "${rc_name}=$rc"
  fi
}
echo "== 3. port: the names and the refusal sidecar, under --keep-going"
run_port hello_port_rc "$OUT/hello.probe" "$OUT/hello.err" \
  samples/iyi/hello.iyi -o "$OUT/hello-port" --pipeline typed --prelude --probe-phase --keep-going
run_port cn_port_rc "$OUT/cn.probe" "$OUT/cn.err" \
  src/compiler/tools/compile_native.iyi -o "$OUT/cn-port" --pipeline typed --prelude --probe-phase --keep-going
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
