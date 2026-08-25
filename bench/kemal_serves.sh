#!/usr/bin/env bash
# Serves a kemal application through four `.iyimod` boundaries.
#
# `bench/shard_serves.sh` proves a program that *requires* kemal serves, which
# is the direct source mode: one build, the shard compiled from source beside
# the program. `bench/bind_chain.sh` proves four boundaries carry enough for a
# consumer to *add a route*, which reaches the router and stops there.
#
# Neither reaches the thing the boundary exists for. A route added by hand is a
# method call; what a kemal user writes is `get "/" do … end`, and answering it
# means the DSL crossed, `Kemal.run` crossed with its body, the handler chain
# ran in kemal's own order, and everything the shard added to
# `HTTP::Server::Context` — a class the *library* owns — arrived with it. Each
# of those failed separately on the way here, and each failed *quietly*: a
# consumer that linked and then read a field nobody had allocated, a
# `class.to_s` that answered the wrong type for seven handlers in a row, a
# `new` that never ran an `initialize`. A gate that stops at "it compiles"
# would have been green through all of them.
#
#     bash bench/kemal_serves.sh
#
# Needs `make`, `shards`, `curl` and the network. The shard is pinned, so what
# it fetches is one version rather than whatever is current.
#
# Exits non-zero if any bind or fill fails, if either arm fails to build, if
# either server does not come up, or if the two answer differently.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CRYSTAL="$REPO/bin/crystal"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"

KEMAL_VERSION="1.12.0"

# One port per arm, high and fixed. A random port makes a failure
# unreproducible; two ports mean the arms can be read side by side without one
# waiting on the other's socket to close.
PORT_SOURCE=31881
PORT_ARTIFACT=31882

# `kill` and then `wait`, both inside a group whose stderr is closed. The shell
# announces a signalled job when it reaps one — `Killed` on a line of its own —
# and that is job control talking about this script rather than anything the
# gate measured.
stop_server() {
  [ -z "${SERVER_PID:-}" ] && return
  { kill -9 "$SERVER_PID"; wait "$SERVER_PID"; } 2>/dev/null
  SERVER_PID=""
}

cleanup() {
  stop_server
}
trap cleanup EXIT

for tool in shards curl; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "needs $tool, which is not on the PATH"
    exit 1
  fi
done

cat > "$WORK/shard.yml" <<YML
name: kemal_serves
version: 0.1.0
dependencies:
  kemal:
    github: kemalcr/kemal
    version: $KEMAL_VERSION
YML

cd "$WORK" || exit 1

if ! shards install > install.log 2>&1; then
  echo "installing the shard failed"
  tail -12 install.log
  echo "workdir $WORK"
  exit 1
fi

# Absolute, because the fill build runs with `mods` as its working directory
# and a relative `lib` would resolve under it.
export CRYSTAL_PATH="$WORK/lib:$REPO/src"
export IYI_PATH="$WORK/lib:$REPO/share/iyi/src:$REPO/share/iyi/crystal:$REPO/src"

mkdir mods

# In dependency order, and each boundary built against the ones before it. See
# `bench/bind_chain.sh`, which explains why both halves of that matter.
bind_one() {
  shard="$1"; root="$2"
  if ! "$CRYSTAL" tool bind -e "$root" --emit-bind mods --use-iyimod mods \
        "lib/$shard/src/$shard.cr" > "bind-$shard.log" 2>&1; then
    echo "binding $shard failed"
    tail -10 "bind-$shard.log"
    echo "workdir $WORK"
    exit 1
  fi
  if ! (cd mods && "$CRYSTAL" build --iyi-keep "$root" --emit-bind . \
          -o "keep_$shard" "${shard}_keep.cr" > "fill-$shard.log" 2>&1); then
    echo "filling $shard failed"
    tail -10 "mods/fill-$shard.log"
    echo "workdir $WORK"
    exit 1
  fi
  echo "  bound $shard"
}

echo "bound, in dependency order:"
bind_one backtracer Backtracer
bind_one radix Radix
bind_one exception_page ExceptionPage
bind_one kemal Kemal

# The application, written the way kemal's own README writes one. `get` is a
# top-level `def` a macro loop writes, and the block returns `_` — so neither
# the method nor its body has a symbol, and both travel as text for the
# consumer to compile. The second route reads a URL parameter, which is what
# makes `HTTP::Server::Context`'s `@params` load-bearing: kemal adds that field
# to a class the library owns, and a boundary carries none of the library's
# types.
#
# `Kemal.run` is written with no block, which is how kemal's README writes it —
# the overload that takes none has an untyped `args` and delegates, so it
# crosses as its body (SPEC.md Part V item 12). Written `Kemal.run { }` this
# line would pass without saying that.
app() {
  cat <<IYI
module main

$1

get "/" do |env|
  "hello from a boundary"
end

get "/echo/:word" do |env|
  env.params.url["word"]
end

Kemal.config_instance.port = $2
Kemal.run
IYI
}

app 'require "kemal"' "$PORT_SOURCE" > app_source.iyi
app "import kemal" "$PORT_ARTIFACT" > app_artifact.iyi

# `Kemal.config` is a module function in the source arm and a constant
# accessor in the artifact — a constant is storage, and a declaration can name
# a type but not a global somebody else's object file holds (SPEC.md Part V
# item 12). One line, and it is the only difference between the two files.
sed -i 's/Kemal\.config_instance/Kemal.config/' app_source.iyi

status=0
for arm in source artifact; do
  port_var="PORT_$(echo "$arm" | tr '[:lower:]' '[:upper:]')"
  port="${!port_var}"

  build_cmd=("$IYI" build --crystal)
  if [ "$arm" = artifact ]; then
    build_cmd+=(--use-iyimod mods)
  fi
  build_cmd+=(-o "out_$arm" "app_$arm.iyi")

  if ! "${build_cmd[@]}" > "build-$arm.log" 2>&1; then
    echo "$arm: build failed"
    grep -oE '(undefined|duplicate) symbol: .*' "build-$arm.log" | sort -u | head -10
    grep -m3 -E '^Error' "build-$arm.log"
    status=1
    continue
  fi

  "./out_$arm" > "server-$arm.log" 2>&1 &
  SERVER_PID=$!

  # Polled, not slept: a fixed sleep is a flake on a slow machine and wasted
  # seconds on a fast one.
  ready=""
  for _ in $(seq 1 100); do
    if curl -s --max-time 2 "http://127.0.0.1:$port/" > /dev/null 2>&1; then
      ready=yes
      break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done

  if [ -z "$ready" ]; then
    echo "$arm: the server never answered on port $port"
    tail -12 "server-$arm.log"
    status=1
    stop_server
    continue
  fi

  {
    curl -s --max-time 5 "http://127.0.0.1:$port/"
    echo ""
    curl -s --max-time 5 "http://127.0.0.1:$port/echo/iyi"
    echo ""
    # A route nobody wrote. 404 is kemal's own `setup_404`, which `Kemal.run`
    # reaches through a private module function whose body travels — so this
    # line is the one that says the *unhappy* path crossed too.
    curl -s --max-time 5 -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:$port/missing"
  } > "answers-$arm.txt"

  stop_server
done

if [ -f answers-source.txt ] && [ -f answers-artifact.txt ]; then
  if diff -q answers-source.txt answers-artifact.txt > /dev/null; then
    echo "four boundaries, and a kemal application answers what the source does"
    sed 's/^/  /' answers-artifact.txt
  else
    echo "THE TWO ARMS ANSWER DIFFERENTLY"
    diff answers-source.txt answers-artifact.txt | head -10
    status=1
  fi
fi

echo "workdir $WORK"
exit $status
