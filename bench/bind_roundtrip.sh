#!/usr/bin/env bash
# Binds a Crystal shard, builds a program against the boundary, and checks it
# prints what the same program prints built against the shard's source.
#
# `bench/samples_roundtrip.sh` asks R-1's question of iyi's own modules. This
# asks it of the other kind of artifact — one whose object code is a shard's,
# whose declarations `crystal tool bind` wrote, and whose consumer is a
# `--crystal` program. SPEC.md III.6 rule 1 names two failures for a boundary
# whose signatures are wrong: an undefined symbol, or a call that returns
# something of another type. `spec/compiler/bind_spec.cr` stops before both of
# them on purpose — it reads the declarations back and never links — so until
# this ran, nothing did.
#
#     bash bench/bind_roundtrip.sh
#
# Needs `make` (both the compiler and `iyi`). Exits non-zero if binding fails,
# if either arm fails to build or link, or if the two print differently.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CRYSTAL="$REPO/bin/crystal"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"

# Four methods, and each is a shape this boundary got wrong once.
#
# `step` writes both its types and is what a shard is supposed to look like.
#
# `wider` is the one that made this file necessary. Crystal narrows a return
# restriction to what the body produced, so this method's symbol is named
# `:String` while the restriction says `String?`. A boundary repeating the
# restriction has the consumer ask for a symbol nobody emitted, and the failure
# is `ld.lld: error: undefined symbol` at the end of a build that had no other
# complaint. What travels is the answer, and this is the case that says so.
#
# `discards` is the opposite mistake, from the first version of the check that
# found `wider`: `: Nil` throws away whatever the body produced, so a check
# reading the *body* calls this broken when it is not. It has to keep crossing.
#
# Its `IO` is the second thing this round trip found. A parameter whose type is
# abstract is emitted once, against the declaration, and a consumer passing a
# `STDOUT` used to ask for `discards<IO::FileDescriptor>` — a symbol nobody
# wrote. The declaration is the contract now and the call is keyed on it, so
# this line is the regression test for that as much as for `: Nil`.
#
# `untyped_return` writes no return type at all, which is the half of rule 1
# that was always instantiated. It is here so the two halves are checked by one
# program.
#
# `bump` reads a class variable, which is a *global*. Its global is defined in
# the main module of whatever build compiled it, and a main module is the one
# part of a build that never travels — so the method arrived as machine code
# referring to `Shard::Part::count`, a symbol nothing defined. Nothing carried
# class variables at all: not this boundary and not a `.iyimod` written from
# iyi's own source, where the same hole made R-1's claim false for any module
# that had one.
#
# `each` takes a block, and a block-taking method's machine code is the
# caller's by design (IV.1g) — the producer emits each instantiation private to
# the unit that called it, so no symbol for one leaves the artifact. Its body
# has to travel instead. It did not, for anything but a generic type, and this
# line is what said so: `undefined symbol:
# *Shard::Part#each<&Proc(Int32, Nil)>`.
cat > "$WORK/shard.cr" <<'CR'
module Shard
  extend self

  class Part
    @seed : Int32
    @@count = 0

    def initialize(@seed : Int32)
    end

    def step(n : Int32) : Int32
      (n + @seed) % 1000
    end

    def wider : String?
      "part-" + @seed.to_s
    end

    def discards(io : IO) : Nil
      io << "seed=" << @seed
    end

    def untyped_return(n : Int32)
      n * @seed
    end

    def each(& : Int32 -> Nil) : Nil
      yield @seed
      yield @seed + 1
    end

    def bump : Int32
      @@count = @@count + 1
      @@count
    end
  end

  def make(seed : Int32) : Part
    Part.new(seed)
  end
end
CR

printf 'require "./shard"\n' > "$WORK/entry.cr"

# The consumer calls all of it, because codegen is demand-driven: a symbol
# nobody reaches is a symbol the linker is never asked for, and a round trip
# that reaches nothing proves nothing.
cat > "$WORK/app_source.iyi" <<'IYI'
module main

require "./shard"

part = Shard::Part.new(7)
puts part.step(5)
puts part.wider
part.discards(STDOUT)
puts ""
puts part.untyped_return(3)
total = 0
part.each do |v|
  total = total + v
end
puts total
puts part.bump
puts part.bump
puts Shard.make(11).step(1)
IYI

sed 's|require "./shard"|import shard|' "$WORK/app_source.iyi" > "$WORK/app_artifact.iyi"

cd "$WORK" || exit 1
mkdir mods
status=0

# The declarations. `--emit-bind` writes the artifact and the keep file beside
# it; the keep file is where the per-type units come from.
if ! "$CRYSTAL" tool bind -e Shard --emit-bind mods entry.cr > bind.log 2>&1; then
  echo "binding the shard failed"
  tail -12 bind.log
  echo "workdir $WORK"
  exit 1
fi
sed -n '/written returns/,/^$/p' bind.log

# The object code. A getter whose body is one instance variable is inlined and
# emits no symbol, which is why this build is `--iyi-keep` rather than ordinary.
if ! (cd mods && "$CRYSTAL" build --iyi-keep Shard --emit-bind . \
        -o keepbin shard_keep.cr > fill.log 2>&1); then
  echo "filling the artifact failed"
  tail -12 mods/fill.log
  echo "workdir $WORK"
  exit 1
fi

# `--crystal` on both arms. A bound shard's artifact says it was built against
# Crystal's standard library, because it was, and a program cannot hold one
# module of each.
for arm in source artifact; do
  build_cmd=("$IYI" build --crystal)
  if [ "$arm" = artifact ]; then
    build_cmd+=(--use-iyimod mods)
  fi
  build_cmd+=(-o "out_$arm" "app_$arm.iyi")

  if ! "${build_cmd[@]}" > "build-$arm.log" 2>&1; then
    echo "$arm: build failed"
    tail -12 "build-$arm.log"
    status=1
    continue
  fi
  "./out_$arm" > "out-$arm.txt" 2>&1
done

if [ -f out-source.txt ] && [ -f out-artifact.txt ]; then
  if diff -q out-source.txt out-artifact.txt > /dev/null; then
    echo "the boundary and the source print the same thing"
  else
    echo "OUTPUT DIFFERS"
    diff out-source.txt out-artifact.txt | head -10
    status=1
  fi
fi

echo "workdir $WORK"
exit $status
