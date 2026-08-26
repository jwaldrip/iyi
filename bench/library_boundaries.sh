#!/usr/bin/env bash
# Binds pieces of Crystal's own library as boundaries and consumes each.
#
# `bench/yaml_reads.sh` does this for one namespace and holds one claim about
# it. This asks the same question of several, because what a boundary breaks on
# depends on what the namespace *holds*: `JSON` is types and methods, `URI` is
# a struct with a lot of parsing behind it, and `Log` is global state written
# by macros — a private constant, a class variable with a live initialiser, and
# two `{% for %}` loops that write a method of the same name on both sides of
# the class.
#
# `Log` is the one that found things, and it found four. `tool bind` died on it
# with a stack overflow and no diagnosis. A parameter written `Class` is every
# metaclass there is and there is no end to them. A class variable the library
# declares was declared a second time here, so the initialiser that runs was
# not the one the artifact carried. And `MonoBodies` was keyed without the side
# of the type, so `Log.info`'s body took `Log#info`'s key.
#
# `Path` and `Time` arrived later and found one thing between them: a constant
# has two spellings, and which one a build picks is a fact about that build's
# order rather than about the constant. See the comment above them.
#
#     bash bench/library_boundaries.sh
#
# Needs `make`. Nothing here reaches the network: what it binds is in this
# checkout.
#
# Exits non-zero if any bind or fill fails, or if any consumer answers
# differently from the same program built from source.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CRYSTAL="$REPO/bin/crystal"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
cd "$WORK" || exit 1

export CRYSTAL_PATH="$REPO/src"
export IYI_PATH="$REPO/share/iyi/src:$REPO/share/iyi/crystal:$REPO/src"

status=0

# root | require | module name | program
check() {
  root="$1"; req="$2"; mod="$3"; program="$4"
  dir="$WORK/$mod"
  mkdir -p "$dir"
  (
    cd "$dir" || exit 1
    printf 'require "%s"\n' "$req" > probe.cr

    if ! "$CRYSTAL" tool bind -e "$root" --emit-bind mods probe.cr > bind.log 2>&1; then
      echo "$root: binding failed"
      tail -8 bind.log
      exit 1
    fi

    if ! (cd mods && "$CRYSTAL" build --iyi-keep "$root" --emit-bind . \
            -o keep "${mod}_keep.cr" > fill.log 2>&1); then
      echo "$root: filling failed"
      tail -8 mods/fill.log
      exit 1
    fi

    printf 'module main\n\nrequire "%s"\n\n%s\n' "$req" "$program" > a_src.iyi
    printf 'module main\n\nimport %s\n\n%s\n' "$mod" "$program" > a_art.iyi

    if ! "$IYI" run --crystal a_src.iyi > out_src.txt 2>&1; then
      echo "$root: the source arm failed"
      tail -8 out_src.txt
      exit 1
    fi

    if ! "$IYI" run --crystal --use-iyimod mods a_art.iyi > out_art.txt 2>&1; then
      echo "$root: the artifact arm failed"
      tail -8 out_art.txt
      exit 1
    fi

    if ! diff -q out_src.txt out_art.txt > /dev/null; then
      echo "$root: THE TWO ARMS ANSWER DIFFERENTLY"
      diff out_src.txt out_art.txt | head -8
      exit 1
    fi

    echo "  $root — $(tr '\n' ' ' < out_art.txt)"
  ) || status=1
}

echo "bound from the library, and consumed:"

check JSON json j_s_o_n 'v = JSON.parse(%q({"a":[1,2,3],"b":"x"}))
puts v["b"]
puts v["a"].as_a.size'

check URI uri u_r_i 'u = URI.parse("https://iyi.example/a/b?q=1#frag")
puts u.host
puts u.path
puts u.query'

# The formatter is written out so the line carries no clock: a gate that
# compares two runs cannot compare timestamps taken seconds apart. The
# dispatcher is synchronous for the same kind of reason — the default hands the
# write to a fiber, and a gate that read the buffer first would compare two
# empty strings and call it a match.
#
# The `debug` line is the half that says the *level* crossed: it must not
# appear, and a boundary that lost `Log::Severity`'s numbering would let it.
check Log log log 'io = IO::Memory.new
backend = Log::IOBackend.new(io, dispatcher: Log::DispatchMode::Sync)
backend.formatter = Log::Formatter.new { |entry, dest| dest << entry.severity.to_s << " " << entry.source << " " << entry.message }
Log.setup(:info, backend)
Log.for("x").info { "hello" }
Log.for("x").debug { "not this one" }
puts io.to_s.strip'

# Two the boundary could not carry until it learned that a constant has two
# spellings. `Path` reads `Iterator::Stop::INSTANCE` from its `PartIterator`
# unit and `Time` reads `Time::Span::ZERO`; both are reached through
# `~NAME:const_read`, a function the producer emitted because *its* units read
# them before initialising them, and which the consumer had no reason to write
# — it initialises them from its own program, in its own order, and emits a
# plain global. `undefined symbol`, in a program whose own source names no
# iterator.
#
# `Time` is also the case that says an enum and a struct with arithmetic on it
# cross: `day_of_week` is an enum read back by name, and `total_hours` is a
# `Time::Span` divided out. The clock is never asked — every value here is
# written down — because a gate that compares two runs cannot compare two
# readings of `Time.utc`.
check Path path path 'p = Path.posix("/a/b/c.txt")
puts p.basename
puts p.extension
puts p.parent
puts (p / "d").to_s'

check Time time time 't = Time.utc(2026, 8, 26, 13, 5, 0)
puts t.to_s("%Y-%m-%d %H:%M:%S")
puts (t + 3.days).day
puts (t - Time.utc(2026, 8, 20)).total_hours
puts t.day_of_week'

if [ "$status" -eq 0 ]; then
  echo "every boundary answers what its source does"
fi

echo "workdir $WORK"
exit $status
