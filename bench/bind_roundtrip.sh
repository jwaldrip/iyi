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

  # On the module rather than on a type inside it, which is a different place
  # for the format to have to put it: a module is not a `TypeDecl`. Kemal's
  # `backtracer` is where this was found — `module Backtracer;
  # class_getter(configuration)` left `Backtracer::configuration` undefined at
  # the end of a build that had every one of that shard's types and their class
  # variables.
  @@made = 0

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

    # A union the consumer never forms, checked against a union restriction.
    # `is_a?` against a union compiles to `~match<(Char | Int32)>`, a function
    # that compares a type id against the *program's* numbering — so it is the
    # main module's and the main module does not travel. A virtual type the
    # consumer could have found for itself by taking the virtual form of every
    # class it numbers; a union it cannot, because no walk over a program
    # arrives at one its own code never wrote.
    def kind(n : Int32) : String
      v = n > 1 ? 1 : (n > 0 ? 'x' : "s")
      v.is_a?(Char | Int32) ? "small" : "other"
    end
  end

  # Inheritance, which a boundary lost entirely: `TypeDecl` had no field for
  # the `<`, so `Derived` arrived without its base *and* without the fields it
  # inherits — a subclass's own field list is only its own. The consumer said
  # `undefined method 'tag' for Shard::Derived`.
  #
  # Three separate things had to follow the edge. A method is keyed on the type
  # that *defines* it, because a boundary has one symbol per method and not one
  # per receiver. That symbol is keyed on the class's *virtual* form, because a
  # value of a class something inherits from is held as one. And a class with
  # subclasses has a second unit — `Shard::Base+` — which is where the methods
  # reached through that form are emitted, and which the artifact was not
  # carrying at all.
  class Base
    @tag : String

    def initialize(@tag : String)
    end

    def tag : String
      @tag
    end

    def describe : String
      "base:" + @tag
    end
  end

  # A second subclass, so that a method answering either of them answers the
  # base's *virtual* type rather than one concrete class. See `pick`.
  class Other < Base
    def initialize(tag : String)
      super(tag)
    end

    def describe : String
      "other:" + @tag
    end
  end

  class Derived < Base
    @extra : Int32

    def initialize(tag : String, @extra : Int32)
      super(tag)
    end

    def extra : Int32
      @extra
    end

    # Overridden, so the two halves of dispatch are both checked: the inherited
    # `tag` comes from the base's unit and this one does not.
    def describe : String
      "derived:" + @tag + ":" + @extra.to_s
    end

    # A body that names this shard's own constants the way the shard wrote them
    # — absolutely — and it has to be on a *type*, which is the path that was
    # broken. The declarations are read inside a module whose root has been
    # stripped, so `Shard::TAG` there is the module's *public* name and R-2
    # answers for it: `Shard does not export Shard::TAG`. A module function's
    # body already took this rewrite; a type's did not, and the first version
    # of this check put the method on the module and passed either way.
    #
    # It takes a block for a second reason: that is what makes the body travel
    # at all. A method whose machine code is in the artifact never has its text
    # read by anybody.
    def tagged(&)
      yield Shard::TAG + ":" + Shard::Inner::DEPTH.to_s
    end
  end

  def self.derived(tag : String, extra : Int32) : Derived
    Derived.new(tag, extra)
  end

  # An abstract class, whose concrete methods are the third thing whose body
  # has to travel — beside a generic's and a block-taker's, and for the same
  # reason each time: they are instantiated per *subclass*, and the subclass is
  # the consumer's. A shard that declares one and never subclasses it carries
  # **no machine code for it at all**, which is why `exception_page` fills with
  # 0 units and why that is not a bug.
  abstract class Sheet
    abstract def title : String

    def render : String
      "[" + title + "]"
    end
  end

  # A non-generic type nested inside a generic one. The keep file skipped a
  # generic — rightly, since `uninitialized Holder(T)` is not a thing anybody
  # can write — and skipped everything it declared along with it. Those have
  # units in the artifact all the same, so radix's keep file was empty while
  # its two error classes carried 1.3 MB each, and the only `to_s` symbols it
  # emitted were the ones its own code happened to reach: a consumer asking
  # for the declared `to_s<IO+>` found nothing.
  class Holder(T)
    @value : T
    @tag : String

    # A default, and it travels. A generic's `new` is synthesised per
    # instantiation and never carried, so its `initialize` is what a consumer
    # builds one with — and a call that leaves an argument out meets a
    # declaration that has to know it could.
    def initialize(@value : T, @tag : String = "plain")
    end

    def tag : String
      @tag
    end

    def value : T
      @value
    end

    class Note
      @text : String

      def initialize(@text : String)
      end

      # An abstract parameter, so the symbol is the declared one and not one
      # per argument type — which is what made the gap visible.
      def write(io : IO) : Nil
        io << "note:" << @text
      end
    end
  end

  def self.note(text : String) : Holder::Note
    Holder::Note.new(text)
  end

  # A nested namespace, which a boundary used to drop whole and report as a
  # "nested namespace skipped". What that cost only shows at a shard's scale:
  # `Kemal::Exceptions` holds four exception classes, each with an object-code
  # unit in the artifact, so a consumer linked their machine code and had none
  # of the classes. A module is also a type — the object code numbers one — and
  # a consumer that cannot name it cannot number it.
  module Inner
    DEPTH = 2

    class Deep
      @tag : String

      def initialize(@tag : String)
      end

      def tag : String
        @tag
      end
    end

    def self.deep(tag : String) : Deep
      Deep.new(tag)
    end
  end

  def make(seed : Int32) : Part
    @@made = @@made + 1
    Part.new(seed)
  end

  def made : Int32
    @@made
  end

  TAG = "shard"

  # A method whose answer is *two* subclasses, and the shape that made this
  # section necessary.
  #
  # Nobody wrote a return type, so the boundary infers one, and what the body
  # answers is `Base+` — the merge of two subclasses. A declaration cannot name
  # a virtual type (`Base+` is how one prints, not a name anybody writes), so
  # it crosses as `: Base`. An ordinary `def` types its call `Base+` because
  # the *body* widens it; a header has no body, so the call came out typed
  # `Base` exactly and `is_a?(Derived)` answered **false**.
  #
  # A method that *writes* `: Base` does not find this: Crystal resolves a
  # written restriction on an abstract class to `Base+` on its own. It takes an
  # inferred one, and the first version of this check wrote the restriction and
  # passed either way.
  def pick(flag : Bool)
    if flag
      Derived.new("picked", 1)
    else
      Other.new("picked")
    end
  end

  # And held in a collection, because the wrong reading also decides what a
  # generic is instantiated with.
  def collect(flag : Bool)
    [pick(flag)]
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
puts Shard.made
puts Shard::Inner.deep("nested").tag
d = Shard.derived("hello", 42)
puts d.tag

# The abstract-return shapes. `is_a?` and `class` are the two questions a wrong
# reading answers wrongly while everything else about the program looks right.
made = Shard.pick(true)
puts made.class
puts made.is_a?(Shard::Derived)
puts made.describe
held = Shard.collect(false)
puts held[0].class
puts held[0].is_a?(Shard::Other)
puts held[0].describe

# And the body that names the shard's own constants absolutely.
d.tagged { |text| puts text }
puts d.extra
puts d.describe
class Report < Shard::Sheet
  def initialize
  end

  def title : String
    "report"
  end
end

held = Shard::Holder(Int32).new(9)
puts held.value
puts held.tag
puts Shard::Holder(String).new("s", "named").tag
puts Report.new.render
Shard.note("kept").write(STDOUT)
puts ""
puts part.kind(2)
puts part.kind(1)
puts part.kind(0)
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

# Printed because it is the evidence: without this line the union above could
# be one the consumer forms for itself, and the gate would be checking nothing.
printf 'the nested-in-a-generic method, emitted against its declaration: '
grep -c 'Shard::Holder::Note' mods/shard_keep.cr > /dev/null && \
  strings -a mods/shard.iyimod | grep -oE '\*Shard::Holder::Note#write[^ ]*' | sort -u | head -1 || echo "MISSING"

printf 'the union this shard matches against, carried: '
"$IYI" mod dump mods/shard.iyimod | grep -F '(Char | Int32)' | tr -d ' ' || echo "MISSING"

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
