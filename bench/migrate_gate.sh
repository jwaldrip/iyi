#!/usr/bin/env bash
# `iyi migrate`, on a Crystal project written to plant every case the
# rewrite has to answer (SPEC.md III.6).
#
#     bash bench/migrate_gate.sh
#
# `bench/migrate_fixture` is an ordinary Crystal project: a namespace over
# several files, a constant reached across them, `include` of a namespace,
# a module function called qualified, a two-file import cycle, a struct
# with `JSON::Serializable`, a reopening of `Int32`, a `not_nil!`, a
# `sort_by!`, and an ECR template embedded by a path from the project
# root. It runs as Crystal and prints eight lines.
#
# The gate is that the migrated tree prints the same eight lines, that
# every module compiles on its own, that each planted case is *named* in
# the notes rather than silently mangled, and that the tree emits
# artifacts — which is R-2 satisfied, and the thing a migration is for.
#
# Hermetic: the fixture depends on no shard, so this needs no network.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="$REPO/bin/crystal"
FIXTURE="$REPO/bench/migrate_fixture"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0
step() {
  if [ "$1" = "ok" ]; then
    printf '  ok   %s\n' "$2"
  else
    printf '  FAIL %s\n' "$2"
    status=1
  fi
}
holds() { # holds <name> <needle> <file>
  if grep -qF -- "$2" "$3"; then step ok "$1"; else step fail "$1 (no '$2')"; fi
}

echo "== the fixture, as Crystal"
if ! (cd "$FIXTURE" && "$CRYSTAL" build -o "$WORK/crystal_shop" src/shop.cr > "$WORK/crystal.err" 2>&1 &&
      cd "$FIXTURE" && "$WORK/crystal_shop" > "$WORK/crystal.out" 2>> "$WORK/crystal.err"); then
  echo "the fixture does not run as Crystal, which is this gate's premise"
  tail -5 "$WORK/crystal.err"
  exit 1
fi
printf '  %s\n' "$(tr '\n' '|' < "$WORK/crystal.out")"

echo "== iyi migrate"
if ! (cd "$FIXTURE" && "$IYI" migrate src --out "$WORK/out" --verbose > "$WORK/migrate.log" 2>&1); then
  echo "migrate failed"
  tail -20 "$WORK/migrate.log"
  exit 1
fi

# Each planted case is named. A migration that answers a case silently is
# a migration nobody can check, which is the whole reason for the notes.
holds "the import cycle is one module, and named"      "R-1 cannot separate" "$WORK/migrate.log"
holds "the reopening of Int32 stays Crystal"           'struct Int32'        "$WORK/migrate.log"
holds "not_nil! is rewritten and named"                'not_nil!'            "$WORK/migrate.log"
holds "sort_by! is rewritten and named"                'sort_by!'            "$WORK/migrate.log"
holds "include of a namespace becomes using"           'include Names'       "$WORK/migrate.log"
holds "the embedded template travels"                  'report.html.ecr'     "$WORK/migrate.log"

# The shape of the tree: the namespace is the path, the cycle is one file,
# the reopening is a `.cr` beside its module, the shards are one module.
for path in shop.iyi shop/names.iyi shop/config.iyi shop/counter.iyi \
            shop/report.iyi shop/models/cart_item.iyi \
            shop/counter_crystal.cr crystal_shards.iyi \
            src/shop/views/report.html.ecr; do
  if [ -f "$WORK/out/$path" ]; then step ok "wrote $path"; else step fail "no $path"; fi
done
if [ ! -f "$WORK/out/shop/models/cart.iyi" ]; then
  step ok "the cycle's members are not separate modules"
else
  step fail "cart.iyi was written beside the merged module"
fi

echo "== every module compiles alone"
if (cd "$FIXTURE" && "$IYI" migrate src --out "$WORK/checked" --check > "$WORK/check.log" 2>&1); then
  step ok "$(tail -1 "$WORK/check.log")"
else
  step fail "modules refused: $(grep -c ':' "$WORK/check.log") lines"
  tail -8 "$WORK/check.log"
fi

echo "== the migrated program answers what the Crystal one answered"
if (cd "$WORK/out" && "$IYI" build --crystal -o "$WORK/iyi_shop" shop.iyi > "$WORK/iyi.err" 2>&1 &&
    cd "$WORK/out" && "$WORK/iyi_shop" > "$WORK/iyi.out" 2>> "$WORK/iyi.err"); then
  if diff -q "$WORK/crystal.out" "$WORK/iyi.out" > /dev/null; then
    step ok "byte for byte, $(wc -l < "$WORK/iyi.out") lines"
  else
    step fail "the two differ"
    diff "$WORK/crystal.out" "$WORK/iyi.out" | head -8
  fi
else
  step fail "the migrated program does not run"
  tail -8 "$WORK/iyi.err"
fi

# `--annotate` is R-2 satisfied without a person guessing: the fixture's
# `Cart#holds?(item)` carries no types, the program calls it once, and the
# types the compiler bound are written into the declaration.
echo "== --annotate writes the types the calls said"
if (cd "$FIXTURE" && "$IYI" migrate src --out "$WORK/annotated" --annotate --verbose > "$WORK/annotate.log" 2>&1); then
  holds "the parameter's type is named"  "item : ::Shop::Models::Item" "$WORK/annotate.log"
  holds "the answer is named"            "holds?\` answers ::Bool"     "$WORK/annotate.log"
  if grep -q "def holds?(item : Item) : ::Bool" "$WORK/annotated/shop/models/cart_item.iyi"; then
    step ok "the declaration carries both, spelled for this module"
  else
    step fail "the declaration was not annotated: $(grep -m1 'def holds?' "$WORK/annotated/shop/models/cart_item.iyi")"
  fi
  if (cd "$WORK/annotated" && "$IYI" build --crystal -o "$WORK/annotated_shop" shop.iyi > "$WORK/annotated.log" 2>&1) &&
     (cd "$WORK/annotated" && "$WORK/annotated_shop" > "$WORK/annotated.out" 2>&1) &&
     diff -q "$WORK/crystal.out" "$WORK/annotated.out" > /dev/null; then
    step ok "the annotated tree answers the same"
  else
    step fail "the annotated tree does not answer the same"
    grep -m1 -A3 "^Error" "$WORK/annotated.log"
  fi
else
  step fail "migrate --annotate failed"
  tail -6 "$WORK/annotate.log"
fi

# Two shapes a line-local rewrite gets wrong, both found on shards: a file
# name that is not a module name (`price-list.cr` gave `module
# shop/price-list`, a subtraction), and a chain whose `.not_nil!` sits on a
# line of its own, where the receiver is above and the narrowing has to be
# one that composes.
echo "== a file name becomes a module name, and a chain keeps its narrowing"
holds "the hyphen is gone from the module" "module shop/price_list" "$WORK/out/shop/price_list.iyi"
holds "and the chain narrows without a receiver on the line" \
      ".try { |value| value } || raise" "$WORK/out/shop/price_list.iyi"

# A regex literal is refused only where the program has no runtime `Regex`
# - iyi's own prelude. A migrated tree is compiled against Crystal's
# library, where the class behind the literal lives, and the fixture's
# `Shop::Names.slug` is one: it has to compile in a `.iyi` module, and the
# constant it expands to has to travel in that module's artifact, which
# the artifact steps above build from.
echo "== a regex literal is the module's, and travels"
holds "the literal is in the module, not rewritten" "gsub(/[^a-z0-9]+/i" "$WORK/out/shop/names.iyi"

# A reopening of a type the tree does not own stays Crystal in a sidecar
# beside its module (R-3), and it names the tree's own types too - which
# moved. It has no `using` line to reach them through, so they are written
# in full: Kemal's `context_crystal.cr` asked for a `Kemal::Route` that no
# longer existed, which is `undefined constant` in a file nobody wrote.
echo "== a sidecar's names follow the types that moved"
holds "the tree's own type is named where it went" \
      "item : Shop::Models::CartItem::Item" "$WORK/out/shop/counter_crystal.cr"
holds "and the reopened type is left alone" "struct Int32" "$WORK/out/shop/counter_crystal.cr"

# `!` is III.1.7a's, so every Crystal bang has to be rewritten - and which
# rewrite is right depends on whose method it is. The fixture plants both on
# the same line shape: `@items.uniq!` is Crystal's in-place member, whose
# copy has to go back where the mutation was, and `cart.tidy!` is the tree's
# own, which lost its bang with its definition. Only the compiler can tell
# them apart, which is why this runs beside `--annotate`.
echo "== a bang is rewritten by whose method it is"
holds "the tree's own def lost the bang"   "def tidy : Int32"          "$WORK/annotated/shop/models/cart_item.iyi"
holds "and so did its call"                "cart.tidy"                 "$WORK/annotated/shop.iyi"
holds "Crystal's mutation puts the copy back" "@items = @items.uniq"   "$WORK/annotated/shop/models/cart_item.iyi"
holds "a bang accessor's reader raises"    'raise "note is not set"'   "$WORK/annotated/shop/models/cart_item.iyi"
if survivor=$(grep -vE '^[[:space:]]*#' "$WORK/annotated"/*.iyi "$WORK/annotated"/shop/**/*.iyi 2>/dev/null | grep -m1 '[a-z_]!'); then
  step fail "a name with a bang survived: $survivor"
else
  step ok "no name with a bang survived, which is III.1.7"
fi

# R-2 satisfied is what makes a migrated tree an iyi program rather than
# the other language in another spelling: every export's types are written, so
# modules can be read as declarations. `include JSON::Serializable`
# generates a `new` and an `initialize` nobody can annotate, which is why
# a macro's defs are exempt (iyimod.cr, `check_types_written`).
echo "== the tree emits artifacts (R-2 holds)"
if (cd "$WORK/annotated" && "$IYI" build --crystal --emit-iyimod mods -o "$WORK/probe" shop.iyi > "$WORK/emit.log" 2>&1); then
  written=$(find "$WORK/annotated/mods" -name '*.iyimod' | wc -l)
  if [ "$written" -ge 6 ]; then
    step ok "$written .iyimod files"
  else
    step fail "only $written .iyimod files"
  fi
else
  step fail "emitting artifacts refused"
  grep -m1 -A3 "^Error" "$WORK/emit.log"
fi

echo "== the same program, built from those artifacts"
if (cd "$WORK/annotated" && "$IYI" build --crystal --use-iyimod mods -o "$WORK/from_artifacts" shop.iyi > "$WORK/artifact.log" 2>&1) &&
   (cd "$WORK/annotated" && "$WORK/from_artifacts" > "$WORK/artifact.out" 2>&1); then
  if diff -q "$WORK/crystal.out" "$WORK/artifact.out" > /dev/null; then
    step ok "byte for byte, with the modules read as declarations"
  else
    step fail "the artifact build answers differently"
    diff "$WORK/crystal.out" "$WORK/artifact.out" | head -8
  fi
else
  step fail "the artifact build failed"
  grep -m1 -A3 "^Error" "$WORK/artifact.log"
fi

# The ordering rule a migrated tree depends on and nothing else tested: a
# shard's top-level code — `pg` registering its driver — runs before the
# initialiser of any module that uses it, which means the entry's own
# `require` cannot be spliced after the imported modules' initialisers
# (semantic.cr, `splice_iyi_module_initialisers`).
# `pub` is what another module may name, and two kinds of declaration were
# missing from it: an `alias` (a name for a type) and an `annotation` (which
# a *consumer* applies). The fixture's `Shop::Money` and `Shop::Priced` are
# both, written in `shop/report`'s signature and over its class - and both
# have to travel in the artifact, which the steps above build from.
echo "== an alias and an annotation are part of a module's surface"
holds "the alias is exported"        "pub alias Money = Int32"  "$WORK/out/shop/config.iyi"
holds "the annotation is exported"   "pub annotation Priced"    "$WORK/out/shop/config.iyi"
holds "and both are reached by name" "Money, Priced}"           "$WORK/out/shop/report.iyi"
# `mod dump` rather than `strings`: the declarations section is compressed,
# so the bytes are not the text.
if "$IYI" mod dump "$WORK/annotated/mods/shop/config.iyimod" 2>/dev/null | grep -q "pub annotation Priced"; then
  step ok "the annotation travels in the artifact"
else
  step fail "the artifact does not carry the annotation"
fi
if "$IYI" mod dump "$WORK/annotated/mods/shop/config.iyimod" 2>/dev/null | grep -q "pub alias Money = Int32"; then
  step ok "and the alias travels as what it resolved to"
else
  step fail "the artifact does not carry the alias"
fi

# `shards install` writes other projects' source into a `lib/` beside the
# manifest, and `iyi migrate .` read all of it: on an application that was
# 756 files that were not its own, 359 of them merged into one module.
echo "== a shards directory is not this tree's to migrate"
if (cd "$FIXTURE" && "$IYI" migrate . --out "$WORK/whole" > "$WORK/whole.log" 2>&1); then
  holds "the shard's file is named as somebody else's" \
        "other projects' source and stayed there" "$WORK/whole.log"
  holds "and the narrower command is named"        "migrate src --out"  "$WORK/whole.log"
  if [ -e "$WORK/whole/pretend.iyi" ]; then
    step fail "the shard became a module of this tree"
  elif [ -f "$WORK/whole/shop.iyi" ]; then
    step ok "the tree's own code migrated and the shard did not"
  else
    step fail "the tree's own entry did not migrate"
  fi
else
  step fail "migrate . failed"
  tail -5 "$WORK/whole.log"
fi

# `--out src` wrote the modules into the tree it was reading and left a
# `src/src` behind. A verb whose first mistake edits the project is not one
# a person tries twice.
echo "== the verb refuses to write into the tree it reads"
if (cd "$FIXTURE" && "$IYI" migrate src --out src > "$WORK/into.log" 2>&1); then
  step fail "migrate --out src was accepted"
else
  holds "and says where the modules go" "the modules go beside it, not into it" "$WORK/into.log"
fi
if [ -n "$(find "$FIXTURE/src" -name '*.iyi' -print -quit)" ]; then
  step fail "the source tree has .iyi files in it"
else
  step ok "the source tree is untouched"
fi

echo "== a required file's top-level code runs before an import's initialiser"
mkdir -p "$WORK/order"
cat > "$WORK/order/registry.cr" <<'CR'
module Registry
  @@names = [] of String

  def self.register(name : String) : Nil
    @@names << name
  end

  def self.names : Array(String)
    @@names
  end
end

Registry.register("from the required file")
CR
cat > "$WORK/order/store.iyi" <<'IYI'
module store

require "./registry.cr"

pub NAMES = Registry.names.dup
IYI
cat > "$WORK/order/main.iyi" <<'IYI'
module main

require "./registry.cr"

import store
using store::{NAMES}

puts NAMES.join(", ")
IYI
if (cd "$WORK/order" && "$IYI" build --crystal -o "$WORK/order_main" main.iyi > "$WORK/order.log" 2>&1) &&
   ("$WORK/order_main" > "$WORK/order.out" 2>&1) &&
   grep -q "from the required file" "$WORK/order.out"; then
  step ok "the register ran first"
else
  step fail "the module initialised before the file it required ran"
  tail -4 "$WORK/order.out"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "migrate gate: a Crystal project became iyi modules, and answers what it answered"
else
  echo "migrate gate: something above is not what it was"
fi
exit "$status"
