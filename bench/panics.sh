#!/usr/bin/env bash
# Panics — SPEC.md III.1.4, made literal. Each step is one sentence the
# section now states in the present tense: a panic prints at the site of
# the bug and unwinds by registry, pending defers run innermost-first, a
# panicking task dies at its boundary while its group cancels the
# siblings, the boundary re-raises in the owner exactly once, a panic
# with no boundary above it exits 1 after its defers ran, and `.or_panic`
# is a real panic. The no-panic path rides the same registry and is
# asserted unchanged.
set -euo pipefail

IYI=${IYI:-./bin/iyi}
work=$(mktemp -d /tmp/iyi-panics.XXXXXX)
trap 'rm -rf "$work"' EXIT

fail() { echo "panics FAIL: $1"; exit 1; }
step() { echo "panics ok   $1"; }

run() { # file -> captures stdout+stderr, tolerates nonzero exit
  set +e
  out=$("$IYI" run "$1" 2>&1)
  code=$?
  set -e
}

# ── 1. a task panics: its defer runs, the boundary re-raises, the
#      sibling is cancelled, the process exits 1 in order ──────────────
cat > "$work/task.iyi" <<'EOF'
module task

pub def work : Int32
  defer puts "task defer ran"
  raise "boom" if true
  1
end

pub def run_all : Int32
  defer puts "outer defer ran"
  group do |g|
    g.spawn { work }
    g.spawn {
      s = sleep(5000)
      puts "sibling woke" if s.is_a?(Nil)
      2
    }
  end
  puts "after group"
  0
end

puts run_all
EOF
run "$work/task.iyi"
[ "$code" = 1 ] || fail "task panic exit was $code, wanted 1"
expected=$(printf 'iyi: panic: boom\ntask defer ran\niyi: panic: a task panicked: boom\nouter defer ran')
[ "$out" = "$expected" ] || fail "task panic output was:
$out"
step "a panicking task dies at its boundary, defers ran, sibling cancelled"

# ── 2. a panic with no boundary above it: main's defers run LIFO, then
#      exit 1 — cleanup that yesterday's panic skipped entirely ────────
cat > "$work/main.iyi" <<'EOF'
module main

pub def go : Int32
  defer puts "first defer"
  defer puts "second defer"
  raise "on main" if true
  0
end

puts go
EOF
run "$work/main.iyi"
[ "$code" = 1 ] || fail "main panic exit was $code, wanted 1"
expected=$(printf 'iyi: panic: on main\nsecond defer\nfirst defer')
[ "$out" = "$expected" ] || fail "main panic output was:
$out"
step "an unbounded panic exits 1 after its defers, innermost first"

# ── 3. `.or_panic` is a real panic now: through the task boundary,
#      carrying the error's message ────────────────────────────────────
cat > "$work/orp.iyi" <<'EOF'
module orp

pub struct Boom
end

impl Error for Boom
  def message : String
    "or_panic fired"
  end
end

pub def risky(n : Int32) : Int32 | Boom
  return Boom.new if n > 0
  n
end

group do |g|
  g.spawn { risky(1).or_panic }
end
puts "unreached"
EOF
run "$work/orp.iyi"
[ "$code" = 1 ] || fail "or_panic exit was $code, wanted 1"
echo "$out" | grep -q "iyi: panic: or_panic fired" || fail "or_panic message missing:
$out"
echo "$out" | grep -q "a task panicked: or_panic fired" || fail "or_panic boundary missing:
$out"
! echo "$out" | grep -q "unreached" || fail "or_panic fell through"
step ".or_panic is a real panic, caught at the boundary"

# ── 4. reading a panicked task's value re-raises — once ────────────────
cat > "$work/value.iyi" <<'EOF'
module tval

pub def blows : Int32
  raise "task blew" if true
  1
end

group do |g|
  t = g.spawn { blows }
  v = t.value
  puts v
end
puts "unreached"
EOF
run "$work/value.iyi"
[ "$code" = 1 ] || fail "value exit was $code, wanted 1"
[ "$(echo "$out" | grep -c 'task blew')" = 2 ] || fail "value re-raise count wrong:
$out"
step "a panicked task's value re-raises in the reader, exactly once"

# ── 5. the panic crosses two boundaries: inner group's owner is a task
#      of the outer group, and each boundary adds its own report ───────
cat > "$work/nested.iyi" <<'EOF'
module nested

pub def inner_work : Int32
  raise "deep" if true
  1
end

pub def middle : Int32
  group do |g|
    g.spawn { inner_work }
  end
  0
end

group do |g|
  g.spawn { middle }
end
puts "unreached"
EOF
run "$work/nested.iyi"
[ "$code" = 1 ] || fail "nested exit was $code, wanted 1"
echo "$out" | grep -q "a task panicked: a task panicked: deep" || fail "nested chain missing:
$out"
step "a panic climbs group by group, each boundary named"

# ── 6. the no-panic path is untouched: defers run LIFO on a normal
#      exit and on a return, and the program answers what it always did ─
cat > "$work/normal.iyi" <<'EOF'
module normal

pub def with_cleanup(early : Bool) : Int32
  defer puts "close a"
  defer puts "close b"
  return 1 if early
  puts "body ran"
  2
end

puts with_cleanup(false)
puts with_cleanup(true)
EOF
run "$work/normal.iyi"
[ "$code" = 0 ] || fail "normal exit was $code, wanted 0"
expected=$(printf 'body ran\nclose b\nclose a\n2\nclose b\nclose a\n1')
[ "$out" = "$expected" ] || fail "normal-path output was:
$out"
step "the no-panic path is unchanged: LIFO on fall-through and on return"

echo "panics gate: every step held"
