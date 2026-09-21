#!/usr/bin/env bash
# What a string knows about itself, checked by running one.
#
# The prelude decides `String`'s layout and fills in its two counts, and
# a wrong count is not a crash: it is a number that is quietly wrong
# somewhere far away. Nothing else in this repository catches that. The
# specs are the compiler's, `samples_roundtrip.sh` compares a program
# against itself, and the samples have no expected output pinned, so a
# concatenation that reported four characters where it holds five would
# pass every gate there is.
#
# Written after exactly that. `String#+` used to count the characters of
# its result by walking it, which made building a string in a loop
# quadratic; replacing the walk with the sum of the two counts is right
# only if the sum is right, and that is what this asks.
set -u
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$REPO/bin/iyi" ] || { echo "  no $REPO/bin/iyi: run make first"; exit 1; }

cat > "$WORK/strings.iyi" <<'IYI'
# Each line prints a name, what was asked, and what came back. The
# checker below holds the answers, so a wrong one is a diff rather than
# an opinion.
def say(name : String, got : Int32) : Nil
  print name
  print " "
  print got.to_s
  print "\n"
end

ascii = "hello" + ", world"
say("ascii.bytesize", ascii.bytesize)
say("ascii.size", ascii.size)

# Six bytes and five characters: the two counts are different numbers,
# so a concatenation that reports one where it means the other is
# visible here and nowhere else.
wide = "h\u00e9l" + "lo"
say("wide.bytesize", wide.bytesize)
say("wide.size", wide.size)

# Both operands multibyte, so neither count can stand in for the sum.
both = "\u00e9\u00e9" + "\u00e9"
say("both.bytesize", both.bytesize)
say("both.size", both.size)

# An empty operand takes the short path that returns the other string
# whole, which has to keep its own counts.
short = "" + wide
say("short.bytesize", short.bytesize)
say("short.size", short.size)

# Built in a loop, which is the shape that made this matter.
grown = ""
index = 0
while index < 100
  grown = grown + "h\u00e9"
  index = index + 1
end
say("grown.bytesize", grown.bytesize)
say("grown.size", grown.size)

print ascii
print "\n"
print wide
print "\n"
IYI

cat > "$WORK/want.txt" <<'WANT'
ascii.bytesize 12
ascii.size 12
wide.bytesize 6
wide.size 5
both.bytesize 6
both.size 3
short.bytesize 6
short.size 5
grown.bytesize 300
grown.size 200
hello, world
héllo
WANT

IYI_CACHE_DIR="$WORK/iyi" "$REPO/bin/iyi" run "$WORK/strings.iyi" > "$WORK/got.txt" 2> "$WORK/err.txt"
status=$?
if [ "$status" -ne 0 ]; then
  echo "  the program did not run:"
  head -5 "$WORK/err.txt" | sed 's|^|    |'
  exit 1
fi

if diff -q "$WORK/want.txt" "$WORK/got.txt" > /dev/null; then
  echo "  strings agree: $(wc -l < "$WORK/want.txt" | tr -d ' ') answers"
  exit 0
fi

echo "  strings differ:"
diff -u "$WORK/want.txt" "$WORK/got.txt" | tail -n +4 | head -20 | sed 's|^|    |'
exit 1
