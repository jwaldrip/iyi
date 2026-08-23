require "spec"
require "../../../src/compiler/iyi/formatter"

# iyi: the formatter on iyi's own syntax.
#
# The file name is what the difference hangs on. `Iyi.format` hands it to
# the parser, which reads `!` as propagation in a `.iyi` file and as a method
# suffix in a `.cr` one, so a spec that left the name off would be formatting
# a different language from the one it is about.
#
# Every case here is written the way this repository writes it, so what these
# assert is that the formatter leaves correct code alone. The two that change
# something are the ones that show it is running at all.
private def assert_iyi_format(input, output = input, file = __FILE__, line = __LINE__)
  it "formats #{input.inspect}", file, line do
    result = Iyi.format("#{input}\n", filename: "spec.iyi")
    result.should eq("#{output}\n"), file: file, line: line
  end
end

describe "Formatter on iyi" do
  # R-1's header, which desugars to two nodes the formatter has to see as one
  # line: the header itself and a module wrapping everything under it.
  assert_iyi_format "module app/greeter"
  assert_iyi_format "module app/nested/deeper"
  assert_iyi_format "module m\n\nimport app/greeter"
  assert_iyi_format "module m\n\nimport app/greeter\nusing app/greeter"
  assert_iyi_format "module m\n\nimport std/list\nusing std/list::{List}"
  assert_iyi_format "module m\n\nimport std/list\nusing std/list::{List, Cons}"

  # A keyword-prefixed segment: `end` and `def` start these names, and the
  # slash after one is what the parser had to take out of the lexer's hands.
  assert_iyi_format "module endpoint/handler"
  assert_iyi_format "module m\n\nimport defs/shared"

  # R-2: what a module exports says so.
  assert_iyi_format "module m\n\npub def polite(name : String) : String\n  name\nend"
  assert_iyi_format "module m\n\npub struct Box(T)\n  getter value : T\nend"
  assert_iyi_format "module m\n\npub class Holder\n  @x = 1\nend"
  # `pub macro` and `pub CONST` were the two the formatter did not know, and
  # nothing formatted in CI had either in it, so it refused a whole file the
  # first time one was written. Every prefix R-2 allows is listed here now.
  assert_iyi_format "module m\n\npub macro described(declaration)\n  def described : String\n    \"x\"\n  end\nend"
  assert_iyi_format "module m\n\npub LIMIT = 42"

  # Traits, their supertraits, and the associated types they declare.
  assert_iyi_format "module m\n\npub trait Show\n  abstract def show : String\nend"
  assert_iyi_format "module m\n\npub trait Ord : Cmp\n  abstract def cmp(other : self) : Int32\nend"
  assert_iyi_format "module m\n\npub trait Each\n  type Elem\n\n  abstract def each(& : (Elem -> Nil)) : Nil\nend"

  # R-3: an impl, its target, and the binder that introduces the target's
  # parameters.
  assert_iyi_format "module m\n\nimpl Show for Int32\n  def show : String\n    \"i\"\n  end\nend"
  assert_iyi_format "module m\n\nimpl Show for Box(T) forall T\n  def show : String\n    \"b\"\n  end\nend"
  assert_iyi_format "module m\n\nimpl Show for Box(T) forall T : Show\n  def show : String\n    \"b\"\n  end\nend"
  assert_iyi_format "module m\n\nimpl Each for Nums\n  type Elem = Int32\n\n  def each(& : Int32 -> Nil) : Nil\n  end\nend"

  # A bound on a name the signature mentions rather than introduces (II.6),
  # and one on a name it introduces (II.7).
  assert_iyi_format "module m\n\ndef includes?(value : Elem) : Bool where Elem : Cmp\n  true\nend"
  assert_iyi_format "module m\n\npub def announce(item : T) : String forall T : Greet\n  item.greet\nend"

  # Errors: propagation, recovery, and the panic that takes no default.
  assert_iyi_format "module m\n\nvalue = read(path)!"
  assert_iyi_format "module m\n\nvalue = read(path).or(0)"
  assert_iyi_format "module m\n\nvalue = read(path).or_panic"
  assert_iyi_format "module m\n\ndef f : Nil\n  defer close(handle)\nend"

  # Running at all: these two are wrong on the way in and right on the way out.
  assert_iyi_format "module m\n\npub    def   polite(name : String) : String\n  name\nend",
    "module m\n\npub def polite(name : String) : String\n  name\nend"
  assert_iyi_format "module m\n\nimpl Show    for    Int32\n  def show : String\n    \"i\"\n  end\nend",
    "module m\n\nimpl Show for Int32\n  def show : String\n    \"i\"\n  end\nend"
end
