require "spec"
require "../../../src/compiler/crystal/formatter"

# iyi: the formatter, on the nine nodes R-1, R-2, R-2b and R-3 added and on the
# two clauses that live on `Def` rather than on a node of their own.
#
# A filename is what puts the lexer in iyi mode (`Lexer#filename=`), so these
# pass one. `assert_format` in `formatter_spec.cr` does not, which is why these
# are a file rather than a describe block over there: a case written without the
# filename silently tests Crystal instead.
private def assert_iyi_format(input, output = input, file = __FILE__, line = __LINE__, focus = false)
  it "formats #{input.inspect}", file, line, focus: focus do
    expected = "#{output}\n"
    result = Crystal.format(input, filename: "spec.iyi")

    unless result == expected
      fail <<-ERROR, file: file, line: line
        Expected

        ~~~
        #{input}
        ~~~

        to format to:

        ~~~
        #{expected}
        ~~~

        but got:

        ~~~
        #{result}
        ~~~
        ERROR
    end

    # Formatting is only useful if it settles. Every case is also its own
    # idempotency check, because a formatter that moves a file on every run
    # cannot be put in front of a commit.
    again = Crystal.format(result, filename: "spec.iyi")
    fail "not idempotent: #{result.inspect} became #{again.inspect}", file: file, line: line unless again == result
  end
end

describe Crystal::Formatter do
  describe "the module header (R-1)" do
    assert_iyi_format "module app/greeter"
    assert_iyi_format "module a/b/c/d"
    assert_iyi_format "module   app/greeter", "module app/greeter"
    assert_iyi_format "module app/greeter\n\npub def one : Int32\n  1\nend"

    # The `/` in a path is a separator, and after an identifier the lexer would
    # otherwise read it as the start of a regex literal. If suppression does not
    # get switched back on, the division below lexes as a regex and the file
    # stops formatting: this is that regression.
    assert_iyi_format "module app/greeter\n\nx = 4 / 2"
    assert_iyi_format "module endpoint/handler\n\nx = 1"
  end

  describe "import and using (R-1, R-2b)" do
    assert_iyi_format "import app/greeter"
    assert_iyi_format "import   app/greeter", "import app/greeter"
    assert_iyi_format "import app/greeter\nimport app/formal"
    assert_iyi_format "using app/greeter"
    assert_iyi_format "using app/greeter::{polite}"
    assert_iyi_format "using app/greeter::{polite, Greet}"
    assert_iyi_format "using app/greeter::{polite,Greet}", "using app/greeter::{polite, Greet}"
    assert_iyi_format "using kemal/router::{Router, Context}"
  end

  describe "pub (R-2)" do
    assert_iyi_format "pub def one : Int32\n  1\nend"
    assert_iyi_format "pub def add(a : Int32, b : Int32) : Int32\n  a + b\nend"
    assert_iyi_format "pub struct Point\n  def initialize\n  end\nend"
    assert_iyi_format "pub class Cell\n  def initialize\n  end\nend"
    assert_iyi_format "pub struct Box(T)\n  def initialize\n  end\nend"
  end

  describe "trait (R-3)" do
    assert_iyi_format "trait Show\n  abstract def show : String\nend"
    assert_iyi_format "pub trait Show\n  abstract def show : String\nend"
    assert_iyi_format "pub trait Into(T)\n  abstract def into : T\nend"
    assert_iyi_format "pub trait Ord : Cmp\n  abstract def item : Int32\nend"
    assert_iyi_format "pub trait Show\n  abstract def show : String\n\n  def shout : String\n    show\n  end\nend"
  end

  describe "impl (R-3)" do
    assert_iyi_format "impl Show for Point\n  def show : String\n    \"p\"\n  end\nend"
    assert_iyi_format "impl Show for Box(T) forall T\n  def show : String\n    \"b\"\n  end\nend"
    assert_iyi_format "impl Show for Pair(X, Y) forall X, Y\n  def show : String\n    \"p\"\n  end\nend"
    assert_iyi_format "impl Into(String) for Point\n  def into : String\n    \"p\"\n  end\nend"
  end

  describe "associated types (II.6)" do
    assert_iyi_format "pub trait Hold\n  type Item\n\n  abstract def item : Item\nend"
    assert_iyi_format "impl Hold for Point\n  type Item = Int32\n\n  def item : Int32\n    1\n  end\nend"
  end

  describe "bounds on a def (II.6, II.7)" do
    assert_iyi_format "def announce(item : T) : String forall T\n  \"x\"\nend"
    assert_iyi_format "pub def announce(item : T) : String forall T : Greet\n  \"x\"\nend"
    assert_iyi_format "def pair(a : T, b : U) : Nil forall T : Show, U : Show\nend"
    assert_iyi_format "def best : Item where Item : Cmp\n  item\nend"
  end

  describe "the error operator and its neighbours (III.1)" do
    assert_iyi_format "x = read(path)!"
    assert_iyi_format "x = read(path).or(0)"
    assert_iyi_format "x = read(path).or_panic"
    assert_iyi_format "x = read(path).or_panic()", "x = read(path).or_panic"
    assert_iyi_format "defer close(handle)"
    assert_iyi_format "def f : Int32\n  defer cleanup\n  1\nend"
  end

  describe "a whole file" do
    assert_iyi_format <<-IYI
      module samples/demo

      import std/list
      using std/list::{List}

      pub trait Show
        abstract def show : String
      end

      pub struct Box(T)
        getter value : T

        def initialize(@value : T)
        end
      end

      impl Show for Box(T) forall T
        def show : String
          "Box"
        end
      end

      puts Box.new(1).show
      IYI
  end
end
