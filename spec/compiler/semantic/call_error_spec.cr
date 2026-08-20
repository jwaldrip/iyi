require "../../spec_helper"

describe "Call errors" do
  it "says wrong number of arguments (to few arguments)" do
    assert_error <<-CODE, "wrong number of arguments for 'foo' (given 0, expected 1)"
      def foo(x)
      end

      foo
      CODE
  end

  it "says wrong number of arguments even if other overloads don't match by block" do
    assert_error <<-CODE, "wrong number of arguments for 'foo' (given 0, expected 1)"
      def foo(x)
      end

      def foo(x, y)
        yield
      end

      foo
      CODE
  end

  it "says not expected to be invoked with a block" do
    assert_error <<-CODE, "'foo' is not expected to be invoked with a block, but a block was given"
      def foo
      end

      foo {}
      CODE
  end

  it "says expected to be invoked with a block" do
    assert_error <<-CODE, "'foo' is expected to be invoked with a block, but no block was given"
      def foo
        yield
      end

      foo
      CODE
  end

  it "says missing named argument" do
    assert_error <<-CODE, "missing argument: x"
      def foo(*, x)
      end

      foo
      CODE
  end

  it "says missing named arguments" do
    assert_error <<-CODE, "missing arguments: x, y"
      def foo(*, x, y)
      end

      foo
      CODE
  end

  it "says no parameter named" do
    assert_error <<-CODE, "no parameter named 'x'"
      def foo
      end

      foo(x: 1)
      CODE
  end

  it "says no parameters named" do
    assert_error <<-CODE, "no parameters named 'x', 'y'"
      def foo
      end

      foo(x: 1, y: 2)
      CODE
  end

  it "says argument already specified" do
    assert_error <<-CODE, "argument for parameter 'x' already specified"
      def foo(x)
      end

      foo(1, x: 2)
      CODE
  end

  it "says type mismatch for positional argument" do
    assert_error <<-CODE, "expected argument #2 to 'foo' to be Int32, not Char"
      def foo(x : Int32, y : Int32)
      end

      foo(1, 'a')
      CODE
  end

  it "says type mismatch for positional argument with two options" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to be Int32 or String, not Char"
      def foo(x : Int32)
      end

      def foo(x : String)
      end

      foo('a')
      CODE
  end

  it "says type mismatch for positional argument with three options" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to be Bool, Int32 or String, not Char"
      def foo(x : Int32)
      end

      def foo(x : String)
      end

      def foo(x : Bool)
      end

      foo('a')
      CODE
  end

  it "says type mismatch for named argument " do
    assert_error <<-CODE, "expected argument 'x' to 'foo' to be Int32, not Char"
      def foo(x : Int32, y : Int32)
      end

      foo(y: 1, x: 'a')
      CODE
  end

  it "replaces free variables in positional argument" do
    assert_error <<-CODE, "expected argument #2 to 'foo' to be Int32, not Char"
      def foo(x : T, y : T) forall T
      end

      foo(1, 'a')
      CODE
  end

  it "replaces free variables in named argument" do
    assert_error <<-CODE, "expected argument 'y' to 'foo' to be Int32, not Char"
      def foo(x : T, y : T) forall T
      end

      foo(x: 1, y: 'a')
      CODE
  end

  it "replaces generic type var in positional argument" do
    assert_error <<-CODE, "expected argument #1 to 'Foo(Int32).foo' to be Int32, not Char"
      class Foo(T)
        def self.foo(x : T)
        end
      end

      Foo(Int32).foo('a')
      CODE
  end

  it "replaces generic type var in named argument" do
    assert_error <<-CODE, "expected argument 'y' to 'Foo(Int32).foo' to be Int32, not Char"
      class Foo(T)
        def self.foo(x : T, y : T)
        end
      end

      Foo(Int32).foo(x: 1, y: 'a')
      CODE
  end

  it "says type mismatch for positional argument even if there are overloads that don't match" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to be Char or Int32, not String"
      def foo(x : Int32)
      end

      def foo(x : Char)
      end

      def foo(x : Char, y : Int32)
      end

      foo("hello")
      CODE
  end

  it "says type mismatch for symbol against enum (did you mean)" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to match a member of enum Color.\n\nDid you mean :red?"
      enum Color
        Red
        Green
        Blue
      end

      def foo(x : Color)
      end

      foo(:rred)
      CODE
  end

  it "says type mismatch for symbol against enum (list all possibilities when 10 or less)" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to match a member of enum Color.\n\nOptions are: :red, :green, :blue, :violet and :purple"
      enum Color
        Red
        Green
        Blue
        Violet
        Purple
      end

      def foo(x : Color)
      end

      foo(:hello_world)
      CODE
  end

  it "says type mismatch for symbol against enum, named argument case" do
    assert_error <<-CODE, "expected argument 'x' to 'foo' to match a member of enum Color.\n\nDid you mean :red?"
      enum Color
        Red
        Green
        Blue
      end

      def foo(x : Color)
      end

      foo(x: :rred)
      CODE
  end

  it "errors on argument if more types are given than expected" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to be Int32, not (Int32 | Nil)"
      def foo(x : Int32)
      end

      def foo(x : Char)
      end

      foo(1 || nil)
      CODE
  end

  it "errors on argument if more types are given than expected, shows all expected types" do
    assert_error <<-CODE, "expected argument #1 to 'foo' to be Char or Int32, not (Char | Int32 | Nil)"
      def foo(x : Int32)
      end

      def foo(x : Char)
      end

      foo(1 ? nil : (1 || 'a'))
      CODE
  end

  it "errors on argument if argument matches in all overloads but with different types in other arguments" do
    assert_error <<-CODE, "expected argument #2 to 'foo' to be Int32, not (Int32 | Nil)"
      def foo(x : String, y : Int32, w : Int32)
      end

      def foo(x : String, y : Nil, w : Char)
      end

      foo("a", 1 || nil, 1)
      CODE
  end

  describe "method signatures in error traces" do
    it "includes named argument" do
      assert_error <<-CODE, "instantiating 'bar(y: Int32)'"
        def foo(x)
        end

        def bar(**opts)
          foo
        end

        bar(y: 1)
        CODE
    end

    it "includes named arguments" do
      assert_error <<-CODE, "instantiating 'bar(y: Int32, z: String)'"
        def foo(x)
        end

        def bar(**opts)
          foo
        end

        bar(y: 1, z: "")
        CODE
    end

    it "includes positional and named argument" do
      assert_error <<-CODE, "instantiating 'bar(Int32, y: String)'"
        def foo(x)
        end

        def bar(*args, **opts)
          foo
        end

        bar(1, y: "")
        CODE
    end

    it "expands single splat argument" do
      assert_error <<-CODE, "instantiating 'bar(Int32)'"
        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(*{1})
        CODE
    end

    it "expands single splat argument, more elements" do
      assert_error <<-CODE, "instantiating 'bar(Int32, String)'"
        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(*{1, ""})
        CODE
    end

    it "expands single splat argument, empty tuple" do
      assert_error <<-CODE, "instantiating 'bar()'"
        #{tuple_new}

        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(*Tuple.new)
        CODE
    end

    it "expands positional and single splat argument" do
      assert_error <<-CODE, "instantiating 'bar(Int32, String)'"
        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(1, *{""})
        CODE
    end

    it "expands positional and single splat argument, more elements" do
      assert_error <<-CODE, "instantiating 'bar(Int32, String, Bool)'"
        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(1, *{"", true})
        CODE
    end

    it "expands positional and single splat argument, empty tuple" do
      assert_error <<-CODE, "instantiating 'bar(Int32)'"
        #{tuple_new}

        def foo(x)
        end

        def bar(*args)
          foo
        end

        bar(1, *Tuple.new)
        CODE
    end

    it "expands double splat argument" do
      assert_error <<-CODE, "instantiating 'bar(y: Int32)'"
        def foo(x)
        end

        def bar(**opts)
          foo
        end

        bar(**{y: 1})
        CODE
    end

    it "expands double splat argument, more elements" do
      assert_error <<-CODE, "instantiating 'bar(y: Int32, z: String)'"
        def foo(x)
        end

        def bar(**opts)
          foo
        end

        bar(**{y: 1, z: ""})
        CODE
    end

    it "expands double splat argument, empty named tuple" do
      assert_error <<-CODE, "instantiating 'bar()'"
        #{named_tuple_new}

        def foo(x)
        end

        def bar(**opts)
          foo
        end

        bar(**NamedTuple.new)
        CODE
    end

    it "expands positional and double splat argument" do
      assert_error <<-CODE, "instantiating 'bar(Int32, y: String)'"
        def foo(x)
        end

        def bar(*args, **opts)
          foo
        end

        bar(1, **{y: ""})
        CODE
    end

    it "expands positional and double splat argument, more elements" do
      assert_error <<-CODE, "instantiating 'bar(Int32, y: String, z: Bool)'"
        def foo(x)
        end

        def bar(*args, **opts)
          foo
        end

        bar(1, **{y: "", z: true})
        CODE
    end

    it "expands positional and double splat argument, empty named tuple" do
      assert_error <<-CODE, "instantiating 'bar(Int32)'"
        #{named_tuple_new}

        def foo(x)
        end

        def bar(*args, **opts)
          foo
        end

        bar(1, **NamedTuple.new)
        CODE
    end

    it "uses `T.method` instead of `T.class#method`" do
      assert_error <<-CODE, "instantiating 'Bar.bar()'"
        def foo(x)
        end

        class Bar
          def self.bar
            foo
          end
        end

        Bar.bar
        CODE
    end

    it "uses `T.method` instead of `T:module#method`" do
      assert_error <<-CODE, "instantiating 'Bar.bar()'"
        def foo(x)
        end

        module Bar
          def self.bar
            foo
          end
        end

        Bar.bar
        CODE
    end
  end
end

private def tuple_new
  <<-CODE
    struct Tuple
      def self.new(*args)
        args
      end
    end
    CODE
end

private def named_tuple_new
  <<-CODE
    struct NamedTuple
      def self.new(**opts)
        opts
      end
    end
    CODE
end
