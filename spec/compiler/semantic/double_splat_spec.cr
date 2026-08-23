require "../../spec_helper"

describe "Semantic: double splat" do
  it "double splats named argument into arguments (1)" do
    assert_type(<<-CODE) { int32 }
      def foo(x, y)
        x
      end

      tup = {x: 1, y: 'a'}
      foo **tup
      CODE
  end

  it "double splats named argument into arguments (2)" do
    assert_type(<<-CODE) { int32 }
      def foo(x, y)
        x
      end

      tup = {y: 'a', x: 1}
      foo **tup
      CODE
  end

  it "errors if duplicate keys on call side with two double splats" do
    assert_error <<-CODE, "duplicate key: x"
      def foo(**args)
      end

      t1 = {x: 1, y: 2}
      t2 = {z: 3, x: 4}
      foo **t1, **t2
      CODE
  end

  it "errors if duplicate keys on call side with double splat and named args" do
    assert_error <<-CODE, "duplicate key: x"
      def foo(**args)
      end

      t1 = {x: 1, y: 2}
      foo **t1, z: 3, x: 4
      CODE
  end

  it "errors missing argument with double splat" do
    assert_error <<-CODE, "missing argument: y"
      def foo(x, y)
      end

      tup = {x: 1}
      foo **tup
      CODE
  end

  it "matches double splat on method (empty)" do
    assert_type(<<-CODE) { named_tuple_of({} of String => Type) }
      def foo(**args)
        args
      end

      foo
      CODE
  end

  it "matches double splat on method with named args" do
    assert_type(<<-CODE) { named_tuple_of({"x": int32, "y": char}) }
      def foo(**args)
        args
      end

      foo x: 1, y: 'a'
      CODE
  end

  it "matches double splat on method with named args and regular args" do
    assert_type(<<-CODE) { named_tuple_of({"y": char, "z": int32}) }
      def foo(x, **args)
        args
      end

      foo y: 'a', z: 3, x: "foo"
      CODE
  end

  it "matches double splat with regular splat" do
    assert_type(<<-CODE) { tuple_of([tuple_of([int32, char]), named_tuple_of({"x": string, "y": bool})]) }
      def foo(*args, **options)
        {args, options}
      end

      foo 1, 'a', x: "foo", y: true
      CODE
  end

  it "uses double splat in new" do
    assert_type(<<-CODE) { int32 }
      class Foo
        @x : Int32

        def initialize(**options)
          @x = options[:x]
        end

        def x
          @x
        end
      end

      Foo.new(x: 1).x
      CODE
  end

  it "uses restriction on double splat, doesn't match with empty named tuple" do
    assert_error <<-CODE, "no overload matches"
      def foo(**options : Int32)
      end

      foo
      CODE
  end

  it "uses restriction on double splat, doesn't match with empty named tuple (2)" do
    assert_error <<-CODE, "no overload matches"
      def foo(x, **options : Int32)
      end

      foo x: 1
      CODE
  end

  it "uses restriction on double splat, means all types must be that type" do
    assert_error <<-CODE, "no overload matches"
      def foo(**options : Int32)
      end

      foo x: 1, y: 'a'
      CODE
  end

  it "overloads based on double splat restriction" do
    assert_type(<<-CODE) { tuple_of([string, bool]) }
      def foo(**options : Int32)
        true
      end

      def foo(**options : Char)
        "foo"
      end

      x1 = foo x: 'a', y: 'b'
      x2 = foo x: 1, y: 2
      {x1, x2}
      CODE
  end

  it "uses double splat restriction" do
    assert_type(<<-CODE) { named_tuple_of({"x" => int32, "y" => char}).metaclass }
      def foo(**options : **T) forall T
        T
      end

      foo x: 1, y: 'a'
      CODE
  end

  it "uses double splat restriction, matches empty" do
    assert_type(<<-CODE) { named_tuple_of({} of String => Type).metaclass }
      def foo(**options : **T) forall T
        T
      end

      foo
      CODE
  end

  it "uses double splat restriction with concrete type" do
    assert_error <<-CODE, "no overload matches"
      struct NamedTuple(T)
        def self.foo(**options : **T)
        end
      end

      NamedTuple(x: Int32, y: Char).foo(x: 1, y: true)
      CODE
  end

  it "matches named args producing an empty double splat (#2678)" do
    assert_type(<<-CODE) { named_tuple_of({} of String => Type) }
      def test(x, **kwargs)
        kwargs
      end

      test(x: 7)
      CODE
  end
end
