require "../../spec_helper"

describe "Semantic: extern struct" do
  it "declares extern struct with no constructor" do
    assert_type(<<-CODE) { int32 }
      @[Extern]
      struct Foo
        @x = uninitialized Int32

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "declares with constructor" do
    assert_type(<<-CODE) { int32 }
      @[Extern]
      struct Foo
        @x = uninitialized Int32

        def initialize(@x)
        end

        def foo
          @x
        end
      end

      Foo.new(1).foo
      CODE
  end

  it "overrides getter" do
    assert_type(<<-CODE) { char }
      @[Extern]
      struct Foo
        @x = uninitialized Int32

        def x
          'a'
        end
      end

      Foo.new.x
      CODE
  end

  it "can be passed to C fun" do
    assert_type(<<-CODE) { float64 }
      @[Extern]
      struct Foo
        @x = uninitialized Int32
      end

      lib LibFoo
        fun foo(x : Foo) : Float64
      end

      LibFoo.foo(Foo.new)
      CODE
  end

  it "can include module" do
    assert_type(<<-CODE) { int32 }
      module Moo
        @x = uninitialized Int32

        def x
          @x
        end
      end

      @[Extern]
      struct Foo
        include Moo
      end

      Foo.new.x
      CODE
  end

  it "errors if using non-primitive for field type" do
    assert_error <<-CODE, "only primitive types, pointers, structs, unions, enums and tuples are allowed in extern struct declarations"
      class Bar
      end

      @[Extern]
      struct Foo
        @x = uninitialized Bar
      end
      CODE
  end

  it "errors if using non-primitive for field type via module" do
    assert_error <<-CODE, "only primitive types, pointers, structs, unions, enums and tuples are allowed in extern struct declarations"
      class Bar
      end

      module Moo
        @x = uninitialized Bar
      end

      @[Extern]
      struct Foo
        include Moo
      end
      CODE
  end

  it "errors if using non-primitive type in constructor" do
    assert_error <<-CODE, "only primitive types, pointers, structs, unions, enums and tuples are allowed in extern struct declarations"
      class Bar
      end

      @[Extern]
      struct Foo
        def initialize
          @x = Bar.new
        end
      end
      CODE
  end

  it "declares extern union with no constructor" do
    assert_type(<<-CODE) { int32 }
      @[Extern(union: true)]
      struct Foo
        @x = uninitialized Int32

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "can use extern struct in lib" do
    assert_type(<<-CODE) { types["Foo"] }
      @[Extern]
      struct Foo
      end

      lib LibFoo
        fun foo(x : Foo) : Foo
      end

      foo = Foo.new
      LibFoo.foo(foo)
      CODE
  end

  it "can new with named args" do
    assert_type(<<-CODE) { types["A"] }
      @[Extern]
      struct A
        def initialize(@x : Int32)
        end
      end

      A.new(x: 6)
      CODE
  end
end
