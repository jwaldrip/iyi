require "../../spec_helper"

describe "Code gen: lib" do
  pending "codegens lib var set and get" do
    run(<<-CODE).to_i.should eq(1)
      lib LibC
        $errno : Int32
      end

      LibC.errno = 1
      LibC.errno
      CODE
  end

  it "call to void function" do
    run(<<-CODE)
      lib LibC
        fun srand(x : UInt32) : Void
      end

      def foo
        LibC.srand(0_u32)
      end

      foo
      CODE
  end

  it "allows passing type to LibC if it has a converter with to_unsafe" do
    codegen(<<-CODE)
      lib LibC
        fun foo(x : Int32) : Int32
      end

      class Foo
        def to_unsafe
          1
        end
      end

      LibC.foo Foo.new
      CODE
  end

  it "allows passing type to LibC if it has a converter with to_unsafe (bug)" do
    codegen(<<-CODE)
      require "prelude"

      lib LibC
        fun foo(x : UInt8*)
      end

      def foo
        yield 1
      end

      LibC.foo(foo &.to_s)
      CODE
  end

  it "allows setting/getting external variable as function pointer" do
    codegen(<<-CODE)
      require "prelude"

      lib LibC
        $x : ->
      end

      LibC.x = ->{}
      LibC.x.call
      CODE
  end

  it "can use enum as fun argument" do
    codegen(<<-CODE)
      enum Foo
        A
      end

      lib LibC
        fun foo(x : Foo)
      end

      LibC.foo(Foo::A)
      CODE
  end

  it "can use enum as fun return" do
    codegen(<<-CODE)
      enum Foo
        A
      end

      lib LibC
        fun foo : Foo
      end

      LibC.foo
      CODE
  end

  it "can use tuple as fun return" do
    test_c(<<-C, <<-CODE, &.to_i.should eq(3))
      struct s {
        int x;
        int y;
      };

      struct s foo() {
        struct s a = {1, 2};
        return a;
      }
      C
      lib LibFoo
        fun foo : {Int32, Int32}
      end

      tuple = LibFoo.foo
      tuple[0] + tuple[1]
      CODE
  end

  it "get fun field from struct (#672)" do
    run(<<-CODE).to_i.should eq(10)
      require "prelude"

      lib Moo
        struct Type
          func : (Type*) -> Int32
        end
      end

      p = Pointer(Moo::Type).malloc(1)
      p.value.func = -> (t: Moo::Type*) { 10 }
      p.value.func.call(p)
      CODE
  end

  it "get fun field from union (#672)" do
    run(<<-CODE).to_i.should eq(10)
      require "prelude"

      lib Moo
        union Type
          func : (Type*) -> Int32
        end
      end

      p = Pointer(Moo::Type).malloc(1)
      p.value.func = -> (t: Moo::Type*) { 10 }
      p.value.func.call(p)
      CODE
  end

  it "refers to lib type (#960)" do
    codegen(<<-CODE)
      lib Thing
      end

      Thing
      CODE
  end

  it "distinguishes lib `type` aliases of the same underlying type in codegen (#16695)" do
    run(<<-CODE).to_i.should_not eq(0)
      lib LibFoo
        type A = Void
        type B = Void
      end

      class Object
        def id
          crystal_type_id # this call creates a dispatch
        end
      end
      LibFoo::A.id &- LibFoo::B.id
      CODE
  end

  it "allows invoking out with underscore " do
    codegen(<<-CODE)
      lib Lib
        fun foo(x : Int32*) : Float64
      end

      Lib.foo out _
      CODE
  end

  it "passes int as another float type in literal" do
    codegen(<<-CODE)
      lib LibFoo
        fun foo(x : Int32)
      end

      LibFoo.foo 1234.5
      CODE
  end

  it "passes nil to varargs (#1570)" do
    codegen(<<-CODE)
      lib LibFoo
        fun foo(...)
      end

      LibFoo.foo(nil)
      CODE
  end

  it "casts C fun to Crystal proc when accessing instance var (#2515)" do
    codegen(<<-CODE)
      require "prelude"

      lib LibFoo
        struct Some
          x : ->
        end
      end

      LibFoo::Some.new.to_s
      CODE
  end

  it "doesn't crash when casting -1 to UInt32 (#3594)" do
    codegen(<<-CODE)
      lib LibFoo
        fun foo(x : UInt32) : Nil
      end

      LibFoo.foo(-1)
      CODE
  end

  it "doesn't crash with nil and varargs (#4414)" do
    codegen(<<-CODE)
      lib LibFoo
        fun foo(Void*, ...)
      end

      x = nil
      LibFoo.foo(x)
      CODE
  end

  it "uses static array in lib extern (#5688)" do
    codegen(<<-CODE)
      lib LibFoo
        $x : Int32[10]
      end

      LibFoo.x
      CODE
  end
end
