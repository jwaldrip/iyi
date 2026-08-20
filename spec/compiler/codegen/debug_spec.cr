require "../../spec_helper"

describe "Code gen: debug" do
  it "codegens abstract struct (#3578)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      abstract struct Base
      end

      struct Foo < Base
      end

      struct Bar < Base
      end

      x = Foo.new || Bar.new
      CODE
  end

  it "codegens lib union (#7335)" do
    codegen <<-CODE, debug: Iyi::Debug::All
      lib Foo
        union Bar
          a : Int32
          b : Int16
          c : Int8
        end
      end

      x = Foo::Bar.new
      CODE
  end

  it "codegens extern union (#7335)" do
    codegen <<-CODE, debug: Iyi::Debug::All
      @[Extern(union: true)]
      struct Foo
        @a = uninitialized Int32
        @b = uninitialized Int16
        @c = uninitialized Int8
      end

      x = Foo.new
      CODE
  end

  it "inlines instance var access through getter in debug mode" do
    run(<<-CODE, debug: Iyi::Debug::All, filename: "foo.cr").to_i.should eq(2)
      struct Bar
        @x = 1

        def set
          @x = 2
        end

        def x
          @x
        end
      end

      class Foo
        @bar = Bar.new

        def set
          bar.set
        end

        def bar
          @bar
        end
      end

      foo = Foo.new
      foo.set
      foo.bar.x
      CODE
  end

  it "codegens correct debug info for untyped expression (#4007 and #4008)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      int = 3
      case int
      when 0
          puts 0
      when 1, 2, Int32
          puts "1 | 2 | Int32"
      else
          puts int
      end
      CODE
  end

  it "codegens correct debug info for new with custom allocate (#3945)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      class Foo
        def initialize
        end

        def self.allocate
          Pointer(UInt8).malloc(1_u64).as(self)
        end
      end

      Foo.new
      CODE
  end

  it "correctly restores debug location after fun change (#4254)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      class Foo
        def self.one
          TWO.two { three }
          self
        end

        def self.three
          1 + 2
        end

        def two(&block)
          block
        end
      end

      ONE = Foo.one
      TWO = Foo.new

      ONE.three
      CODE
  end

  it "has correct debug location after constant initialization in call with block (#4719)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      fun __crystal_malloc_atomic(size : UInt32) : Void*
        x = uninitialized Void*
        x
      end

      class Foo
      end

      class Bar
        def initialize
          yield
        end
      end

      A = Foo.new

      Bar.new { }

      A
      CODE
  end

  it "has debug info in closure inside if (#5593)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      def foo
        if true && true
          yield 1
        end
      end

      def bar(&block)
        block
      end

      foo do |i|
        bar do
          i
        end
      end
      CODE
  end

  it "doesn't emit incorrect debug info for closured self" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      def foo(&block : Int32 ->)
        block.call(1)
      end

      class Foo
        def bar
          foo do
            self
          end
        end
      end

      Foo.new.bar
      CODE
  end

  it "doesn't emit debug info for unused variable declarations (#9882)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      x : Int32
      CODE
  end

  it "emits global debug info for constants" do
    mod = codegen(<<-CODE, debug: Iyi::Debug::All)
      struct Bar
        def initialize(@x : Int32)
        end
      end

      A = Bar.new(41)

      v1 = A
      v1
      CODE

    str = mod.to_s
    str.should contain("DIGlobalVariable(name: \"A\", linkageName: \"A\",")
    str.should contain(%(~A:const_init))
  end

  it "emits global debug info once for constants read before assignment" do
    mod = codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      struct Bar
        def initialize(@x : Int32)
        end
      end

      A
      A = Bar.new(41)
      CODE

    str = mod.to_s
    str.scan(%r{DIGlobalVariable\(name: "A", linkageName: "A",}).size.should eq(1)
    str.should contain(%(~A:const_init))
  end

  it "keeps literal constants inlined in debug mode" do
    mod = codegen(<<-CODE, debug: Iyi::Debug::All)
      A = 1
      A
      CODE

    str = mod.to_s
    str.should_not match(/^@A =/)
    str.should contain("ret i32 1")
  end

  it "emits global debug info for class vars" do
    mod = codegen(<<-CODE, debug: Iyi::Debug::All)
      class Foo
        @@x = "world"

        def self.x
          @@x
        end
      end

      Foo.x
      CODE

    str = mod.to_s
    str.should match(/@"Foo::x" = global (?:ptr|%String\*) null, !dbg !/)
    str.should contain("DIGlobalVariable(name: \"Foo::x\", linkageName: \"Foo::x\",")
  end

  it "stores and restores debug location after jumping to main (#6920)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      Module.method

      module Module
        def self.value
          1 &+ 2
        end

        @@x : Int32 = value

        def self.method
          @@x
        end
      end
      CODE
  end

  it "stores and restores debug location after jumping to main (2)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      module Foo
        @@x : Int32 = begin
          y = 1
        end

        def self.x
          @@x
        end
      end

      Foo.x
      CODE
  end

  it "stores and restores debug location after jumping to main (3)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      def raise(exception)
        x = uninitialized NoReturn
        x
      end

      lib LibFoo
        $foo : ->
      end

      LibFoo.foo = ->{ }
      CODE
  end

  it "doesn't fail on constant read calls (#11416)" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      require "prelude"

      class Foo
        def foo
        end
      end

      def a_foo
        Foo.new
      end

      THE_FOO.foo

      THE_FOO = a_foo
      CODE
  end

  it "doesn't fail on splat expansions inside array-like literals" do
    run(<<-CODE, debug: Iyi::Debug::All).to_i.should eq(123)
      require "prelude"

      class Foo
        def each
          yield 1
          yield 2
          yield 3
        end
      end

      class Bar
        @bar = 0

        def <<(value)
          @bar = @bar &* 10 &+ value
        end

        def bar
          @bar
        end
      end

      x = Foo.new
      y = Bar{*x}
      y.bar
      CODE
  end

  it "codegens proc debug info" do
    codegen(<<-CODE, debug: Iyi::Debug::All)
      x = ->(n : Int32) { n &+ 1 }
      y : Proc(Int32, Int32)? = ->(n : Int32) { n &+ 2 }
      captured = 40
      z = ->(n : Int32) { captured &+ n }
      {x, y, z}
      CODE
  end

  {% unless LibLLVM::IS_LT_210 %}
    it "supports 128-bit enumerators" do
      codegen(<<-CODE, debug: Iyi::Debug::All).to_s.should contain(%(!DIEnumerator(name: "X", value: 1002003004005006007008009)))
        enum Foo : Int128
          X = 1002003004005006007008009_i128
        end

        x = Foo::X
        CODE
    end
  {% end %}

  it "doesn't fail if no top-level code follows discarded class var initializer (#15970)" do
    codegen <<-CODE, debug: Iyi::Debug::All
      module Foo
        @@x = 1
      end
      CODE
  end

  it "doesn't fail if class var initializer is followed by metaclass (#15970)" do
    codegen <<-CODE, debug: Iyi::Debug::All
      module Foo
        @@x = 1
      end

      Int32
      CODE
  end

  it "doesn't fail if Proc self is closured (#16382)" do
    codegen <<-CODE, debug: Iyi::Debug::All
      struct Proc
        def partial
          -> do
            self
          end
        end
      end

      -> { }.partial.call
      CODE
  end
end
