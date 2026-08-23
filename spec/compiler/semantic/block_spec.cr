require "../../spec_helper"

describe "Block inference" do
  it "infer type of empty block body" do
    assert_type(<<-CODE) { nil_type }
      def foo; yield; end

      foo do
      end
      CODE
  end

  it "infer type of block body" do
    input = parse(<<-CODE).as(Expressions)
      def foo; yield; end

      foo do
        x = 1
      end
      CODE
    result = semantic input
    input.last.as(Call).block.should_not(be_nil).body.type.should eq(result.program.int32)
  end

  it "infer type of block parameter" do
    input = parse(<<-CODE).as(Expressions)
      def foo
        yield 1
      end

      foo do |x|
        1
      end
      CODE
    result = semantic input
    mod = result.program
    input.last.as(Call).block.should_not(be_nil).args[0].type.should eq(mod.int32)
  end

  it "infer type of local variable" do
    assert_type(<<-CODE) { union_of(char, int32) }
      def foo
        yield 1
      end

      y = 'a'
      foo do |x|
        y = x
      end
      y
      CODE
  end

  it "infer type of yield" do
    assert_type(<<-CODE) { int32 }
      def foo
        yield
      end

      foo do
        1
      end
      CODE
  end

  it "infer type with union" do
    assert_type(<<-CODE) { union_of(array_of(int32), array_of(float64)) }
      require "prelude"
      a = [1] || [1.1]
      a.tap { |x| x }
      CODE
  end

  it "uses block arg, too many parameters" do
    assert_error <<-CODE, "too many block parameters (given 1, expected maximum 0)"
      def foo
        yield
      end

      foo do |x|
        x
      end
      CODE
  end

  it "yields with different types" do
    assert_type(<<-CODE) { union_of(int32, char) }
      def foo
        yield 1
        yield 'a'
      end

      foo do |x|
        x
      end
      CODE
  end

  it "break from block without value" do
    assert_type(<<-CODE) { nil_type }
      def foo; yield; end

      foo do
        break
      end
      CODE
  end

  it "break without value has nil type" do
    assert_type(<<-CODE) { nilable int32 }
      def foo; yield; 1; end
      foo do
        break if false
      end
      CODE
  end

  it "infers type of block before call" do
    result = assert_type(<<-CODE) { generic_class "Foo", float64 }
      struct Int32
        def foo
          10.5
        end
      end

      class Foo(T)
        def initialize(x : T)
          @x = x
        end
      end

      def bar(&block : Int32 -> U) forall U
        Foo(U).new(yield 1)
      end

      bar { |x| x.foo }
      CODE
    mod = result.program
    type = result.node.type.as(GenericClassInstanceType)
    type.type_vars["T"].type.should eq(mod.float64)
    type.instance_vars["@x"].type.should eq(mod.float64)
  end

  it "infers type of block before call taking other args free vars into account" do
    assert_type(<<-CODE) { generic_class "Foo", float64 }
      class Foo(X)
        def initialize(x : X)
          @x = x
        end
      end

      def foo(x : U, &block: U -> T) forall T, U
        Foo(T).new(yield x)
      end

      a = foo(1) do |x|
        10.5
      end
      CODE
  end

  it "reports error if yields a type that's not that one in the block specification" do
    assert_error <<-CODE, "argument #1 of yield expected to be Int32, not Float64"
      def foo(&block: Int32 -> )
        yield 10.5
      end

      foo {}
      CODE
  end

  it "reports error if yields a type that's not that one in the block specification" do
    assert_error <<-CODE, "argument #1 of yield expected to be Int32, not (Float64 | Int32)"
      def foo(&block: Int32 -> )
        yield (1 || 1.5)
      end

      foo {}
      CODE
  end

  it "reports error if yields a type that later changes and that's not that one in the block specification" do
    assert_error <<-CODE, "argument #1 of yield expected to be Int32, not (Float64 | Int32)"
      def foo(&block: Int32 -> )
        a = 1
        while true
          yield a
          a = 1.5
        end
      end

      foo {}
      CODE
  end

  it "reports error if missing arguments to yield" do
    assert_error <<-CODE, "wrong number of yield arguments (given 1, expected 2)"
      def foo(&block: Int32, Int32 -> )
        yield 1
      end

      foo { |x| x }
      CODE
  end

  it "reports error if block didn't return expected type" do
    assert_error <<-CODE, "expected block to return Float64, not Char"
      def foo(&block: Int32 -> Float64)
        yield 1
      end

      foo { 'a' }
      CODE
  end

  it "reports error if block type doesn't match" do
    assert_error <<-CODE, "expected block to return Float64, not (Float64 | Int32)"
      def foo(&block: Int32 -> Float64)
        yield 1
      end

      foo { 1 || 1.5 }
      CODE
  end

  it "reports error if block changes type" do
    assert_error <<-CODE, "type must be Float64"
      def foo(&block: Int32 -> Float64)
        yield 1
      end

      a = 10.5
      while true
        foo { a }
        a = 1
      end
      CODE
  end

  it "reports error on method instantiate (#4543)" do
    assert_error <<-CODE, "expected block to return Int32, not UInt32"
      class Foo
        @foo = 42

        def initialize(&block : -> Int32)
          @foo = yield
        end
      end

      Foo.new { 42u32 }
      CODE
  end

  it "matches block arg return type" do
    assert_type(<<-CODE) { generic_class "Foo", float64 }
      class Foo(T)
      end

      def foo(&block: Int32 -> Foo(T)) forall T
        yield 1
        Foo(T).new
      end

      foo { Foo(Float64).new }
      CODE
  end

  it "infers type of block with generic type" do
    assert_type(<<-CODE) { float64 }
      class Foo(T)
      end

      def foo(&block: Foo(Int32) -> )
        yield Foo(Int32).new
      end

      foo do |x|
        10.5
      end
      CODE
  end

  it "infer type with self block arg" do
    assert_type(<<-CODE) { nilable types["Foo"] }
      class Foo
        def foo(&block : self -> )
          yield self
        end
      end

      f = Foo.new
      a = nil
      f.foo do |x|
        a = x
      end
      a
      CODE
  end

  it "error with self input type doesn't match" do
    assert_error <<-CODE, "argument #1 of yield expected to be Foo, not Int32"
      class Foo
        def foo(&block : self -> )
          yield 1
        end
      end

      f = Foo.new
      f.foo {}
      CODE
  end

  it "error with self output type doesn't match" do
    assert_error <<-CODE, "expected block to return Foo, not Int32"
      class Foo
        def foo(&block : Int32 -> self )
          yield 1
        end
      end

      f = Foo.new
      f.foo { 1 }
      CODE
  end

  it "errors when using local variable with block parameter name" do
    assert_error "def foo; yield 1; end; foo { |a| }; a",
      "undefined local variable or method 'a'"
  end

  it "types empty block" do
    assert_type(<<-CODE) { nil_type }
      def foo
        ret = yield
        ret
      end

      foo { }
      CODE
  end

  it "preserves type filters in block" do
    assert_type(<<-CODE) { char }
      class Foo
        def bar
          'a'
        end
      end

      def foo
        yield 1
      end

      a = Foo.new || nil
      if a
        foo do |x|
          a.bar
        end
      else
        'b'
      end
      CODE
  end

  it "checks block type with virtual type" do
    assert_type(<<-CODE) { int32 }
      require "prelude"

      class Foo
      end

      class Bar < Foo
      end

      a = [] of Foo
      a << Bar.new

      a.map { |x| x.to_s }

      1
      CODE
  end

  it "maps block of union types to union types" do
    assert_type(<<-CODE) { array_of(union_of(types["Foo1"].virtual_type, types["Foo2"].virtual_type)) }
      require "prelude"

      class Foo1
      end

      class Bar1 < Foo1
      end

      class Foo2
      end

      class Bar2 < Foo2
      end

      a = [Foo1.new, Foo2.new, Bar1.new, Bar2.new]
      a.map { |x| x }
      CODE
  end

  it "does next from block without value" do
    assert_type(<<-CODE) { nil_type }
      def foo; yield; end

      foo do
        next
      end
      CODE
  end

  it "does next from block with value" do
    assert_type(<<-CODE) { int32 }
      def foo; yield; end

      foo do
        next 1
      end
      CODE
  end

  it "does next from block with value 2" do
    assert_type(<<-CODE, inject_primitives: true) { union_of(int32, bool) }
      def foo; yield; end

      foo do
        if 1 == 1
          next 1
        end
        false
      end
      CODE
  end

  it "ignores block parameter if not used" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      def foo(&block)
        yield 1
      end

      foo do |x|
        x + 1
      end
      CODE
  end

  it "allows yielding multiple types when a union is expected" do
    assert_type(<<-CODE) { array_of(float64) }
      require "prelude"

      class Foo
        include Enumerable(Int32 | Float64)

        def each
          yield 1
          yield 1.5
        end
      end

      foo = Foo.new
      foo.map &.to_f
      CODE
  end

  it "allows initialize with yield (#224)" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      class Foo
        @x : Int32

        def initialize
          @x = yield 1
        end

        def x
          @x
        end
      end

      foo = Foo.new do |a|
        a + 1
      end
      foo.x
      CODE
  end

  it "passes #233: block with initialize with default args" do
    assert_type(<<-CODE) { types["Foo"] }
      class Foo
        def initialize(x = nil)
          yield
        end
      end

      Foo.new {}
      CODE
  end

  it "errors if declares def inside block" do
    assert_error <<-CODE, "can't declare def dynamically"
      def foo
        yield
      end

      foo do
        def bar
        end
      end
      CODE
  end

  it "errors if declares macro inside block" do
    assert_error <<-CODE, "can't declare macro dynamically"
      def foo
        yield
      end

      foo do
        macro bar
        end
      end
      CODE
  end

  it "errors if declares fun inside block" do
    assert_error <<-CODE, "can't declare fun dynamically"
      def foo
        yield
      end

      foo do
        fun bar : Int32
        end
      end
      CODE
  end

  it "errors if declares class inside block" do
    assert_error <<-CODE, "can't declare class dynamically"
      def foo
        yield
      end

      foo do
        class Foo
        end
      end
      CODE
  end

  it "errors if declares module inside block" do
    assert_error <<-CODE, "can't declare module dynamically"
      def foo
        yield
      end

      foo do
        module Foo
        end
      end
      CODE
  end

  it "errors if declares lib inside block" do
    assert_error <<-CODE, "can't declare lib dynamically"
      def foo
        yield
      end

      foo do
        lib LibFoo
        end
      end
      CODE
  end

  it "errors if declares alias inside block" do
    assert_error <<-CODE, "can't declare alias dynamically"
      def foo
        yield
      end

      foo do
        alias A = Int32
      end
      CODE
  end

  it "errors if declares include inside block" do
    assert_error <<-CODE, "can't include dynamically"
      def foo
        yield
      end

      foo do
        include Int32
      end
      CODE
  end

  it "errors if declares extend inside block" do
    assert_error <<-CODE, "can't extend dynamically"
      def foo
        yield
      end

      foo do
        extend Int32
      end
      CODE
  end

  it "errors if declares enum inside block" do
    assert_error <<-CODE, "can't declare enum dynamically"
      def foo
        yield
      end

      foo do
        enum Foo
          A
        end
      end
      CODE
  end

  it "allows alias as block fun type" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      alias Alias = Int32 -> Int32

      def foo(&block : Alias)
        block.call(1)
      end

      foo do |x|
        x + 1
      end
      CODE
  end

  it "errors if alias is not a fun type" do
    assert_error <<-CODE, "expected block type to be a function type, not Int32"
      alias Alias = Int32

      def foo(&block : Alias)
        block.call(1)
      end

      foo do |x|
        x + 1
      end
      CODE
  end

  it "errors if proc is not instantiated" do
    assert_error <<-CODE, "can't create an instance of generic class Proc(*T, R) without specifying its type vars"
      def capture(&block : Proc)
        block
      end

      capture { }
      CODE
  end

  it "passes #262" do
    assert_type(<<-CODE) { array_of(bool) }
      require "prelude"

      h = {} of String => Int32
      h.map { true }
      CODE
  end

  it "allows invoking method on a object of a captured block with a type that was never instantiated" do
    assert_type(<<-CODE) { proc_of(types["Bar"], void) }
      require "prelude"

      class Bar
        def initialize(@bar : NoReturn)
        end

        def bar
          @bar
        end
      end

      def foo(&block : Bar ->)
        block
      end

      def method(bar)
        bar.bar
      end

      foo do |bar|
        method(bar).baz
      end
      CODE
  end

  it "types bug with yield not_nil! that is never not nil" do
    assert_type(<<-CODE, inject_primitives: true) { nilable(int32) }
      lib LibC
        fun exit : NoReturn
      end

      def foo
        key = nil
        if 1 == 2
          yield LibC.exit
        end
        yield 1
      end

      extra = nil

      foo do |key|
        if 1 == 1
          extra = 1
          extra + key
        end
      end

      extra
      CODE
  end

  it "ignores void return type (#427)" do
    assert_type(<<-CODE) { nil_type }
      lib Fake
        fun foo(func : -> Void)
      end

      def foo(&block : -> Void)
        Fake.foo block
      end

      foo do
        1
      end
      CODE
  end

  it "ignores void return type (2) (#427)" do
    assert_type(<<-CODE) { int32 }
      def foo(&block : Int32 -> Void)
        yield 1
      end

      foo do
        1
      end
      CODE
  end

  it "ignores void return type (3) (#427)" do
    assert_type(<<-CODE) { int32 }
      alias Alias = Int32 -> Void

      def foo(&block : Alias)
        yield 1
      end

      foo do
        1
      end
      CODE
  end

  it "ignores void return type (4)" do
    assert_type(<<-CODE) { int32 }
      alias Alias = Void

      def foo(&block : -> Alias)
        yield
      end

      foo do
        1
      end
      CODE
  end

  it "uses block return type as return type, even if can't infer block type" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      class Foo
        def initialize(@foo : Int32)
        end

        def foo
          @foo
        end
      end

      def bar(&block : -> Int32)
        block
      end

      f = ->(x : Foo) {
        bar { x.foo }
      }

      foo = Foo.new(100)
      block = f.call(foo)
      block.call
      CODE
  end

  it "uses block var with same name as local var" do
    assert_type(<<-CODE) { int32 }
      def foo
        yield true
      end

      a = 1
      foo do |a|
        a
      end
      a
      CODE
  end

  it "types recursive hash assignment" do
    assert_type(<<-CODE) { array_of int32 }
      require "prelude"

      class Hash
        def map
          ary = Array(typeof(yield first_key, first_value)).new(@size)
          each do |k, v|
            ary.push yield k, v
          end
          ary
        end
      end

      hash = {} of Int32 => Int32
      z = hash.map {|key| key + 1 }
      hash[1] = z.size
      z
      CODE
  end

  it "errors if invoking new with block when no initialize is defined" do
    assert_error <<-CODE, "'Foo.new' is not expected to be invoked with a block, but a block was given"
      class Foo
      end

      Foo.new { }
      CODE
  end

  it "recalculates call that uses block arg output as free var" do
    assert_type(<<-CODE) { union_of(char, int32).metaclass }
      def foo(&block : Int32 -> U) forall U
        block
        U
      end

      class Foo
        def initialize
          @x = 1
        end

        def x=(@x : Char)
        end

        def bar
          foo do |x|
            @x
          end
        end
      end

      z = Foo.new.bar
      Foo.new.x = 'a'
      z
      CODE
  end

  it "finds type inside module in block" do
    assert_type(<<-CODE) { types["Moo"].types["Bar"] }
      module Moo
        class Foo
        end

        class Bar
          def initialize(&block : Int32 -> U) forall U
            block
          end
        end
      end

      z = nil
      module Moo
        z = Bar.new { Foo.new }
      end
      z
      CODE
  end

  it "passes &->f" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      def foo
      end

      def bar(&block)
        yield
        1
      end

      bar &->foo
      CODE
  end

  it "errors if declares class inside captured block" do
    assert_error <<-CODE, "can't declare class dynamically"
      def foo(&block)
        block.call
      end

      foo do
        class B
        end
      end
      CODE
  end

  it "doesn't assign block variable type to last value (#694)" do
    assert_type(<<-CODE) { int32 }
      def foo
        yield 1
      end

      z = 1
      foo do |x|
        z = x
        x = "a"
      end
      z
      CODE
  end

  it "errors if yields from top level" do
    assert_error <<-CODE, "can't use `yield` outside a method"
      yield
      CODE
  end

  it "errors on recursive yield" do
    assert_error <<-CODE, "recursive block expansion"
      def foo
        yield

        foo do
        end
      end

      foo {}
      CODE
  end

  it "errors on recursive yield with non ProcNotation restriction (#6896)" do
    assert_error <<-CODE, "recursive block expansion"
      def foo(&block : -> Int32)
        yield

        foo do
          1
        end
      end

      foo { 1 }
      CODE
  end

  it "errors on recursive yield with ProcNotation restriction" do
    assert_error <<-CODE, "recursive block expansion"
      def foo(&block : -> Int32)
        yield

        foo do
          1
        end
      end

      foo { 1 }
      CODE
  end

  it "binds to proc, not only to its body (#1796)" do
    assert_type(<<-CODE) { union_of(int32, char).metaclass }
      def yielder(&block : Int32 -> U) forall U
        yield 1
        U
      end

      yielder { next 'a' if true; 1 }
      CODE
  end

  it "binds block return type free variable even if there are no block parameters (#1797)" do
    assert_type(<<-CODE) { int32.metaclass }
      def yielder(&block : -> U) forall U
        yield
        U
      end

      yielder { 1 }
      CODE
  end

  it "returns from proc literal" do
    assert_type(<<-CODE, inject_primitives: true) { union_of int32, float64 }
      foo = ->{
        if 1 == 1
          return 1
        end

        1.5
      }

      foo.call
      CODE
  end

  it "errors if returns from captured block" do
    assert_error <<-CODE, "can't return from captured block, use next"
      def foo(&block)
        block
      end

      def bar
        foo do
          return
        end
      end

      bar
      CODE
  end

  it "errors if breaks from captured block" do
    assert_error <<-CODE, "can't break from captured block, try using `next`."
      def foo(&block)
        block
      end

      def bar
        foo do
          break
        end
      end

      bar
      CODE
  end

  it "errors if doing next in proc literal" do
    assert_error <<-CODE, "invalid next"
      foo = ->{
        next
      }
      foo.call
      CODE
  end

  it "does next from captured block" do
    assert_type(<<-CODE, inject_primitives: true) { union_of int32, float64 }
      def foo(&block : -> T) forall T
        block
      end

      f = foo do
        if 1 == 1
          next 1
        end

        next 1.5
      end

      f.call
      CODE
  end

  it "sets captured block type to that of restriction" do
    assert_type(<<-CODE) { proc_of(union_of(int32, string)) }
      def foo(&block : -> Int32 | String)
        block
      end

      foo { 1 }
      CODE
  end

  it "sets captured block type to that of restriction with alias" do
    assert_type(<<-CODE) { proc_of(union_of(int32, string)) }
      alias Alias = -> Int32 | String
      def foo(&block : Alias)
        block
      end

      foo { 1 }
      CODE
  end

  it "matches block with generic type and free var" do
    assert_type(<<-CODE) { int32.metaclass }
      class Foo(T)
      end

      def foo(&block : -> Foo(T)) forall T
        block
        T
      end

      foo { Foo(Int32).new }
      CODE
  end

  it "doesn't mix local var with block var, using break (#2314)" do
    assert_type(<<-CODE) { bool }
      def foo
        yield 1
      end

      x = true
      foo do |x|
        break
      end
      x
      CODE
  end

  it "doesn't mix local var with block var, using next (#2314)" do
    assert_type(<<-CODE) { bool }
      def foo
        yield 1
      end

      x = true
      foo do |x|
        next
      end
      x
      CODE
  end

  ["Object", "Bar | Object", "(Object ->)", "( -> Object)"].each do |string|
    it "errors if using #{string} as block return type (#2358)" do
      assert_error <<-CODE, "use a more specific type"
        class Foo(T)
        end

        class Bar
        end

        def capture(&block : -> #{string})
          block
        end

        capture { 1 }
        CODE
    end
  end

  it "yields splat" do
    assert_type(<<-CODE) { tuple_of([char, int32]) }
      def foo
        tup = {1, 'a'}
        yield *tup
      end

      foo do |x, y|
        {y, x}
      end
      CODE
  end

  it "yields splat and non splat" do
    assert_type(<<-CODE) { tuple_of([nilable(char), union_of(int32, bool)]) }
      def foo
        tup = {1, 'a'}
        yield *tup

        yield true, nil
      end

      foo do |x, y|
        {y, x}
      end
      CODE
  end

  it "uses splat in block parameter" do
    assert_type(<<-CODE) { tuple_of([int32, char]) }
      def foo
        yield 1, 'a'
      end

      foo do |*args|
        args
      end
      CODE
  end

  it "uses splat in block parameter, many args" do
    assert_type(<<-CODE) { tuple_of([int32, tuple_of([char, bool, nil_type]), float64, string]) }
      def foo
        yield 1, 'a', true, nil, 1.5, "hello"
      end

      foo do |x, *y, z, w|
        {x, y, z, w}
      end
      CODE
  end

  it "uses splat in block parameter, but not enough yield expressions" do
    assert_error <<-CODE, "too many block parameters (given 3+, expected maximum 1)"
      def foo
        yield 1
      end

      foo do |x, y, z, *w|
        {x, y, z, w}
      end
      CODE
  end

  it "errors if splat parameter becomes a union" do
    assert_error <<-CODE, "yield argument to block splat parameter must be a Tuple"
      def foo
        yield 1
        yield 1, 2
      end

      foo do |*args|
      end
      CODE
  end

  it "auto-unpacks tuple" do
    assert_type(<<-CODE) { tuple_of([int32, char]) }
      def foo
        tup = {1, 'a'}
        yield tup
      end

      foo do |x, y|
        {x, y}
      end
      CODE
  end

  it "auto-unpacks tuple, less than max" do
    assert_type(<<-CODE) { tuple_of([int32, char]) }
      def foo
        tup = {1, 'a', true}
        yield tup
      end

      foo do |x, y|
        {x, y}
      end
      CODE
  end

  it "auto-unpacks with block arg type" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      def foo(&block : {Int32, Int32} -> _)
        yield({1, 2})
      end

      foo do |x, y|
        x + y
      end
      CODE
  end

  it "auto-unpacks tuple, captured block" do
    assert_type(<<-CODE, inject_primitives: true) { tuple_of([int32, char]) }
      def foo(&block : {Int32, Char} -> _)
        tup = {1, 'a'}
        block.call tup
      end

      foo do |x, y|
        {x, y}
      end
      CODE
  end

  it "auto-unpacks tuple, captured empty block" do
    assert_no_errors <<-CODE, inject_primitives: true
      def foo(&block : {Int32, Char} -> _)
        tup = {1, 'a'}
        block.call tup
      end

      foo do |x, y|
      end
      CODE
  end

  it "auto-unpacks tuple, captured block with multiple statements" do
    assert_type(<<-CODE, inject_primitives: true) { tuple_of([float64, int32, bool]) }
      def foo(&block : {Float64, Int32} -> _)
        tup = {1.0, 3}
        block.call tup
      end

      foo do |x, y|
        z = x < y
        {x, y, z}
      end
      CODE
  end

  it "auto-unpacks tuple, less than max, captured block" do
    assert_type(<<-CODE, inject_primitives: true) { tuple_of([int32, char]) }
      def foo(&block : {Int32, Char, Bool} -> _)
        tup = {1, 'a', true}
        block.call tup
      end

      foo do |x, y|
        {x, y}
      end
      CODE
  end

  it "doesn't auto-unpack tuple, more args" do
    assert_error <<-CODE, "too many block parameters (given 3, expected maximum 2)"
      def foo
        tup = {1, 'a'}
        yield tup, true
      end

      foo do |x, y, z|
      end
      CODE
  end

  it "auto-unpacks tuple, too many args" do
    assert_error <<-CODE, "too many block parameters (given 3, expected maximum 2)"
      def foo
        tup = {1, 'a'}
        yield tup
      end

      foo do |x, y, z|
      end
      CODE
  end

  it "auto-unpacks tuple, too many args, captured block" do
    assert_error <<-CODE, "too many block parameters (given 3, expected maximum 2)"
      def foo(&block : {Int32, Char} -> _)
        tup = {1, 'a'}
        block.call tup
      end

      foo do |x, y, z|
      end
      CODE
  end

  it "doesn't crash on #2531" do
    run(<<-CODE).to_i.should eq(10)
      def foo
        yield
      end

      value = true ? 1 : nil
      foo do
        value ? nil : nil
      end
      value ? 10 : 20
      CODE
  end

  it "yields in overload, matches type" do
    assert_type(<<-CODE) { union_of(int32, int64) }
      struct Int
        def foo(&block : self ->)
          yield self
        end
      end

      (1 || 1_i64).foo do |x|
        x
      end
      CODE
  end

  it "uses free var in return type in captured block" do
    assert_type(<<-CODE) { int32.metaclass }
      class U
      end

      def foo(&block : -> U) forall U
        block
        U
      end

      foo { 1 }
      CODE
  end

  it "uses free var in return type with tuple type" do
    assert_type(<<-CODE) { tuple_of([tuple_of([int32, int32]), tuple_of([int32, int32]).metaclass]) }
      class T; end

      class U; end

      class Foo(T)
        def initialize(@x : T)
        end

        def foo(&block : T -> U) forall U
          {yield(@x), U}
        end
      end

      Foo.new(1).foo { |x| {x, x} }
      CODE
  end

  it "reports mismatch with generic argument type in output type" do
    assert_error(<<-CODE, "expected block to return String, not Int32")
      class Foo(T)
        def foo(&block : -> T)
        end
      end

      Foo(String).new.foo { 1 }
      CODE
  end

  it "reports mismatch with generic argument type in input type" do
    assert_error(<<-CODE, "argument #1 of yield expected to be String, not Int32")
      class Foo(T)
        def foo(&block : T -> )
          yield 1
        end
      end

      Foo(String).new.foo {}
      CODE
  end

  it "unpacks block argument" do
    assert_type(<<-CODE) { tuple_of([int32, char]) }
      def foo
        yield({1, 'a'})
      end

      foo do |(x, y)|
        {x, y}
      end
      CODE
  end

  it "correctly types unpacked tuple block arg after block (#3339)" do
    assert_type(<<-CODE) { int32 }
      def foo
        yield({""})
      end

      i = 1
      foo do |(i)|

      end
      i
      CODE
  end

  it "can infer block type given that the method has a return type (#7160)" do
    assert_type(<<-CODE) { int32 }
      struct Int32
        def self.foo
          0
        end
      end

      class Node
        @child : Node?

        def sum : Int32
          if child = @child
            child.call(&.sum)
          else
            0
          end
        end

        def call(&block : self -> T) forall T
          T.foo
        end
      end

      Node.new.sum
      CODE
  end

  it "doesn't crash on cleaning up typeof node without dependencies (#8669)" do
    assert_no_errors <<-CODE
      def foo(&)
      end

      foo do
        typeof(bar)
      end
      CODE
  end

  it "respects block arg restriction when block has a splat parameter (#6473)" do
    assert_type(<<-CODE) { int32 }
      def foo(&block : Int32 ->)
        yield 1
      end

      def bar(x)
        x
      end

      foo do |*x|
        bar(*x)
      end
      CODE
  end

  it "respects block arg restriction when block has a splat parameter (2) (#9524)" do
    assert_type(<<-CODE) { tuple_of([int32, int32]) }
      def foo(&block : {Int32, Int32} ->)
        yield({1, 2})
      end

      def bar(x)
        x
      end

      foo do |*x|
        bar(*x)
      end
      CODE
  end

  it "allows underscore in block return type even if the return type can't be computed" do
    assert_no_errors <<-CODE
      def foo(& : -> _)
        yield
      end

      def recursive
        if true
          foo { recursive }
        end
      end

      recursive
      CODE
  end

  it "doesn't fail with 'already had enclosing call' (#11200)" do
    assert_no_errors <<-CODE
      def capture(&block)
        block
      end

      abstract class Foo
      end

      class Bar(Input) < Foo
        def method
        end

        def foo
          capture do
            self.method
            Baz(Input)
          end
        end
      end

      class Baz(Input) < Bar(Input)
      end

      foo = Bar(Bool).new.as(Foo)
      foo.foo
      CODE
  end

  it "renders expected block return type of a free variable on mismatch" do
    assert_error(<<-CODE, "expected block to return Int64, not String")
      struct Foo
        def bar(arg : U, &block : -> U) forall U
        end
      end

      Foo.new.bar(1_i64) { "hi" }
      CODE
  end
end
