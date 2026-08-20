require "../../spec_helper"

describe "Semantic: alias" do
  it "resolves alias type" do
    assert_type(<<-CODE) { types["Int32"].metaclass }
      alias Alias = Int32
      Alias
      CODE
  end

  it "declares alias inside type" do
    assert_type(<<-CODE) { types["Int32"].metaclass }
      alias Foo::Bar = Int32
      Foo::Bar
      CODE
  end

  it "works with alias type as restriction" do
    assert_type(<<-CODE) { int32 }
      alias Alias = Int32

      def foo(x : Alias)
        x
      end

      foo 1
      CODE
  end

  it "allows using alias type as generic type" do
    assert_type(<<-CODE) { int32 }
      class Foo(T)
        def initialize(x : T)
          @x = x
        end

        def x
          @x
        end
      end

      alias Num = Int32 | Float64

      f = Foo(Num).new(1)
      g = Foo(Num).new(1.5)
      1
      CODE
  end

  it "allows defining recursive aliases" do
    result = assert_type(<<-CODE) { int32 }
      class Foo(T)
      end

      alias Alias = Int32 | Foo(Alias)
      1
      CODE
    mod = result.program

    foo = mod.types["Foo"].as(GenericClassType)
    a = mod.types["Alias"].as(AliasType)

    foo_alias = foo.instantiate([a] of TypeVar)

    aliased_type = a.aliased_type.as(UnionType)
    union_types = aliased_type.union_types.sort_by &.to_s
    union_types[0].should eq(foo_alias)
    union_types[1].should eq(mod.int32)
  end

  it "allows defining recursive fun aliases" do
    result = assert_type(<<-CODE) { int32 }
      alias Alias = Alias -> Alias
      1
      CODE

    mod = result.program

    a = mod.types["Alias"].as(AliasType)
    aliased_type = a.aliased_type.as(ProcInstanceType)

    aliased_type.should eq(mod.proc_of(a, a))
  end

  it "allows recursive array with alias" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      alias Type = Nil | Pointer(Type)
      p = Pointer(Type).malloc(1_u64)
      1
      CODE
  end

  it "errors if alias already defined" do
    assert_error <<-CODE, "alias Alias is already defined"
      alias Alias = String
      alias Alias = Int32
      CODE
  end

  it "errors if alias is already defined as another type" do
    assert_error <<-CODE, "can't alias String because it's already defined as a class"
      alias String = Int32
      CODE
  end

  it "errors if defining infinite recursive alias" do
    assert_error <<-CODE, "infinite recursive definition of alias Alias"
      alias Alias = Alias
      Alias
      CODE
  end

  it "errors if defining infinite recursive alias in union" do
    assert_error <<-CODE, "infinite recursive definition of alias Alias"
      alias Alias = Int32 | Alias
      Alias
      CODE
  end

  it "allows using generic type of recursive alias as restriction (#488)" do
    assert_type(<<-CODE) { int32 }
      class Foo(T)
      end

      alias Rec = String | Foo(Rec)

      def command(request : Foo(Rec))
        1
      end

      foo = Foo(Rec).new
      command(foo)
      CODE
  end

  it "resolves type through alias (#563)" do
    assert_type(<<-CODE) { int32 }
      module Moo
        Foo = 1
      end

      alias Alias = Moo
      Alias::Foo
      CODE
  end

  it "errors if trying to resolve type of recursive alias" do
    assert_error <<-CODE, "undefined constant Rec::A"
      class Foo(T)
        A = 1
      end

      alias Rec = Int32 | Foo(Rec)

      Rec::A
      CODE
  end

  %w(class module struct).each do |type|
    it "reopens #{type} through alias" do
      assert_type(<<-CODE) { int32 }
        #{type} Foo
        end

        alias Bar = Foo

        #{type} Bar
          def self.bar
            1
          end
        end

        Bar.bar
        CODE
    end

    it "reopens #{type} through alias within itself" do
      assert_type <<-CODE { int32 }
        #{type} Foo
          alias Bar = Foo

          #{type} Bar
            def self.bar
              1
            end
          end
        end

        Foo.bar
        CODE
    end
  end

  %w(class struct).each do |type|
    it "inherits #{type} through alias" do
      assert_type(<<-CODE) { int32 }
        abstract #{type} Parent
        end

        alias Alias = Parent

        #{type} Child  < Alias
          def self.bar
            1
          end
        end

        Child.bar
        CODE
    end
  end

  it "includes module through alias" do
    assert_type(<<-CODE) { int32 }
      module Moo
        def bar
          1
        end
      end

      alias Alias = Moo

      class Foo
        include Alias
      end

      Foo.new.bar
      CODE
  end

  it "errors if declares alias inside if" do
    assert_error <<-CODE, "can't declare alias dynamically"
      if 1 == 2
        alias Foo = Int32
      end
      CODE
  end

  it "errors if trying to use typeof in alias" do
    assert_error <<-CODE, "can't use 'typeof' here"
      alias Foo = typeof(1)
      CODE
  end

  it "can use .class in alias (#2835)" do
    assert_type(<<-CODE) { union_of(int32.metaclass, string.metaclass).metaclass }
      alias Foo = Int32.class | String.class
      Foo
      CODE
  end

  it "uses constant in alias (#3259)" do
    assert_type(<<-CODE) { static_array_of(uint8, 10).metaclass }
      CONST = 10
      alias Alias = UInt8[CONST]
      Alias
      CODE
  end

  it "uses constant in alias with math (#3259)" do
    assert_type(<<-CODE) { static_array_of(uint8, 10).metaclass }
      CONST = 2*3 + 4
      alias Alias = UInt8[CONST]
      Alias
      CODE
  end

  it "looks up alias for macro resolution (#3548)" do
    assert_type(<<-CODE) { int32 }
      class Foo
        class Bar
          def self.baz
            1
          end
        end
      end

      alias Baz = Foo

      Baz::Bar.baz
      CODE
  end

  it "finds type through alias (#4645)" do
    assert_type(<<-CODE) { int32 }
      module FooBar
        module Foo
          A = 10
        end

        module Bar
          include Foo
        end
      end

      class Baz
        alias Bar = FooBar::Bar

        def test
          Bar::A
        end
      end

      Baz.new.test
      CODE
  end

  it "doesn't find type parameter in alias (#3502)" do
    assert_error <<-CODE, "undefined constant T"
      class A(T)
        alias B = A(T)
      end
      CODE
  end

  it "doesn't crash by infinite recursion against type alias and generics (#5329)" do
    assert_error <<-CODE, "can't cast Foo(Int32) to Bar"
      class Foo(T)
        def initialize(@foo : T)
        end
      end

      alias Bar = Foo(Bar | Int32)

      Foo(Bar).new(Foo.new(1).as(Bar))
      CODE
  end

  it "can pass recursive alias to proc" do
    assert_type(<<-CODE, inject_primitives: true) { nil_type }
      class Object
        def itself
          self
        end
      end

      alias Rec = Int32 | Array(Rec)

      a = uninitialized Rec

      f = ->(x : Rec) {}
      f.call(a.itself)
      CODE
  end

  it "overloads union type through alias" do
    assert_type(<<-CODE) { int32 }
      alias X = Int8 | Int32

      def foo(x : Int32)
        1
      end

      def foo(x : X)
        'a'
      end

      foo(1)
      CODE
  end
end
