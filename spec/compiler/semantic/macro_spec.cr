require "../../spec_helper"

describe "Semantic: macro" do
  it "types macro" do
    assert_type(<<-CODE) { int32 }
      macro foo
        1
      end

      foo
      CODE
  end

  it "errors if macro uses undefined variable" do
    assert_error "macro foo(x) {{y}} end; foo(1)",
      "undefined macro variable 'y'"
  end

  it "types macro def" do
    assert_type(<<-CODE) { int32 }
      class Foo
        def foo : Int32
          {{ @type }}
          1
        end
      end

      Foo.new.foo
      CODE
  end

  it "errors if macro def type not found" do
    assert_error <<-CODE, "undefined constant Foo"
      class Baz
        def foo : Foo
          {{ @type }}
        end
      end

      Baz.new.foo
      CODE
  end

  it "errors if macro def type doesn't match found" do
    assert_error <<-CODE, "method Foo#foo must return Int32 but it is returning Char"
      class Foo
        def foo : Int32
          {{ @type}}
          'a'
        end
      end

      Foo.new.foo
      CODE
  end

  it "allows subclasses of return type for macro def" do
    run(<<-CODE).to_i.should eq(2)
      class Foo
        def foo
          1
        end
      end

      class Bar < Foo
        def foo
          2
        end
      end

      class Baz
        def foobar : Foo
          {{ @type }}
          Bar.new
        end
      end

      Baz.new.foobar.foo
      CODE
  end

  it "allows return values that include the return type of the macro def" do
    run(<<-CODE).to_i.should eq(2)
      module Foo
        def foo
          1
        end
      end

      class Bar
        include Foo

        def foo
          2
        end
      end

      class Baz
        def foobar : Foo
          {{ @type }}
          Bar.new
        end
      end

      Baz.new.foobar.foo
      CODE
  end

  it "allows generic return types for macro def" do
    run(<<-CODE).to_i.should eq(2)
      class Foo(T)
        def foo
          @foo
        end

        def initialize(@foo : T)
        end
      end

      class Baz
        def foobar : Foo(Int32)
          {{ @type }}
          Foo.new(2)
        end
      end

      Baz.new.foobar.foo
      CODE

    assert_error(<<-CODE, "method Bar#bar must return Foo(String) but it is returning Foo(Int32)")
      class Foo(T)
        def initialize(@foo : T)
        end
      end

      class Bar
        def bar : Foo(String)
          {{ @type }}
          Foo.new(3)
        end
      end

      Bar.new.bar
      CODE
  end

  it "allows union return types for macro def" do
    assert_type(<<-CODE) { int32 }
      class Foo
        def foo : String | Int32
          {{ @type }}
          1
        end
      end

      Foo.new.foo
      CODE
  end

  it "types macro def that calls another method" do
    assert_type(<<-CODE) { int32 }
      def bar_baz
        1
      end

      class Foo
        def foo : Int32
          {{ @type }}
          {% begin %}
            bar_{{ "baz".id }}
          {% end %}
        end
      end

      Foo.new.foo
      CODE
  end

  it "types macro def that calls another method inside a class" do
    assert_type(<<-CODE) { int32 }
      class Foo
        def bar_baz
          1
        end

        def foo : Int32
          {{ @type }}
          {% begin %}
            bar_{{ "baz".id }}
          {% end %}
        end
      end

      Foo.new.foo
      CODE
  end

  it "types macro def that calls another method inside a class" do
    assert_type(<<-CODE) { int32 }
      class Foo
        def foo : Int32
          {{ @type }}
          {% begin %}
            bar_{{ "baz".id }}
          {% end %}
        end
      end

      class Bar < Foo
        def bar_baz
          1
        end
      end

      Bar.new.foo
      CODE
  end

  it "types macro def with argument" do
    assert_type(<<-CODE) { int32 }
      class Foo
        def foo(x) : Int32
          {{ @type }}
          x
        end
      end

      Foo.new.foo(1)
      CODE
  end

  it "expands macro with block" do
    assert_type(<<-CODE) { int32 }
      macro foo
        {{yield}}
      end

      foo do
        def bar
          1
        end
      end

      bar
      CODE
  end

  it "expands macro with block and argument to yield" do
    assert_type(<<-CODE) { int32 }
      macro foo
        {{yield 1}}
      end

      foo do |value|
        def bar
          {{value}}
        end
      end

      bar
      CODE
  end

  it "errors if find macros but wrong arguments" do
    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 1, expected 0)", inject_primitives: true)
      macro foo
        1
      end

      foo(1)
      CODE
  end

  it "errors if find macros but missing argument" do
    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 0, expected 1)")
      macro foo(x)
        1
      end

      foo
      CODE

    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 0, expected 1)")
      private macro foo(x)
        1
      end

      foo
      CODE
  end

  describe "raise" do
    describe "inside macro" do
      describe "without node" do
        it "does not contain `expanding macro`" do
          ex = assert_error(<<-CODE, "OH NO")
            macro foo
              {{ raise "OH NO" }}
            end

            foo
            CODE

          ex.to_s.should_not contain("expanding macro")
        end

        it "supports an empty message (#8631)" do
          assert_error(<<-CODE, "")
            macro foo
              {{ raise "" }}
            end

            foo
          CODE
        end

        it "renders both frames (#7147)" do
          ex = assert_error(<<-CODE, "OH NO")
            macro macro_raise(node)
              {% raise "OH NO" %}
            end

            macro_raise 10
          CODE

          ex.to_s.should contain "OH NO"
          ex.to_s.should contain "error in line 2"
          ex.to_s.should contain "error in line 5"
          ex.to_s.scan("error in line").size.should eq 2
        end
      end

      describe "with node" do
        it "contains the message and not `expanding macro` (#5669)" do
          ex = assert_error(<<-CODE, "OH")
            macro foo(x)
              {{ x.raise "OH\nNO" }}
            end

            foo(1)
          CODE

          ex.to_s.should contain "NO"
          ex.to_s.should_not contain("expanding macro")
        end

        it "renders both frames (#7147)" do
          ex = assert_error(<<-'CODE', "OH")
            macro macro_raise_on(arg)
              {% arg.raise "OH NO" %}
            end

            macro_raise_on 123
          CODE

          ex.to_s.should contain "OH NO"
          ex.to_s.should contain "error in line 5"
          ex.to_s.scan("error in line").size.should eq 2
        end

        it "pointing at the correct node in complex/nested macro (#7147)" do
          ex = assert_error(<<-'CODE', "Value method must be an instance method")
            class Child
              def self.value : Nil
              end
            end

            module ExampleModule
              macro calculate_value
                {% begin %}
                  {%
                    if method = Child.class.methods.find &.name.stringify.==("value")
                      method.raise "Value method must be an instance method."
                    else
                      raise "BUG: Didn't find value method."
                    end
                  %}
                {% end %}
              end

              class_getter value : Nil do
                calculate_value
              end
            end

            ExampleModule.value
          CODE

          ex.to_s.should contain "error in line 20"
          ex.to_s.should contain "error in line 2"
          ex.to_s.scan("error in line").size.should eq 2
        end

        # TODO: Remove this spec once symbols literals have their location fixed
        it "points to caller when missing node location information (#7147)" do
          ex = assert_error(<<-'CODE', "foo")
            macro macro_raise_on(arg)
              {% arg.raise "foo" %}
            end

            macro_raise_on :this
          CODE

          ex.to_s.should contain "error in line 5"
          ex.to_s.scan("error in line").size.should eq 1
        end

        it "points to proper location of a raise on a TypeNode#keys NT element" do
          ex = assert_error(<<-'CODE', "OH NO")
            class Foo
              def self.test(**args : **T) forall T
                {% T.keys.each { |k| k.raise "OH NO" } %}
              end
            end

            Foo.test foo: 1
            CODE

          ex.to_s.should contain "OH NO"
          ex.to_s.should contain "error in line 7"
          ex.to_s.should contain "error in line 3"
          ex.to_s.scan("error in line 7").size.should eq 2
        end

        it "uses the MacroId's location when a method call on a MacroId proxies through StringLiteral" do
          assert_no_errors <<-'CODE'
            class Foo
              def self.test(**args : **T) forall T
                {% raise "expected key on line 7" unless T.keys.first.line_number == 7 %}
              end
            end

            Foo.test foo: 1
            CODE
        end
      end
    end

    describe "inside method" do
      describe "without node" do
        it "renders both frames (#7147)" do
          ex = assert_error(<<-CODE, "OH")
            def foo(x)
              {% raise "OH NO" %}
            end

            foo 1
          CODE

          ex.to_s.should contain "OH NO"
          ex.to_s.should contain "error in line 2"
          ex.to_s.should contain "error in line 5"
          ex.to_s.scan("error in line").size.should eq 2
        end
      end
    end
  end

  it "can specify tuple as return type" do
    assert_type(<<-CODE) { tuple_of([int32, int32] of Type) }
      class Foo
        def foo : {Int32, Int32}
          {{ @type }}
          {1, 2}
        end
      end

      Foo.new.foo
      CODE
  end

  it "allows specifying self as macro def return type" do
    assert_type(<<-CODE) { types["Foo"] }
      class Foo
        def foo : self
          {{ @type }}
          self
        end
      end

      Foo.new.foo
      CODE
  end

  it "allows specifying self as macro def return type (2)" do
    assert_type(<<-CODE) { types["Bar"] }
      class Foo
        def foo : self
          {{ @type }}
          self
        end
      end

      class Bar < Foo
      end

      Bar.new.foo
      CODE
  end

  it "preserves correct self in restriction when macro def is to be instantiated in subtypes (#5044)" do
    assert_type(<<-CODE) { string }
      class Foo
        def foo(x)
          1
        end
      end

      class Bar < Foo
        def foo(x : self)
          {{ @type }}
          "x"
        end
      end

      class Baz < Bar
      end

      class Baz2 < Bar
      end

      (Baz.new || Baz2.new).foo(Baz.new)
      CODE
  end

  it "doesn't affect self restrictions outside the macro def being instantiated in subtypes" do
    assert_type(<<-CODE) { union_of int32, bool }
      class Foo
        def foo(other) : Bool
          {% @type %}
          false
        end
      end

      class Bar1 < Foo
        def bar1
          1
        end

        def foo(other : self)
          other.bar1
        end
      end

      class Bar2 < Foo
        def bar2
          ""
        end

        def foo(other : self)
          other.bar2
        end
      end

      Foo.new.as(Foo).foo(Bar1.new)
      CODE
  end

  it "errors if non-existent named arg" do
    assert_error(<<-CODE, "no parameter named 'y'")
      macro foo(x = 1)
        {{x}} + 1
      end

      foo y: 2
      CODE
  end

  it "errors if named arg already specified" do
    assert_error(<<-CODE, "argument for parameter 'x' already specified")
      macro foo(x = 1)
        {{x}} + 1
      end

      foo 2, x: 2
      CODE
  end

  it "finds macro in included module" do
    assert_type(<<-CODE) { int32 }
      module Moo
        macro bar
          1
        end
      end

      class Foo
        include Moo

        def foo
          bar
        end
      end

      Foo.new.foo
      CODE
  end

  it "errors when trying to define def inside def with macro expansion" do
    assert_error(<<-CODE, "can't define def inside def")
      macro foo
        def bar; end
      end

      def baz
        foo
      end

      baz
      CODE
  end

  it "error raised within complex macro included hook (#7394)" do
    ex = assert_error(<<-'CODE', "Value method must be an instance method")
      module ExampleModule
        macro included
          {% verbatim do %}
            {%
              if method = @type.class.methods.find &.name.stringify.==("value")
                method.raise "Value method must be an instance method."
              else
                raise "BUG: Didn't find value method."
              end
            %}
          {% end %}
        end
      end

      class ExampleClass
        def self.value : Nil
        end

        include ExampleModule
      end
    CODE

    ex.to_s.should contain "error in line 16"
  end

  it "error raise within macro included hook points to `include` vs `raise`" do
    ex = assert_error(<<-'CODE', "noooo")
      module Foo
        macro included
          {% raise "noooo" %}
        end
      end

      include Foo
    CODE

    ex.to_s.should contain "error in line 3"
    ex.to_s.should contain "error in line 7"
  end

  it "error raise within macro inherited hook points to the inheriting type vs `raise`" do
    ex = assert_error(<<-'CODE', "noooo")
      abstract struct Parent
        macro inherited
          {% raise "noooo" %}
        end
      end

      struct Child < Parent
      end
    CODE

    ex.to_s.should contain "error in line 3"
    ex.to_s.should contain "error in line 7"
  end

  it "gives precise location info when doing yield inside macro" do
    assert_error(<<-CODE, "in line 6")
      macro foo
        {{yield}}
      end

      foo do
        1 + 'a'
      end
      CODE
  end

  it "transforms with {{yield}} and call" do
    assert_type(<<-CODE) { int32 }
      macro foo
        bar({{yield}})
      end

      def bar(value)
        value
      end

      def baz
        1
      end

      foo do
        baz
      end
      CODE
  end

  it "begins with {{ yield }} (#15050)" do
    result = top_level_semantic <<-CODE, wants_doc: true
      macro foo
        {{yield}}
      end

      foo do
        # doc comment
        def test
        end
      end
      CODE
    result.program.defs.try(&.["test"][0].def.doc).should eq "doc comment"
  end

  it "can return class type in macro def" do
    assert_type(<<-CODE) { types["Int32"].metaclass }
      class Foo
        def foo : Int32.class
          {{ @type }}
          Int32
        end
      end

      Foo.new.foo
      CODE
  end

  it "can return virtual class type in macro def" do
    assert_type(<<-CODE, inject_primitives: true) { types["Foo"].metaclass.virtual_type }
      class Foo
      end

      class Bar < Foo
      end

      class Foo
        def foo : Foo.class
          {{ @type }}
          1 == 1 ? Foo : Bar
        end
      end

      Foo.new.foo
      CODE
  end

  it "can't define new variables (#466)" do
    error = assert_error <<-CODE
      macro foo
        hello = 1
      end

      foo
      hello
      CODE

    error.to_s.should_not contain("did you mean")
  end

  it "finds macro in included generic module" do
    assert_type(<<-CODE) { int32 }
      module Moo(T)
        macro moo
          1
        end
      end

      class Foo
        include Moo(Int32)

        def foo
          moo
        end
      end

      Foo.new.foo
      CODE
  end

  it "finds macro in inherited generic class" do
    assert_type(<<-CODE) { int32 }
      class Moo(T)
        macro moo
          1
        end
      end

      class Foo < Moo(Int32)
        def foo
          moo
        end
      end

      Foo.new.foo
      CODE
  end

  it "doesn't die on && inside if (bug)" do
    assert_type(<<-CODE) { int32 }
      macro foo
        1 && 2
      end

      foo ? 3 : 4
      CODE
  end

  it "checks if macro expansion returns (#821)" do
    assert_type(<<-CODE) { nilable symbol }
      macro pass
        return :pass
      end

      def me
        pass
        nil
      end

      me
      CODE
  end

  it "errors if declares macro inside if" do
    assert_error(<<-CODE, "can't declare macro dynamically")
      if 1 == 2
        macro foo; end
      end
      CODE
  end

  it "allows declaring class with macro if" do
    assert_type(<<-CODE) { types["Foo"] }
      {% if true %}
        class Foo; end
      {% end %}

      Foo.new
      CODE
  end

  it "allows declaring class with macro for" do
    assert_type(<<-CODE) { types["Foo"] }
      {% for i in 0..0 %}
        class Foo; end
      {% end %}

      Foo.new
      CODE
  end

  it "allows declaring class with inline macro expression (#1333)" do
    assert_type(<<-CODE) { types["Foo"] }
      {{ "class Foo; end".id }}

      Foo.new
      CODE
  end

  it "errors if requires inside class through macro expansion" do
    str = %(
      macro req
        require "bar"
      end

      class Foo
        req
      end
    )
    expect_raises SyntaxException, "can't require inside type declarations" do
      semantic parse str
    end
  end

  it "errors if requires inside if through macro expansion" do
    assert_error(<<-CODE, "can't require dynamically")
      macro req
        require "bar"
      end

      if 1 == 2
        req
      end
      CODE
  end

  it "can define constant via macro included" do
    assert_type(<<-CODE) { int32 }
      module Mod
        macro included
          CONST = 1
        end
      end

      include Mod

      CONST
      CODE
  end

  it "errors if applying protected modifier to macro" do
    assert_error(<<-CODE, "can only use 'private' for macros")
      class Foo
        protected macro foo
          1
        end
      end

      Foo.foo
      CODE
  end

  it "expands macro with break inside while (#1852)" do
    assert_type(<<-CODE) { nil_type }
      macro test
        foo = "bar"
        break
      end

      while true
        test
      end
      CODE
  end

  it "can access variable inside macro expansion (#2057)" do
    assert_type(<<-CODE) { int32 }
      macro foo
        x
      end

      def method
        yield 1
      end

      method do |x|
        foo
      end
      CODE
  end

  it "declares variable for macro with out" do
    assert_type(<<-CODE) { int32 }
      lib LibFoo
        fun foo(x : Int32*)
      end

      macro some_macro
        z
      end

      LibFoo.foo(out z)
      some_macro
      CODE
  end

  it "show macro trace in errors (1)" do
    ex = assert_error(<<-CODE, "Error: expanding macro")
      macro foo
        Bar
      end

      foo
      CODE

    ex.to_s.should contain "error in line 5"
  end

  it "show macro trace in errors (2)" do
    ex = assert_error(<<-CODE, "Error: expanding macro")
      {% begin %}
        Bar
      {% end %}
      CODE

    ex.to_s.should contain "error in line 1"
  end

  it "errors if using macro that is defined later" do
    assert_error(<<-CODE, "macro 'foo' must be defined before this point but is defined later")
      class Bar
        foo
      end

      macro foo
      end
      CODE
  end

  it "looks up argument types in macro owner, not in subclass (#2395)" do
    assert_type(<<-CODE) { int32 }
      struct Nil
        def method(x : Problem)
          0
        end
      end

      class Foo
        def method(x : Problem) : Int32
          {% for ivar in @type.instance_vars %}
            @{{ivar.id}}.method(x)
          {% end %}
          42
        end
      end

      class Problem
      end

      module Moo
        class Problem
        end

        class Bar < Foo
          @foo : Foo?
        end
      end

      Moo::Bar.new.method(Problem.new)
      CODE
  end

  it "doesn't error when adding macro call to constant (#2457)" do
    assert_type(<<-CODE) { int32 }
      macro foo
      end

      ITS = {} of String => String

      macro coco
        {% ITS["foo"] = yield %}
        1
      end

      coco do
        foo
      end
      CODE
  end

  it "errors if named arg matches single splat parameter" do
    assert_error(<<-CODE, "no parameter named 'x'")
      macro foo(*y)
      end

      foo x: 1, y: 2
      CODE
  end

  it "errors if named arg matches splat parameter" do
    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 0, expected 1+)")
      macro foo(x, *y)
      end

      foo x: 1, y: 2
      CODE
  end

  it "says missing argument because positional args don't match past splat" do
    assert_error(<<-CODE, "missing argument: z")
      macro foo(x, *y, z)
      end

      foo 1, 2
      CODE
  end

  it "allows named args after splat" do
    assert_type(<<-CODE) { tuple_of([tuple_of([int32]), char]) }
      macro foo(*y, x)
        { {{y}}, {{x}} }
      end

      foo 1, x: 'a'
      CODE
  end

  it "errors if missing one argument" do
    assert_error(<<-CODE, "missing argument: z")
      macro foo(x, y, z)
      end

      foo x: 1, y: 2
      CODE
  end

  it "errors if missing two arguments" do
    assert_error(<<-CODE, "missing arguments: x, z")
      macro foo(x, y, z)
      end

      foo y: 2
      CODE
  end

  it "doesn't include parameters with default values in missing arguments error" do
    assert_error(<<-CODE, "missing argument: z")
      macro foo(x, z, y = 1)
      end

      foo(x: 1)
      CODE
  end

  it "solves macro expression arguments before macro expansion (type)" do
    assert_type(<<-CODE) { int32 }
      macro foo(x)
        {% if x.is_a?(TypeNode) && x.name == "String" %}
          1
        {% else %}
          'a'
        {% end %}
      end

      foo({{ String }})
      CODE
  end

  it "solves macro expression arguments before macro expansion (constant)" do
    assert_type(<<-CODE) { int32 }
      macro foo(x)
        {% if x.is_a?(NumberLiteral) && x == 1 %}
          1
        {% else %}
          'a'
        {% end %}
      end

      CONST = 1
      foo({{ CONST }})
      CODE
  end

  it "solves named macro expression arguments before macro expansion (type) (#2423)" do
    assert_type(<<-CODE) { int32 }
      macro foo(x)
        {% if x.is_a?(TypeNode) && x.name == "String" %}
          1
        {% else %}
          'a'
        {% end %}
      end

      foo(x: {{ String }})
      CODE
  end

  it "solves named macro expression arguments before macro expansion (constant) (#2423)" do
    assert_type(<<-CODE) { int32 }
      macro foo(x)
        {% if x.is_a?(NumberLiteral) && x == 1 %}
          1
        {% else %}
          'a'
        {% end %}
      end

      CONST = 1
      foo(x: {{ CONST }})
      CODE
  end

  it "finds generic type argument of included module" do
    assert_type(<<-CODE) { int32.metaclass }
      module Bar(T)
        def t
          {{ T }}
        end
      end

      class Foo(U)
        include Bar(U)
      end

      Foo(Int32).new.t
      CODE
  end

  it "finds generic type argument of included module with self" do
    assert_type(<<-CODE) { generic_class("Foo", int32).metaclass }
      module Bar(T)
        def t
          {{ T }}
        end
      end

      class Foo(U)
        include Bar(self)
      end

      Foo(Int32).new.t
      CODE
  end

  it "finds free type vars" do
    assert_type(<<-CODE) { tuple_of([int32.metaclass, string.metaclass]) }
      module Foo(T)
        def self.foo(foo : U) forall U
          { {{ T }}, {{ U }} }
        end
      end

      Foo(Int32).foo("foo")
      CODE
  end

  it "finds type for global path shared with free var" do
    assert_type(<<-CODE) { int32 }
      module T
      end

      def foo(x : T) forall T
        {{ ::T.module? ? 1 : 'a' }}
      end

      foo("")
      CODE
  end

  it "gets named arguments in double splat" do
    assert_type(<<-CODE) { named_tuple_of({"x": string, "y": bool}) }
      macro foo(**options)
        {{options}}
      end

      foo x: "foo", y: true
      CODE
  end

  it "uses splat and double splat" do
    assert_type(<<-CODE) { tuple_of([tuple_of([int32, char]), named_tuple_of({"x": string, "y": bool})]) }
      macro foo(*args, **options)
        { {{args}}, {{options}} }
      end

      foo 1, 'a', x: "foo", y: true
      CODE
  end

  it "double splat and regular args" do
    assert_type(<<-CODE) { tuple_of([int32, bool, named_tuple_of({"w": char, "z": string})]) }
      macro foo(x, y, **options)
        { {{x}}, {{y}}, {{options}} }
      end

      foo 1, w: 'a', y: true, z: "z"
      CODE
  end

  it "declares multi-assign vars for macro" do
    assert_type(<<-CODE) { int32 }
      macro id(x, y)
        {{x}}
        {{y}}
      end

      a, b = 1, 2
      id(a, b)
      1
      CODE
  end

  it "declares rescue variable inside for macro" do
    assert_type(<<-CODE) { int32 }
      macro id(x)
        {{x}}
      end

      begin
      rescue ex
        id(ex)
      end

      1
      CODE
  end

  it "matches with default value after splat" do
    assert_type(<<-CODE) { tuple_of([int32, tuple_of([char]), bool]) }
      macro foo(x, *y, z = true)
        { {{x}}, {{y}}, {{z}} }
      end

      foo 1, 'a'
      CODE
  end

  it "uses bare *" do
    assert_type(<<-CODE) { tuple_of([int32, char]) }
      macro foo(x, *, y)
        { {{x}}, {{y}} }
      end

      foo 10, y: 'a'
      CODE
  end

  it "uses bare *, doesn't let more args" do
    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 2, expected 1)")
      macro foo(x, *, y)
      end

      foo 10, 20, y: 30
      CODE
  end

  it "reports wrong number of arguments for module macro call with path receiver (#5479)" do
    assert_error(<<-CODE, "wrong number of arguments for macro 'foo' (given 2, expected 1)")
      module Mod
        macro foo(foo)
        end
      end

      Mod.foo(String, String)
      CODE
  end

  it "reports named argument errors for module macro call with path receiver" do
    assert_error(<<-CODE, "no parameter named 'y'")
      module Mod
        macro foo(x = 1)
        end
      end

      Mod.foo(y: String)
      CODE
  end

  it "uses bare *, doesn't let more args" do
    assert_error(<<-CODE, "no overload matches")
      def foo(x, *, y)
      end

      foo 10, 20, y: 30
      CODE
  end

  it "finds macro through alias (#2706)" do
    assert_type(<<-CODE) { int32 }
      module Moo
        macro bar
          1
        end
      end

      alias Foo = Moo

      Foo.bar
      CODE
  end

  it "can override macro (#2773)" do
    assert_type(<<-CODE) { char }
      macro foo
        1
      end

      macro foo
        'a'
      end

      foo
      CODE
  end

  it "works inside proc literal (#2984)" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      macro foo
        1
      end

      ->{ foo }.call
      CODE
  end

  it "finds var in proc for macros" do
    assert_type(<<-CODE, inject_primitives: true) { int32 }
      macro foo(x)
        {{x}}
      end

      ->(x : Int32) { foo(x) }.call(1)
      CODE
  end

  it "applies visibility modifier only to first level" do
    assert_type(<<-CODE) { int32 }
      macro foo
        class Foo
          def self.foo
            1
          end
        end
      end

      private foo

      Foo.foo
      CODE
  end

  it "gives correct error when method is invoked but macro exists at the same scope" do
    assert_error(<<-CODE, "undefined method 'foo'")
      macro foo(x)
      end

      class Foo
      end

      Foo.new.foo
      CODE
  end

  it "uses uninitialized variable with macros" do
    assert_type(<<-CODE) { int32 }
      macro foo(x)
        {{x}}
      end

      a = uninitialized Int32
      foo(a)
      CODE
  end

  describe "skip_file macro directive" do
    it "skips expanding the rest of the current file" do
      res = semantic(<<-CODE)
        class A
        end

        {% skip_file %}

        class B
        end
        CODE

      res.program.types.has_key?("A").should be_true
      res.program.types.has_key?("B").should be_false
    end

    it "skips file inside an if macro expression" do
      res = semantic(<<-CODE)
        class A
        end

        {% if true %}
          class C; end
          {% skip_file %}
          class D; end
        {% end %}

        class B
        end
        CODE

      res.program.types.has_key?("A").should be_true
      res.program.types.has_key?("B").should be_false
      res.program.types.has_key?("C").should be_true
      res.program.types.has_key?("D").should be_false
    end
  end

  it "finds method before macro (#236)" do
    assert_type(<<-CODE) { char }
      macro global
        1
      end

      class Foo
        def global
          'a'
        end

        def bar
          global
        end
      end

      Foo.new.bar
      CODE
  end

  it "finds macro and method at the same scope" do
    assert_type(<<-CODE) { tuple_of [int32, char] }
      macro global(x)
        1
      end

      def global(x, y)
        'a'
      end

      {global(1), global(1, 2)}
      CODE
  end

  it "finds macro and method at the same scope inside included module" do
    assert_type(<<-CODE) { tuple_of [int32, char] }
      module Moo
        macro global(x)
          1
        end

        def global(x, y)
          'a'
        end
      end

      class Foo
        include Moo

        def main
          {global(1), global(1, 2)}
        end
      end

      Foo.new.main
      CODE
  end

  it "finds macro in included module at class level (#4639)" do
    assert_type(<<-CODE) { int32 }
      module Moo
        macro foo
          def self.bar
            2
          end
        end
      end

      class Foo
        include Moo

        foo
      end

      Foo.bar
      CODE
  end

  it "finds macro in module in Object" do
    assert_type(<<-CODE) { int32 }
      class Object
        macro foo
          def self.bar
            2
          end
        end
      end

      module Moo
        foo
      end

      Moo.bar
      CODE
  end

  it "finds metaclass instance of instance method (#4739)" do
    assert_type(<<-CODE) { int32 }
      class Parent
        macro foo
          def self.bar
            1
          end
        end
      end

      class Child < Parent
        def foo
        end
      end

      class GrandChild < Child
        foo
      end

      GrandChild.bar
      CODE
  end

  it "finds metaclass instance of instance method (#4639)" do
    assert_type(<<-CODE) { int32 }
      module Include
        macro foo
          def foo
            1
          end
        end
      end

      class Parent
        include Include

        foo
      end

      class Foo < Parent
        foo
      end

      Foo.new.foo
      CODE
  end

  it "can lookup type parameter when macro is called inside class (#5343)" do
    assert_type(<<-CODE) { int32.metaclass }
      class Foo(T)
        macro foo
          {{T}}
        end
      end

      alias FooInt32 = Foo(Int32)

      class Bar
        def self.foo
          FooInt32.foo
        end
      end

      Bar.foo
      CODE
  end

  it "cannot lookup type defined in caller class" do
    assert_error(<<-CODE, "undefined constant Baz")
      class Foo
        macro foo
          {{Baz}}
        end
      end

      class Bar
        def self.foo
          Foo.foo
        end

        class Baz
        end
      end

      Bar.foo
      CODE
  end

  it "clones default value before expanding" do
    assert_type(<<-CODE) { nil_type }
      FOO = {} of String => String?

      macro foo(x = {} of String => String)
        {% FOO["foo"] = x["foo"] %}
        {% x["foo"] = "foo" %}
      end

      foo
      foo
      {{ FOO["foo"] }}
      CODE
  end

  it "does macro verbatim inside macro" do
    assert_type(<<-CODE) { types["Bar"].metaclass }
      class Foo
        macro inherited
          {% verbatim do %}
            def foo
              {{ @type }}
            end
          {% end %}
        end
      end

      class Bar < Foo
      end

      Bar.new.foo
      CODE
  end

  it "does macro verbatim outside macro" do
    assert_type(<<-CODE) { int32 }
      {% verbatim do %}
        1
      {% end %}
      CODE
  end

  it "evaluates yield expression (#2924)" do
    assert_type(<<-CODE) { string }
      macro a(b)
        {{yield b}}
      end

      a("foo") do |c|
        {{c}}
      end
      CODE
  end

  it "finds generic in macro code" do
    assert_type(<<-CODE) { array_of(string).metaclass }
      {% begin %}
        {{ Array(String) }}
      {% end %}
      CODE
  end

  it "finds generic in macro code using free var" do
    assert_type(<<-CODE) { array_of(int32).metaclass }
      class Foo(T)
        def self.foo
          {% begin %}
            {{ Array(T) }}
          {% end %}
        end
      end

      Foo(Int32).foo
      CODE
  end

  it "expands multiline macro expression in verbatim (#6643)" do
    assert_type(<<-CODE) { int32 }
      {% verbatim do %}
        {{
          if true
            1
            "2"
            3
          end
        }}
      {% end %}
      CODE
  end

  it "preserves escaped interpolation in verbatim (#16413)" do
    assert_type(<<-'CODE') { nil_type }
      {% begin %}
        {% verbatim do %}
          {%
            name = "FOO"
            "\#{get_env(#{name})}"
          %}
        {% end %}
      {% end %}
      CODE
  end

  it "can use macro in instance var initializer (#7666)" do
    assert_type(<<-CODE) { string }
      class Foo
        macro m
          "test"
        end

        @x : String = m

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "can use macro in instance var initializer (just assignment) (#7666)" do
    assert_type(<<-CODE) { string }
      class Foo
        macro m
          "test"
        end

        @x = m

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "shows correct error message in macro expansion (#7083)" do
    assert_error(<<-CODE, "can't instantiate abstract class Foo")
      abstract class Foo
        {% begin %}
          def self.new
            allocate
          end
        {% end %}
      end

      Foo.new
      CODE
  end

  it "doesn't crash on syntax error inside macro (regression, #8038)" do
    expect_raises(Iyi::SyntaxException, "unterminated array literal") do
      semantic(<<-CODE)
        {% begin %}[{% end %}
        CODE
    end
  end

  it "has correct location after expanding assignment after instance var" do
    result = semantic <<-CODE
      macro foo(x)       #  1
        @{{x}}           #  2
                         #  3
        def bar          #  4
        end              #  5
      end                #  6
                         #  7
      class Foo          #  8
        foo(x = 1)       #  9
      end
      CODE

    method = result.program.types["Foo"].lookup_first_def("bar", false).should_not(be_nil)
    method.location.should_not(be_nil).expanded_location.should_not(be_nil).line_number.should eq(9)
  end

  it "assigns to underscore" do
    assert_no_errors <<-CODE
      {% _ = 1 %}
      CODE
  end

  it "unpacks block parameters inside macros (#13742)" do
    assert_no_errors <<-CODE
      macro foo
        {% [{1, 2}, {3, 4}].each { |(k, v)| k } %}
      end

      foo
      CODE

    assert_no_errors <<-CODE
      macro foo
        {% [{1, 2}, {3, 4}].each { |(k, v)| k } %}
      end

      foo
      foo
      CODE
  end

  it "unpacks to underscore within block parameters inside macros" do
    assert_type(<<-CODE) { bool }
      {% begin %}
        {% x = nil %}
        {% [{1, true, 'a', ""}].each { |(_, y, _, _)| x = y } %}
        {{ x }}
      {% end %}
      CODE
  end

  it "executes OpAssign (#9356)" do
    assert_type(<<-CODE) { int32 }
      {% begin %}
        {% a = nil %}
        {% a ||= 1 %}
        {% if a %}
          1
        {% else %}
          'a'
        {% end %}
      {% end %}
      CODE
  end

  it "executes MultiAssign" do
    assert_type(<<-CODE) { tuple_of([int32, int32] of Type) }
      {% begin %}
        {% a, b = 1, 2 %}
        { {{a}}, {{b}} }
      {% end %}
      CODE
  end

  it "executes MultiAssign with ArrayLiteral value" do
    assert_type(<<-CODE) { tuple_of([int32, int32] of Type) }
      {% begin %}
        {% xs = [1, 2] %}
        {% a, b = xs %}
        { {{a}}, {{b}} }
      {% end %}
      CODE
  end

  it "assigns to underscore in MultiAssign" do
    assert_type(<<-CODE) { tuple_of([char, bool]) }
      {% begin %}
        {% _, x, *_, y = [1, 'a', "", nil, true] %}
        { {{x}}, {{y}} }
      {% end %}
      CODE
  end

  describe "@caller" do
    it "returns an array of each call" do
      assert_type(<<-CODE) { int32 }
        macro test
          {{@caller.size == 1 ? 1 : 'f'}}
        end

        test
        CODE
    end

    it "provides access to the `Call` information" do
      assert_type(<<-CODE) { tuple_of([int32, char] of Type) }
        macro test(num)
          {{@caller.first.args[0] == 1 ? 1 : 'f'}}
        end

        {test(1), test(2)}
        CODE
    end

    it "returns nil if no stack is available" do
      assert_type(<<-CODE) { char }
        def test
          {{(c = @caller) ? 1 : 'f'}}
        end

        test
        CODE
    end
  end
end
