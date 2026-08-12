require "../../spec_helper"

# Semantics of the iyi declarations: `module` headers, `using`, and `impl`.
#
# `import` is not covered here — it resolves against files on disk, so it is
# exercised by `samples/iyi/modules.iyi` rather than by this file. Everything
# else needs only that the used module exist, so these specs declare it
# directly instead of importing it.
describe "Semantic: iyi" do
  describe "using" do
    it "resolves a function of a used module from module top level" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Greeter
            extend self

            def polite
              1
            end
          end
        end

        module Consumer
          using app/greeter

          def self.go
            polite
          end
        end

        Consumer.go
        CRYSTAL
    end

    it "resolves a function of a used module from a nested type" do
      # The case `include` cannot cover: the directive is on `Consumer`, and
      # `Consumer::User` is not on `Consumer`'s ancestor chain.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Greeter
            extend self

            def polite
              1
            end
          end
        end

        module Consumer
          using app/greeter

          struct User
            def greet
              polite
            end
          end
        end

        Consumer::User.new.greet
        CRYSTAL
    end

    it "resolves a type of a used module" do
      assert_type(<<-CRYSTAL) { types["Consumer"].types["User"] }
        module App
          module Greeter
            module Greet
            end
          end
        end

        module Consumer
          using app/greeter

          struct User
            include Greet
          end
        end

        Consumer::User.new
        CRYSTAL
    end

    it "does not re-export what it brought in" do
      # `using` is written by the consumer, so importing the consumer must not
      # be a way to reach what the consumer used.
      assert_error <<-CRYSTAL, "undefined method 'polite'"
        module App
          module Greeter
            extend self

            def polite
              1
            end
          end
        end

        module Consumer
          using app/greeter
        end

        Consumer.polite
        CRYSTAL
    end

    it "does not reach a name the selective form left out" do
      assert_error <<-CRYSTAL, "undefined local variable or method 'polite'"
        module App
          module Greeter
            extend self

            def polite
              1
            end

            def title
              2
            end
          end
        end

        module Consumer
          using app/greeter::{title}

          polite
        end
        CRYSTAL
    end

    it "reaches a name the selective form listed" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Greeter
            extend self

            def polite
              1
            end

            def title
              2
            end
          end
        end

        module Consumer
          using app/greeter::{polite}

          def self.go
            polite
          end
        end

        Consumer.go
        CRYSTAL
    end

    it "takes type names in the selective form too" do
      assert_type(<<-CRYSTAL) { types["Consumer"].types["User"] }
        module App
          module Greeter
            module Greet
            end

            module Loud
            end
          end
        end

        module Consumer
          using app/greeter::{Greet}

          struct User
            include Greet
          end
        end

        Consumer::User.new
        CRYSTAL
    end

    it "does not reach a type the selective form left out" do
      assert_error <<-CRYSTAL, "undefined constant Loud"
        module App
          module Greeter
            module Greet
            end

            module Loud
            end
          end
        end

        module Consumer
          using app/greeter::{Greet}

          struct User
            include Loud
          end
        end
        CRYSTAL
    end
  end

  describe "using conflicts (SPEC.md II.3)" do
    it "reports an ambiguous function at the point of use" do
      assert_error <<-CRYSTAL, "'title' is ambiguous here"
        module App
          module Greeter
            extend self

            def title
              1
            end
          end

          module Formal
            extend self

            def title
              2
            end
          end
        end

        module Consumer
          using app/greeter
          using app/formal

          def self.go
            title
          end
        end

        Consumer.go
        CRYSTAL
    end

    it "reports an ambiguous type at the point of use" do
      assert_error <<-CRYSTAL, "'Greet' is ambiguous here"
        module App
          module Greeter
            module Greet
            end
          end

          module Formal
            module Greet
            end
          end
        end

        module Consumer
          using app/greeter
          using app/formal

          struct User
            include Greet
          end
        end
        CRYSTAL
    end

    it "does not report two used modules that merely could clash" do
      # Two modules exporting one name is not by itself a mistake. Nothing is
      # wrong until a name is written that could mean either.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Greeter
            extend self

            def title
              1
            end

            def polite
              1
            end
          end

          module Formal
            extend self

            def title
              2
            end
          end
        end

        module Consumer
          using app/greeter
          using app/formal

          def self.go
            polite
          end
        end

        Consumer.go
        CRYSTAL
    end

    it "resolves an otherwise ambiguous name once one directive is narrowed" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Greeter
            extend self

            def title
              1
            end
          end

          module Formal
            extend self

            def title
              true
            end

            def address
              2
            end
          end
        end

        module Consumer
          using app/greeter
          using app/formal::{address}

          def self.go
            title
          end
        end

        Consumer.go
        CRYSTAL
    end

    # II.3's other rule, and the one that keeps a library from breaking its
    # consumers by adding an export. Checked from inside a nested type,
    # because that is where getting the search order wrong shows up.
    #
    # It needs a module header, so nothing in the source is at top level and
    # there is no last expression to assert a type on. The `: Bool` return
    # restriction is the assertion instead: only one of the two candidates
    # satisfies it, so which one was chosen decides whether this compiles.
    # The pair of specs is what pins it down — the second shows the used
    # function really is found when there is no local one to beat it.
    it "lets a local definition beat a used one, from a nested type" do
      assert_no_errors <<-CRYSTAL
        module app/consumer

        module App
          module Greeter
            extend self

            def polite
              1
            end
          end
        end

        using app/greeter

        def polite
          true
        end

        struct User
          def greet : Bool
            polite
          end
        end

        User.new.greet
        CRYSTAL
    end

    it "falls back to the used one when there is no local definition" do
      assert_error <<-CRYSTAL, "must return Bool"
        module app/consumer

        module App
          module Greeter
            extend self

            def polite
              1
            end
          end
        end

        using app/greeter

        struct User
          def greet : Bool
            polite
          end
        end

        User.new.greet
        CRYSTAL
    end

    it "raises on `using` of something that is not a module" do
      assert_error <<-CRYSTAL, %(can't `using` App::Greeter, it's a struct)
        module App
          struct Greeter
          end
        end

        module Consumer
          using app/greeter
        end
        CRYSTAL
    end
  end

  describe "module header" do
    it "puts a module's own functions in scope for the types declared in it" do
      # An iyi module is a compilation unit, so its `def`s are functions in
      # lexical scope. Crystal modules do not work this way, which is what the
      # next spec pins down.
      assert_no_errors <<-CRYSTAL
        module app/thing

        def helper
          1
        end

        struct T
          def go : Int32
            helper
          end
        end

        T.new.go
        CRYSTAL
    end

    it "leaves a Crystal module scoping exactly as it was" do
      assert_error <<-CRYSTAL, "undefined local variable or method 'helper'"
        module Thing
          extend self

          def helper
            1
          end

          struct T
            def go
              helper
            end
          end
        end

        Thing::T.new.go
        CRYSTAL
    end
  end

  describe "traits are their own type (SPEC.md R-3)" do
    it "refuses to reopen a struct as a trait" do
      assert_error <<-CRYSTAL, "Foo is not a trait, it's a struct"
        module App
          struct Foo
          end

          trait Foo
            abstract def show
          end
        end
        CRYSTAL
    end

    it "refuses to reopen a module as a trait" do
      assert_error <<-CRYSTAL, "Greet is not a trait, it's a module"
        module App
          module Greet
          end

          trait Greet
            abstract def greet
          end
        end
        CRYSTAL
    end

    it "refuses to `include` a trait" do
      # The whole point of R-3: a type acquires a trait through an impl, whose
      # location the orphan rule can check. `include` has no such rule.
      assert_error <<-CRYSTAL, "can't include App::Show::Showable, it's a trait"
        module App
          module Show
            trait Showable
              abstract def show
            end

            struct Foo
              include Showable

              def show
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "refuses to `extend` a trait" do
      assert_error <<-CRYSTAL, "can't extend App::Show::Showable, it's a trait"
        module App
          module Show
            trait Showable
              abstract def show
            end

            struct Foo
              extend Showable
            end
          end
        end
        CRYSTAL
    end

    it "still lets an impl register the trait" do
      # `impl` reaches the same machinery `include` does, so refusing the
      # written directive must not close the path the impl needs.
      assert_type(<<-CRYSTAL) { bool }
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Foo
            end

            impl Showable for Foo
              def show : Int32
                1
              end
            end
          end
        end

        App::Show::Foo.new.is_a?(App::Show::Showable)
        CRYSTAL
    end

    it "refuses to `using` a trait" do
      assert_error <<-CRYSTAL, "can't `using` App::Show::Showable, it's a trait"
        module App
          module Show
            trait Showable
              abstract def show
            end
          end
        end

        module Consumer
          using app/show/showable
        end
        CRYSTAL
    end

    it "still lets the selective form name a trait" do
      # `using app/show::{Showable}` uses the *module* and selects a type name
      # from it, which is II.3 working as specified — only naming the trait as
      # the used module itself is refused.
      assert_type(<<-CRYSTAL) { types["App"].types["Show"].types["Foo"] }
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Foo
            end

            impl Showable for Foo
              def show : Int32
                1
              end
            end
          end
        end

        module Consumer
          using app/show::{Showable, Foo}

          def self.build : Showable
            Foo.new
          end
        end

        Consumer.build
        CRYSTAL
    end

    it "refuses to implement a module" do
      assert_error <<-CRYSTAL, "can't implement App::Greeter, it's a module. Only a trait can be implemented"
        module App
          module Greeter
          end

          struct Foo
          end

          impl Greeter for Foo
            def greet
              1
            end
          end
        end
        CRYSTAL
    end

    it "refuses to implement a trait for a trait" do
      # A blanket impl in disguise: it would give every implementer of one
      # trait a second one, from a module that has heard of neither.
      assert_error <<-CRYSTAL, "it's a trait"
        module App
          module Show
            trait Showable
              abstract def show
            end

            trait Loud
              abstract def shout
            end

            impl Showable for Loud
              def show
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports a requirement the impl does not satisfy, at the impl" do
      # Crystal's abstract-def check reports at the point the type is first
      # used and names the type. This names the impl and the method.
      assert_error <<-CRYSTAL, "impl App::Show::Showable for App::Show::Foo is missing a method required by the trait: show"
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Foo
            end

            impl Showable for Foo
            end
          end
        end
        CRYSTAL
    end

    it "reports every missing requirement at once" do
      assert_error <<-CRYSTAL, "is missing methods required by the trait: shout, show"
        module App
          module Show
            trait Showable
              abstract def show : Int32
              abstract def shout : Int32

              def loud : Int32
                shout
              end
            end

            struct Foo
            end

            impl Showable for Foo
            end
          end
        end
        CRYSTAL
    end

    it "does not report a requirement an unused type leaves unimplemented" do
      # The point of checking at the impl: today this compiles clean, because
      # Crystal only reports an unimplemented abstract where the type is used.
      assert_error <<-CRYSTAL, "is missing a method required by the trait: show"
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Unused
            end

            impl Showable for Unused
            end
          end
        end

        1
        CRYSTAL
    end

    it "accepts a requirement satisfied by a default method" do
      # A trait method with a body is not a requirement, so an impl that
      # defines only the abstract one is complete.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Show
            trait Showable
              abstract def show : Int32

              def shown : Int32
                show
              end
            end

            struct Foo
            end

            impl Showable for Foo
              def show : Int32
                21
              end
            end
          end
        end

        App::Show::Foo.new.shown
        CRYSTAL
    end

    it "keeps a trait usable as a type restriction" do
      # The reason `TraitType` subclasses the module type rather than replacing
      # it: a value typed by the trait still dispatches to the impl.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Foo
            end

            impl Showable for Foo
              def show : Int32
                1
              end
            end

            def self.render(x : Showable) : Int32
              x.show
            end
          end
        end

        App::Show.render(App::Show::Foo.new)
        CRYSTAL
    end
  end

  describe "impl coherence (R-3)" do
    it "allows an impl in the module that defines the trait" do
      assert_type(<<-CRYSTAL) { types["App"].types["Data"].types["Foo"] }
        module App
          module Data
            struct Foo
            end
          end

          module Show
            trait Showable
              abstract def show
            end

            impl Showable for App::Data::Foo
              def show
                1
              end
            end
          end
        end

        App::Data::Foo.new
        CRYSTAL
    end

    it "allows an impl in the module that defines the type" do
      assert_type(<<-CRYSTAL) { types["App"].types["Data"].types["Foo"] }
        module App
          module Show
            trait Showable
              abstract def show
            end
          end

          module Data
            struct Foo
            end

            impl App::Show::Showable for Foo
              def show
                1
              end
            end
          end
        end

        App::Data::Foo.new
        CRYSTAL
    end

    it "refuses an impl in a module that defines neither" do
      # The case the import DAG does not rule out on its own: a third module
      # that can name both is free to write the impl, and so is a fourth.
      assert_error <<-CRYSTAL, "an impl must live in the module that defines the trait"
        module App
          module Show
            trait Showable
              abstract def show
            end
          end

          module Data
            struct Foo
            end
          end

          module Orphan
            impl App::Show::Showable for App::Data::Foo
              def show
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "is vacuous when neither declaration is in a module" do
      # A program that never writes a module header is one compilation unit,
      # so there is no other module for an impl to have gone in.
      assert_type(<<-CRYSTAL) { types["Foo"] }
        trait Showable
          abstract def show
        end

        struct Foo
        end

        impl Showable for Foo
          def show
            1
          end
        end

        Foo.new
        CRYSTAL
    end
  end

  describe "generic impls (SPEC.md II.7)" do
    it "implements a trait for every instantiation of a generic type" do
      assert_type(<<-CRYSTAL) { int32 }
        trait Showable
          abstract def show
        end

        struct Box(T)
          def initialize(@value : T)
          end

          def value
            @value
          end
        end

        impl Showable for Box(T) forall T
          def show
            value
          end
        end

        Box.new(1).show
        CRYSTAL
    end

    it "binds the impl's own parameter names positionally" do
      # `Pair` declared `A, B`; the impl calls them `X, Y`. An impl states
      # arity, not vocabulary — Crystal requires a reopened generic to repeat
      # the declared names, which leaks a type's private naming.
      assert_type(<<-CRYSTAL) { bool }
        trait Showable
          abstract def show
        end

        struct Pair(A, B)
          def initialize(@first : A, @second : B)
          end

          def second
            @second
          end
        end

        impl Showable for Pair(X, Y) forall X, Y
          def show : Y
            second
          end
        end

        Pair.new(1, true).show
        CRYSTAL
    end

    it "requires the binder" do
      assert_error <<-CRYSTAL, "introduce the parameters with `forall`"
        trait Showable
          abstract def show
        end

        struct Box(T)
        end

        impl Showable for Box(T)
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses a specialised impl" do
      assert_error <<-CRYSTAL, "iyi has no specialised impls"
        trait Showable
          abstract def show
        end

        struct Box(T)
        end

        impl Showable for Box(Int32)
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses a concrete argument alongside a binder" do
      assert_error <<-CRYSTAL, "iyi has no specialised impls"
        trait Showable
          abstract def show
        end

        struct Pair(A, B)
        end

        impl Showable for Pair(T, Int32) forall T
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses a blanket impl" do
      assert_error <<-CRYSTAL, "can't implement Showable for every type"
        trait Showable
          abstract def show
        end

        impl Showable for T forall T
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses a blanket impl before complaining about its bound" do
      # Refusing the blanket form is permanent; the bound being unimplemented
      # is not. The permanent answer is the more useful one.
      assert_error <<-CRYSTAL, "can't implement Showable for every type"
        trait Showable
          abstract def show
        end

        impl Showable for T forall T : Showable
          def show
            1
          end
        end
        CRYSTAL
    end

    it "rejects bounds as unimplemented" do
      assert_error <<-CRYSTAL, "trait bounds on impl type parameters"
        trait Showable
          abstract def show
        end

        struct Box(T)
        end

        impl Showable for Box(T) forall T : Showable
          def show
            1
          end
        end
        CRYSTAL
    end

    it "checks arity" do
      assert_error <<-CRYSTAL, "wrong number of type vars"
        trait Showable
          abstract def show
        end

        struct Box(T)
        end

        impl Showable for Box(T, U) forall T, U
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses binding one parameter twice" do
      assert_error <<-CRYSTAL, "is bound twice"
        trait Showable
          abstract def show
        end

        struct Pair(A, B)
        end

        impl Showable for Pair(T, T) forall T
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses an unused binder name" do
      assert_error <<-CRYSTAL, "which is never used"
        trait Showable
          abstract def show
        end

        struct Box(T)
        end

        impl Showable for Box(T) forall T, U
          def show
            1
          end
        end
        CRYSTAL
    end

    it "refuses a rename that would capture" do
      # `Pair` declared `A`; renaming the impl's `X` to `A` would silently turn
      # a body reference to `A` into the type parameter.
      assert_error <<-CRYSTAL, "can't also be used as a name here"
        trait Showable
          abstract def show
        end

        struct A
        end

        struct Pair(A, B)
        end

        impl Showable for Pair(X, Y) forall X, Y
          def show
            A.new
          end
        end
        CRYSTAL
    end

    it "refuses `forall` on a target that takes no parameters" do
      assert_error <<-CRYSTAL, "has nothing to bind"
        trait Showable
          abstract def show
        end

        struct Foo
        end

        impl Showable for Foo forall T
          def show
            1
          end
        end
        CRYSTAL
    end
  end

  # A bound on a *method*'s free variable, which is a different mechanism from
  # a bound on an impl's parameter: the method exists either way, so there is
  # one check where the variable binds and nothing to defer. The impl form
  # stays unimplemented — see the `describe` above.
  describe "trait bounds on a method (SPEC.md II.7)" do
    it "accepts a call whose bound type implements the trait" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            struct Foo
            end

            impl Showable for Foo
              def show : Int32
                1
              end
            end

            def self.render(x : T) : Int32 forall T : Showable
              x.show
            end
          end
        end

        App::Show.render(App::Show::Foo.new)
        CRYSTAL
    end

    it "refuses a call whose bound type does not implement the trait" do
      assert_error <<-CRYSTAL, "Char does not implement App::Show::Showable, required by `T` in `render`"
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            def self.render(x : T) : Int32 forall T : Showable
              1
            end
          end
        end

        App::Show.render('a')
        CRYSTAL
    end

    it "binds through a block's return type" do
      # The shape the Kemal router needs: nothing in the parameter list
      # mentions the bounded variable.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Router
            trait IntoBody
              abstract def into_body : Int32
            end

            impl IntoBody for Char
              def into_body : Int32
                1
              end
            end

            # The body does not call the block: the spec harness runs a
            # minimal prelude with no `Proc#call`, and what is under test is
            # where `B` binds, not what the body does with it.
            def self.add_route(&block : Int32 -> B) : Int32 forall B : IntoBody
              1
            end
          end
        end

        App::Router.add_route { |x| 'a' }
        CRYSTAL
    end

    it "refuses a block whose return type does not implement the trait" do
      assert_error <<-CRYSTAL, "Bool does not implement App::Router::IntoBody, required by `B` in `add_route`"
        module App
          module Router
            trait IntoBody
              abstract def into_body : Int32
            end

            def self.add_route(&block : Int32 -> B) : Int32 forall B : IntoBody
              1
            end
          end
        end

        App::Router.add_route { |x| true }
        CRYSTAL
    end

    it "checks only the names that carry a bound" do
      assert_error <<-CRYSTAL, "does not implement App::Show::Showable, required by `A` in `pair`"
        module App
          module Show
            trait Showable
              abstract def show : Int32
            end

            impl Showable for Char
              def show : Int32
                1
              end
            end

            def self.pair(a : A, b : B) : Int32 forall A : Showable, B
              a.show
            end
          end
        end

        App::Show.pair('a', true)
        App::Show.pair(true, 'a')
        CRYSTAL
    end

    it "refuses a bound that is not a trait" do
      assert_error <<-CRYSTAL, "can't bound T by App::Helpers, it's a module. A bound is a trait, and nothing else"
        module App
          module Helpers
          end

          def self.f(x : T) : Int32 forall T : Helpers
            1
          end
        end

        App.f(1)
        CRYSTAL
    end
  end

  # iyi: `trait Ord : Eq` — a trait requiring another trait (SPEC.md II.6).
  # A requirement, not an inclusion, so a type still acquires `Eq` only by
  # having an `impl Eq for` it — which is what keeps R-3 the only route in.
  describe "supertraits" do
    it "lets a default method call a method the required trait provides" do
      # `Ord` never declares `eq`. It is the requirement that guarantees the
      # implementer has one.
      assert_type(<<-CRYSTAL) { bool }
        module App
          module Cmp
            trait Eq
              abstract def eq : Bool
            end

            trait Ord : Eq
              abstract def key : Int32

              def same : Bool
                eq
              end
            end

            struct N
              def initialize
              end
            end

            impl Eq for N
              def eq : Bool
                true
              end
            end

            impl Ord for N
              def key : Int32
                1
              end
            end
          end
        end

        App::Cmp::N.new.same
        CRYSTAL
    end

    it "reports a required trait the type does not implement" do
      assert_error <<-CRYSTAL, "needs an impl of App::Cmp::Eq for App::Cmp::N first"
        module App
          module Cmp
            trait Eq
              abstract def eq : Bool
            end

            trait Ord : Eq
              abstract def key : Int32
            end

            struct N
            end

            impl Ord for N
              def key : Int32
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "does not let implementing the requiring trait confer the required one" do
      # The reason this is a requirement rather than an `include`: if `Ord`
      # included `Eq`, every implementer of `Ord` would satisfy `Eq` with no
      # impl anywhere, which is the open-class hole R-3 closes.
      assert_error <<-CRYSTAL, "needs an impl of App::Cmp::Eq for App::Cmp::M first"
        module App
          module Cmp
            trait Eq
              abstract def eq : Bool
            end

            trait Ord : Eq
              abstract def key : Int32
            end

            struct N
              def initialize
              end
            end

            impl Eq for N
              def eq : Bool
                true
              end
            end

            impl Ord for N
              def key : Int32
                1
              end
            end

            struct M
            end

            impl Ord for M
              def key : Int32
                2
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports every required trait that is missing at once" do
      assert_error <<-CRYSTAL, "needs impls of App::Cmp::Eq, App::Cmp::Show for App::Cmp::N first"
        module App
          module Cmp
            trait Eq
              abstract def eq : Bool
            end

            trait Show
              abstract def show : String
            end

            trait Ord : Eq, Show
              abstract def key : Int32
            end

            struct N
            end

            impl Ord for N
              def key : Int32
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "refuses a requirement that is not a trait" do
      assert_error <<-CRYSTAL, "can't require App::Cmp::Helpers, it's a module. A trait can only require another trait"
        module App
          module Cmp
            module Helpers
            end

            trait Ord : Helpers
              abstract def key : Int32
            end
          end
        end
        CRYSTAL
    end

    it "refuses a trait that requires itself" do
      assert_error <<-CRYSTAL, "App::Cmp::Ord can't require itself"
        module App
          module Cmp
            trait Ord : Ord
              abstract def key : Int32
            end
          end
        end
        CRYSTAL
    end

    it "refuses the same requirement twice" do
      assert_error <<-CRYSTAL, "App::Cmp::Ord already requires App::Cmp::Eq"
        module App
          module Cmp
            trait Eq
              abstract def eq : Bool
            end

            trait Ord : Eq, Eq
              abstract def key : Int32
            end
          end
        end
        CRYSTAL
    end
  end

  # iyi: `type Elem` — an associated type (SPEC.md II.6). It is an output of the
  # impl, not an input the caller picks, which is why a trait that declares one
  # can be implemented only once for a type.
  describe "associated types" do
    it "resolves the trait's own signatures through the impl's answer" do
      assert_type(<<-CRYSTAL) { string }
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem

              def describe : Elem
                first
              end
            end

            struct Names
              def initialize
              end
            end

            impl Container for Names
              type Elem = String

              def first : String
                "ada"
              end
            end
          end
        end

        App::Coll::Names.new.describe
        CRYSTAL
    end

    it "lets two types answer it differently" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
              def initialize
              end
            end

            impl Container for Names
              type Elem = String

              def first : String
                "ada"
              end
            end

            struct Counts
              def initialize
              end
            end

            impl Container for Counts
              type Elem = Int32

              def first : Int32
                42
              end
            end
          end
        end

        App::Coll::Counts.new.first
        CRYSTAL
    end

    it "checks the impl's signature against its own answer" do
      assert_error <<-CRYSTAL, "must return String"
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
              def initialize
              end
            end

            impl Container for Names
              type Elem = String

              def first : Int32
                1
              end
            end
          end
        end

        App::Coll::Names.new.first
        CRYSTAL
    end

    it "reports an associated type the impl does not answer" do
      assert_error <<-CRYSTAL, "impl App::Coll::Container for App::Coll::Names does not answer an associated type the trait declares: Elem"
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
            end

            impl Container for Names
              def first : String
                "ada"
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports an answer the trait never asked for" do
      assert_error <<-CRYSTAL, "App::Coll::Container declares no associated type named Key. It declares: Elem"
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
            end

            impl Container for Names
              type Elem = String
              type Key = Int32

              def first : String
                "ada"
              end
            end
          end
        end
        CRYSTAL
    end

    it "refuses a second impl of the same trait for one type" do
      # The whole difference from a parameter: a second answer would make a
      # call on the type ambiguous about which impl it meant.
      assert_error <<-CRYSTAL, "already implements App::Coll::Container, and a trait with associated types can be implemented only once for a type"
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
              def initialize
              end
            end

            impl Container for Names
              type Elem = String

              def first : String
                "ada"
              end
            end

            impl Container for Names
              type Elem = Int32

              def first : Int32
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "refuses one declared anywhere but a trait or an impl body" do
      assert_error <<-CRYSTAL, "an associated type can only be declared directly in a trait or an impl body"
        module App
          module Coll
            trait Container
              type Elem

              abstract def first : Elem
            end

            struct Names
            end

            impl Container for Names
              type Elem = String

              struct Inner
                type Nested = Int32
              end

              def first : String
                "ada"
              end
            end
          end
        end
        CRYSTAL
    end

    it "allows a default method bounded on the associated type" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Coll
            trait Cmp
              abstract def cmp : Int32
            end

            trait Container
              type Elem

              abstract def first : Elem

              def biggest : Elem where Elem : Cmp
                first
              end
            end

            struct Score
              def initialize
              end
            end

            impl Cmp for Score
              def cmp : Int32
                1
              end
            end

            struct Scores
              def initialize
              end
            end

            impl Container for Scores
              type Elem = Score

              def first : Score
                Score.new
              end
            end
          end
        end

        App::Coll::Scores.new.biggest.cmp
        CRYSTAL
    end

    it "reports an element type that does not meet the bound" do
      # The point of the bound: Crystal duck-types these and fails at
      # instantiation, naming neither the bound nor the element type.
      assert_error <<-CRYSTAL, "Int32 does not implement App::Coll::Cmp, required by `where Elem : App::Coll::Cmp` in `biggest`"
        module App
          module Coll
            trait Cmp
              abstract def cmp : Int32
            end

            trait Container
              type Elem

              abstract def first : Elem

              def biggest : Elem where Elem : Cmp
                first
              end
            end

            struct Raw
              def initialize
              end
            end

            impl Container for Raw
              type Elem = Int32

              def first : Int32
                1
              end
            end
          end
        end

        App::Coll::Raw.new.biggest
        CRYSTAL
    end

    it "leaves an unbounded method alone on the same trait" do
      # Only the bounded method is restricted; the rest of the trait stays
      # available whatever the element type is.
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Coll
            trait Cmp
              abstract def cmp : Int32
            end

            trait Container
              type Elem

              abstract def first : Elem

              def biggest : Elem where Elem : Cmp
                first
              end

              def any : Elem
                first
              end
            end

            struct Raw
              def initialize
              end
            end

            impl Container for Raw
              type Elem = Int32

              def first : Int32
                1
              end
            end
          end
        end

        App::Coll::Raw.new.any
        CRYSTAL
    end

    it "refuses a where bound that is not a trait" do
      assert_error <<-CRYSTAL, "can't bound Elem by App::Coll::Helpers, it's a module. A bound is a trait, and nothing else"
        module App
          module Coll
            module Helpers
            end

            trait Container
              type Elem

              abstract def first : Elem

              def go : Elem where Elem : Helpers
                first
              end
            end

            struct Raw
              def initialize
              end
            end

            impl Container for Raw
              type Elem = Int32

              def first : Int32
                1
              end
            end
          end
        end

        App::Coll::Raw.new.go
        CRYSTAL
    end

    it "refuses a name that is both a parameter and an associated type" do
      assert_error <<-CRYSTAL, "declares T both as a parameter and as an associated type"
        module App
          module Coll
            trait Both(T)
              type T

              abstract def go : T
            end
          end
        end
        CRYSTAL
    end
  end

  # iyi: `abstract def self.zero : self` — a trait requiring a class-level
  # method (SPEC.md II.6). Needed for an identity: `Enumerable#sum` has no
  # element to ask when the collection is empty.
  describe "class-level requirements" do
    it "lets a default method reach the requirement through an associated type" do
      assert_type(<<-CRYSTAL) { int32 }
        module App
          module Coll
            trait Num
              abstract def self.zero : self
              abstract def add(other : self) : self
            end

            impl Num for Int32
              def self.zero : self
                0
              end

              def add(other : self) : self
                self + other
              end
            end

            trait Container
              type Elem

              abstract def first : Elem

              def start : Elem where Elem : Num
                Elem.zero
              end
            end

            struct Nums
              def initialize
              end
            end

            impl Container for Nums
              type Elem = Int32

              def first : Int32
                1
              end
            end
          end
        end

        App::Coll::Nums.new.start
        CRYSTAL
    end

    it "reports a class-level requirement the impl does not satisfy" do
      # Named `self.zero`, because that is what has to be written to fix it.
      assert_error <<-CRYSTAL, "is missing a method required by the trait: self.zero"
        module App
          module Coll
            trait Num
              abstract def self.zero : self
              abstract def add(other : self) : self
            end

            struct Money
              def initialize
              end
            end

            impl Num for Money
              def add(other : self) : self
                Money.new
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports instance and class requirements together" do
      assert_error <<-CRYSTAL, "is missing methods required by the trait: add, self.zero"
        module App
          module Coll
            trait Num
              abstract def self.zero : self
              abstract def add(other : self) : self
            end

            struct Money
            end

            impl Num for Money
            end
          end
        end
        CRYSTAL
    end

    it "still refuses an abstract class method outside a trait" do
      # A trait is the only type whose implementers have their class methods
      # checked; anywhere else the requirement would oblige nobody.
      assert_error <<-CRYSTAL, "can't define abstract def on metaclass"
        abstract class Base
          abstract def self.make : self
        end
        CRYSTAL
    end
  end

  # iyi: `impl Into(String) for User` — a trait with parameters (SPEC.md II.6).
  # Parameters are the form to reach for where several impls for one type are
  # the point; associated types are the form for a single answer per type.
  describe "parameterised traits" do
    it "implements a trait at a type argument" do
      assert_type(<<-CRYSTAL) { string }
        module App
          module Conv
            trait Into(T)
              abstract def into : T
            end

            struct User
              def initialize
              end
            end

            impl Into(String) for User
              def into : String
                "u"
              end
            end
          end
        end

        App::Conv::User.new.into
        CRYSTAL
    end

    it "checks the impl's signature against the type argument" do
      # The argument is not decoration: `Into(String)` instantiates the trait,
      # so the requirement being satisfied is `into : String`.
      assert_error <<-CRYSTAL, "must return String"
        module App
          module Conv
            trait Into(T)
              abstract def into : T
            end

            struct User
              def initialize
              end
            end

            impl Into(String) for User
              def into : Int32
                1
              end
            end
          end
        end

        App::Conv::User.new.into
        CRYSTAL
    end

    it "reports a missing type argument at the impl" do
      assert_error <<-CRYSTAL, "type arguments must be specified when implementing App::Conv::Into(T), one for each of T"
        module App
          module Conv
            trait Into(T)
              abstract def into : T
            end

            struct User
            end

            impl Into for User
              def into : String
                "u"
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports type arguments given to a trait that has no parameters" do
      assert_error <<-CRYSTAL, "can't implement App::Conv::Plain with type arguments, it's not a generic trait"
        module App
          module Conv
            trait Plain
              abstract def go : Int32
            end

            struct User
            end

            impl Plain(String) for User
              def go : Int32
                1
              end
            end
          end
        end
        CRYSTAL
    end

    it "reports the wrong number of type arguments" do
      assert_error <<-CRYSTAL, "wrong number of type arguments for App::Conv::Into(T) (given 2, expected 1)"
        module App
          module Conv
            trait Into(T)
              abstract def into : T
            end

            struct User
            end

            impl Into(String, Int32) for User
              def into : String
                "u"
              end
            end
          end
        end
        CRYSTAL
    end
  end
end
