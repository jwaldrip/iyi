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
end
