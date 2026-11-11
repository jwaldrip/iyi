require "../../spec_helper"

# A layout fold read before it settles is judged by what the read built.
#
# Native: a use that builds a type argument, an enum value, a macro's output or
# a typing decision from a stale value is refused. A use whose result still
# comes out the same under the final layout is not.
#
# `--crystal`: nothing is refused. A stale use keeps the value Crystal 1.21.0
# gives it, and the layouts it read are pinned so their neighbours agree.
#
# Every program goes through `Program#semantic`, or through the two top-level
# passes it is split into, as the compiler runs them.

private def fold_use_program(iyi_prelude : Bool) : Program
  program = Program.new
  program.color = false
  program.iyi_prelude = iyi_prelude
  program.define_crystal_constants
  program
end

private def fold_use_semantic(program : Program, code : String, cleanup : Bool = true) : ASTNode
  program.semantic(program.normalize(parse(code)), cleanup: cleanup)
end

# A header that defines `M` and one implementor, with no `raise` of its own.
private def fold_use_module : String
  <<-CODE
    module M
    end

    struct G(T)
      include M

      def initialize(@v : T)
      end
    end

    a = G(Int8).new(1_i8).as(M)

    CODE
end

# Adds an implementor of `M` that is larger than any so far, so every layout
# fold of `M` goes stale.
private def fold_use_growth : String
  "b = G({Int64, Int64}).new({1_i64, 2_i64}).as(M)\n"
end

# One program: the header, the main code `body`, and the cleanup-typing code. The
# exhaustive `case` makes the cleanup write a `raise(String)` for its unreachable
# branch, and the cleanup types the body of that user `raise`.
private def fold_use_source(body : String, raise_body : String = "") : String
  <<-CODE
    require "primitives"

    module M
    end

    struct G(T)
      include M

      def initialize(@v : T)
      end
    end

    enum Color
      Red
      Green
    end

    struct Enum
      def ==(other : self)
        value == other.value
      end
    end

    def raise(message : String) : NoReturn
      #{raise_body}
      while true
      end
    end

    a = G(Int8).new(1_i8).as(M)
    #{body}
    c = Color::Red
    case c
    in .red?
      1
    in .green?
      2
    end
    CODE
end

# The cleanup-typing code alone, for a second pass over a program whose header
# and constants an earlier pass has already typed and cleaned.
private def fold_use_cleanup_source(raise_body : String) : String
  <<-CODE
    enum Color
      Red
      Green
    end

    struct Enum
      def ==(other : self)
        value == other.value
      end
    end

    def raise(message : String) : NoReturn
      #{raise_body}
      while true
      end
    end

    c = Color::Red
    case c
    in .red?
      1
    in .green?
      2
    end
    CODE
end

# Declares `X = sizeof({Int32, M})` in a first pass, which settles and cleans it,
# as a finished top-level pass does. `growth` runs in the same pass, after `X`.
private def fold_use_declare_x(program : Program, growth : String = "") : Nil
  fold_use_semantic(program, "require \"primitives\"\n" + fold_use_module + "X = sizeof({Int32, M})\n" + growth)
end

# A second pass whose cleanup types `raise_body`. `X` is already a cleaned constant
# when that body is typed, so a read of it there sees the literal the constant holds.
private def fold_use_after_cleanup(program : Program, raise_body : String) : ASTNode
  fold_use_declare_x(program)
  fold_use_semantic(program, fold_use_cleanup_source(raise_body))
end

# `X` folds to 8 and is 32 after growth. `Y` derives from it.
private def fold_use_derived : String
  "X = sizeof({Int32, M})\nY = X &+ 1\nx = X\ny = Y\n"
end

private def fold_use_const(program : Program, name : String) : Const
  program.types[name].as(Const)
end

private def fold_use_literal(program : Program, name : String) : NumberLiteral
  fold_use_const(program, name).value.as(NumberLiteral)
end

# The literal a `sizeof` of `subject` was expanded to, found by its fold record.
# Unlike the constant's value, this is a literal as soon as the fold is typed,
# so it is read here before cleanup has replaced the constant's `sizeof`.
private def fold_use_fold_literal(program : Program, subject : String) : NumberLiteral
  fold = program.layout_folds.values.find! { |f| f.kind == LayoutFoldKind::Size && f.subject.to_s == subject }
  fold.node.as(ExpandableNode).expanded.as(NumberLiteral)
end

private def fold_use_static_array(program : Program, size : Int32) : GenericInstanceType
  program.static_array_of(program.types["UInt8"], size).as(GenericInstanceType)
end

# Every number a generic instance holds as a type variable, found the way
# `Program` walks its own types.
private def fold_use_type_variables(type : Type, found : Array(NumberLiteral)) : Nil
  nested_types = type.types?
  return unless nested_types

  nested_types.each_value do |nested|
    if nested.is_a?(GenericType)
      nested.each_instantiated_type do |instance|
        next unless instance.is_a?(GenericInstanceType)
        instance.type_vars.each_value { |var| found << var if var.is_a?(NumberLiteral) }
      end
    end
    fold_use_type_variables(nested, found)
  end
end

# Control 13: a type variable that is a layout fold literal is always backed by an
# adopted read, so no literal can be held without a use that justified it.
private def fold_use_census(program : Program) : Nil
  found = [] of NumberLiteral
  fold_use_type_variables(program, found)
  program.file_modules.each_value { |file_module| fold_use_type_variables(file_module, found) }

  found.each do |literal|
    next unless program.layout_fold_of(literal)

    adopted = program.layout_fold_uses.any? do |use|
      use.reads.any? { |read| read.literal.same?(literal) && read.adopted }
    end
    adopted.should be_true
  end
end

describe "Semantic: layout fold uses" do
  describe "native" do
    it "refuses a derived type argument whose input moved (control 1)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source(fold_use_derived, fold_use_growth + "buf = StaticArray(UInt8, Y).new\n"))
      end
    end

    it "does not refuse a derived type argument whose result is still equal (control 4)" do
      program = fold_use_program(true)
      # `&*` by zero reads X and gives 0 whatever X is, so W is 4 both before and
      # after growth. Written without parentheses or a bitwise mask.
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nW = X &* 0 &+ 4\n", fold_use_growth + "buf = StaticArray(UInt8, W).new\n"))

      fold_use_literal(program, "X").value.should eq "32"
      fold_use_const(program, "W").compile_time_value.should eq 4
      fold_use_census(program)
    end

    it "does not refuse a value that no type, enum, macro or typing decision takes (control 3)" do
      program = fold_use_program(true)
      fold_use_semantic(program, fold_use_source(fold_use_derived, fold_use_growth))

      fold_use_literal(program, "X").value.should eq "32"
      fold_use_const(program, "Y").compile_time_value.should eq 33
      fold_use_census(program)
    end

    it "refuses a type argument that is the fold's own copy (control 5)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nx = X\n", fold_use_growth + "buf = StaticArray(UInt8, X).new\n"))
      end
    end

    it "refuses a def return type built from a stale constant (control 6)" do
      program = fold_use_program(true)
      body = fold_use_derived + "def make : StaticArray(UInt8, Y)\n  StaticArray(UInt8, 9).new\nend\n"
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source(body, fold_use_growth + "make\n"))
      end
    end

    it "refuses a macro that consumed a stale value after cleanup (control 7)" do
      program = fold_use_program(true)
      # The macro is in the `raise` the cleanup types, after X is a cleaned
      # constant and after the growth. Its output `8` differs from `32`.
      expect_raises(Iyi::TypeException, /a macro read/) do
        fold_use_after_cleanup(program, fold_use_growth + "z = {{ X }}\n")
      end
    end

    it "does not refuse a macro that reads a changed value and never uses it (control 7, unused read)" do
      program = fold_use_program(true)
      # The macro reads X into a macro variable and never uses it, so its output
      # `1` is the same whatever X is. Only a read whose value is consumed can differ.
      fold_use_after_cleanup(program, fold_use_growth + "{% unused = X %}z = {{ 1 }}\n")

      fold_use_literal(program, "X").value.should eq "32"
      fold_use_census(program)
    end

    it "does not refuse a macro whose output is the same under the final layout (control 7, same output)" do
      program = fold_use_program(true)
      # Multiplying by zero produces the same output for either layout.
      fold_use_after_cleanup(program, fold_use_growth + "z = {{ X * 0 }}\n")

      fold_use_literal(program, "X").value.should eq "32"
      fold_use_census(program)
    end

    it "refuses a tuple index that a stale constant selects after cleanup (control 8)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /typing read/) do
        fold_use_after_cleanup(program, fold_use_growth + "t = {1, 2, 3, 4, 5, 6, 7, 8, 9}\nt[X]\n")
      end
    end

    it "does not refuse a fold whose value no type takes (control 9)" do
      program = fold_use_program(true)
      # A type argument whose value no type takes: `Foo` is built from the type of
      # the computed size, `Int32`. Type arguments take no operators, so the
      # computed size is given through `typeof`.
      body = "struct Foo(T)\nend\nf = Foo(typeof(sizeof({Int32, M}) &+ 1)).new\n" + fold_use_growth
      fold_use_semantic(program, fold_use_source(body))

      fold_use_fold_literal(program, "{Int32, M}").value.should eq "32"
      fold_use_census(program)
    end

    it "does not refuse a temporary copy used only as a value (temp)" do
      program = fold_use_program(true)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nt = X &+ 1\nu = t\n", fold_use_growth))

      fold_use_literal(program, "X").value.should eq "32"
      fold_use_census(program)
    end

    it "refuses a nested derivation whose input moved (nested)" do
      program = fold_use_program(true)
      # Z derives from Y, which derives from X. Each step is a constant read by
      # name, so no parentheses are needed.
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nY = X &+ 1\nZ = Y &* 2\n", fold_use_growth + "buf = StaticArray(UInt8, Z).new\n"))
      end
    end

    it "writes nothing when it refuses, and names the measured value (error)" do
      program = fold_use_program(true)
      error = expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source(fold_use_derived, fold_use_growth + "buf = StaticArray(UInt8, Y).new\n"))
      end

      fold_use_literal(program, "X").value.should eq "8"
      error.inner.try(&.message).to_s.should contain "measured 8 here"
    end

    it "refuses an adopted literal that is still stale (control 10, adoption)" do
      program = fold_use_program(true)
      # X is cleaned in the first pass, so the second pass's type argument adopts
      # the very literal the constant holds. Growth in the second pass makes it stale.
      fold_use_semantic(program, "require \"primitives\"\n" + fold_use_module + "X = sizeof({Int32, M})\n")
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_growth + "buf = StaticArray(UInt8, X).new\n")
      end
    end

    it "accepts an adopted literal that was corrected before it was adopted (control 10, adoption after correction)" do
      program = fold_use_program(true)
      fold_use_declare_x(program, fold_use_growth)

      literal = fold_use_literal(program, "X")
      literal.value.should eq "32"
      literal.should be(fold_use_fold_literal(program, "{Int32, M}"))

      fold_use_semantic(program, "buf = StaticArray(UInt8, X).new\n")

      literal.value.should eq "32"
      fold_use_static_array(program, 32).type_vars["N"].should be(literal)
      fold_use_census(program)
    end

    it "accepts a fresh use of the corrected value made after the first settle (control 10, fresh use)" do
      program = fold_use_program(true)
      fold_use_semantic(program, fold_use_module + "X = sizeof({Int32, M})\n" + fold_use_growth, cleanup: false)
      program.settle_layout_folds(patch: true)
      literal = fold_use_fold_literal(program, "{Int32, M}")
      literal.value.should eq "32"

      fold_use_semantic(program, "buf = StaticArray(UInt8, sizeof({Int32, M})).new\n", cleanup: false)
      program.settle_layout_folds(patch: true)

      literal.value.should eq "32"
      fold_use_census(program)
    end

    it "refuses an enum value computed from a stale constant (control 11)" do
      program = fold_use_program(true)
      first, first_processor = program.top_level_semantic(program.normalize(parse(fold_use_module + "X = sizeof({Int32, M})\n")))
      first = program.semantic_after_top_level(first, first_processor)

      second, second_processor = program.top_level_semantic(program.normalize(parse("enum E\n  A = X\nend\n" + fold_use_growth + "e = E::A\n")))
      expect_raises(Iyi::TypeException, /enum value/) do
        program.semantic_after_top_level(second, second_processor)
      end
    end
  end

  describe "--crystal" do
    it "keeps the value a derived type argument read and pins its input (control 2)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source(fold_use_derived, fold_use_growth + "buf = StaticArray(UInt8, Y).new\n"))

      fold_use_literal(program, "X").value.should eq "8"
      fold_use_const(program, "Y").compile_time_value.should eq 9
      fold_use_static_array(program, 9).type_vars["N"].as(NumberLiteral).value.should eq "9"
      fold_use_census(program)
    end

    it "keeps a type argument's literal, and the copy of it, tied together (control 5)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nx = X\n", fold_use_growth + "buf = StaticArray(UInt8, X).new\n"))

      literal = fold_use_literal(program, "X")
      literal.value.should eq "8"
      fold_use_static_array(program, 8).type_vars["N"].should be(literal)
      fold_use_census(program)
    end

    it "does not refuse a stale def return type, and keeps its input (control 6, crystal)" do
      program = fold_use_program(false)
      body = fold_use_derived + "def make : StaticArray(UInt8, Y)\n  StaticArray(UInt8, 9).new\nend\n"
      fold_use_semantic(program, fold_use_source(body, fold_use_growth + "make\n"))

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "does not refuse a stale macro after cleanup, and keeps its input (control 7, crystal)" do
      program = fold_use_program(false)
      fold_use_after_cleanup(program, fold_use_growth + "z = {{ X }}\n")

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "does not refuse a stale tuple index after cleanup, and keeps its input (control 8, crystal)" do
      program = fold_use_program(false)
      fold_use_after_cleanup(program, fold_use_growth + "t = {1, 2, 3, 4, 5, 6, 7, 8, 9}\nt[X]\n")

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "keeps an adopted stale literal and the type argument that holds it (control 10, crystal)" do
      program = fold_use_program(false)
      fold_use_semantic(program, "require \"primitives\"\n" + fold_use_module + "X = sizeof({Int32, M})\n")
      fold_use_semantic(program, fold_use_growth + "buf = StaticArray(UInt8, X).new\n")

      literal = fold_use_literal(program, "X")
      literal.value.should eq "8"
      fold_use_static_array(program, 8).type_vars["N"].should be(literal)
      fold_use_census(program)
    end

    it "keeps the enum value and the constant it was computed from (control 11, crystal)" do
      program = fold_use_program(false)
      first, first_processor = program.top_level_semantic(program.normalize(parse(fold_use_module + "X = sizeof({Int32, M})\n")))
      first = program.semantic_after_top_level(first, first_processor)

      second, second_processor = program.top_level_semantic(program.normalize(parse("enum E\n  A = X\nend\n" + fold_use_growth + "e = E::A\n")))
      program.semantic_after_top_level(second, second_processor)

      fold_use_literal(program, "X").value.should eq "8"
      program.types["E"].as(EnumType).types["A"].as(Const).compile_time_value.should eq 8
    end

    it "keeps a nested derivation's input and computes its value from it (nested, crystal)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nY = X &+ 1\nZ = Y &* 2\n", fold_use_growth + "buf = StaticArray(UInt8, Z).new\n"))

      fold_use_literal(program, "X").value.should eq "8"
      fold_use_const(program, "Z").compile_time_value.should eq 18
      fold_use_census(program)
    end

    it "reports each stale use it keeps, and pins the expression fold that shares its layout (control 12)" do
      previous = ENV["IYI_LAYOUT_FOLD_REPORT"]?
      ENV["IYI_LAYOUT_FOLD_REPORT"] = "1"
      begin
        program = fold_use_program(false)
        # `s` is a second expression fold of the same layout as X. It is not a use,
        # so it is pinned only because it shares the component that the type
        # argument through Y pins.
        fold_use_semantic(program, fold_use_source(fold_use_derived + "s = sizeof({Int32, M})\n", fold_use_growth + "buf = StaticArray(UInt8, Y).new\n"))

        program.layout_fold_lines.any?(&.includes?("layout fold use stale")).should be_true

        folds = program.layout_folds.values.select { |f| f.kind == LayoutFoldKind::Size && f.subject.to_s == "{Int32, M}" }
        folds.size.should eq 2
        shared = folds.last
        shared.node.as(ExpandableNode).expanded.as(NumberLiteral).value.should eq "8"
        fold_use_literal(program, "X").value.should eq "8"

        tied = program.layout_fold_lines.select(&.includes?("in main: folded 8, final 32: kept (tied to type argument"))
        tied.size.should eq 2
      ensure
        if previous
          ENV["IYI_LAYOUT_FOLD_REPORT"] = previous
        else
          ENV.delete("IYI_LAYOUT_FOLD_REPORT")
        end
      end
    end
  end
end
