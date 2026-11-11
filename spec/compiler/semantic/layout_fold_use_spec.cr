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

# The cleanup-typing program: the exhaustive `case` makes the cleanup write a
# `raise(String)` for its unreachable branch, and the cleanup types the body of
# that user `raise`. Whatever `raise_body` grows is therefore typed after the
# main code has read its folds.
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
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nW = (X & 16) &+ 4\n", fold_use_growth + "buf = StaticArray(UInt8, W).new\n"))

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
      body = fold_use_derived + "def make : StaticArray(UInt8, Y)\n  uninitialized StaticArray(UInt8, 9)\nend\n"
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source(body, fold_use_growth + "make\n"))
      end
    end

    it "refuses a macro that reads a stale constant (control 7)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /a macro read/) do
        fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\n", fold_use_growth + "z = {{ X }}\n"))
      end
    end

    it "refuses a tuple index that a stale constant selects (control 8)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /typing read/) do
        fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\n", fold_use_growth + "t = {1, 2, 3, 4, 5, 6, 7, 8, 9}\nt[X]\n"))
      end
    end

    it "does not refuse a fold whose value no type takes (control 9)" do
      program = fold_use_program(true)
      body = "struct Foo(T)\nend\nf = Foo(sizeof({Int32, M}) &+ 1)\n" + fold_use_growth
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
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nZ = (X &+ 1) &* 2\n", fold_use_growth + "buf = StaticArray(UInt8, Z).new\n"))
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

    it "refuses an adoption made before the first settle (control 10, native half)" do
      program = fold_use_program(true)
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        fold_use_semantic(program, fold_use_module + "X = sizeof({Int32, M})\nbuf = StaticArray(UInt8, X).new\n" + fold_use_growth, cleanup: false)
        program.settle_layout_folds(patch: true)
      end
    end

    it "accepts an adoption after a correction, and a second settle (control 10)" do
      program = fold_use_program(true)
      fold_use_semantic(program, fold_use_module + "X = sizeof({Int32, M})\n" + fold_use_growth, cleanup: false)
      program.settle_layout_folds(patch: true)
      literal = fold_use_literal(program, "X")
      literal.value.should eq "32"

      fold_use_semantic(program, "buf = StaticArray(UInt8, X).new\n", cleanup: false)
      program.settle_layout_folds(patch: true)

      literal.value.should eq "32"
      fold_use_census(program)
    end

    it "refuses an enum value computed from a stale constant (control 11)" do
      program = fold_use_program(true)
      first, first_processor = program.top_level_semantic(program.normalize(parse(fold_use_module + "X = sizeof({Int32, M})\n")))
      program.semantic_after_top_level(first, first_processor)

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
      body = fold_use_derived + "def make : StaticArray(UInt8, Y)\n  uninitialized StaticArray(UInt8, 9)\nend\n"
      fold_use_semantic(program, fold_use_source(body, fold_use_growth + "make\n"))

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "does not refuse a stale macro, and keeps its input (control 7, crystal)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\n", fold_use_growth + "z = {{ X }}\n"))

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "does not refuse a stale tuple index, and keeps its input (control 8, crystal)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\n", fold_use_growth + "t = {1, 2, 3, 4, 5, 6, 7, 8, 9}\nt[X]\n"))

      fold_use_literal(program, "X").value.should eq "8"
    end

    it "keeps the enum value and the constant it was computed from (control 11, crystal)" do
      program = fold_use_program(false)
      first, first_processor = program.top_level_semantic(program.normalize(parse(fold_use_module + "X = sizeof({Int32, M})\n")))
      program.semantic_after_top_level(first, first_processor)

      second, second_processor = program.top_level_semantic(program.normalize(parse("enum E\n  A = X\nend\n" + fold_use_growth + "e = E::A\n")))
      program.semantic_after_top_level(second, second_processor)

      fold_use_literal(program, "X").value.should eq "8"
      program.types["E"].as(EnumType).types["A"].as(Const).compile_time_value.should eq 8
    end

    it "keeps a nested derivation's input and computes its value from it (nested, crystal)" do
      program = fold_use_program(false)
      fold_use_semantic(program, fold_use_source("X = sizeof({Int32, M})\nZ = (X &+ 1) &* 2\n", fold_use_growth + "buf = StaticArray(UInt8, Z).new\n"))

      fold_use_literal(program, "X").value.should eq "8"
      fold_use_const(program, "Z").compile_time_value.should eq 18
      fold_use_census(program)
    end

    it "reports each stale use it keeps, with the layouts it pins (control 12)" do
      previous = ENV["IYI_LAYOUT_FOLD_REPORT"]?
      ENV["IYI_LAYOUT_FOLD_REPORT"] = "1"
      begin
        program = fold_use_program(false)
        fold_use_semantic(program, fold_use_source(fold_use_derived, fold_use_growth + "buf = StaticArray(UInt8, Y).new\n"))

        program.layout_fold_lines.any?(&.includes?("layout fold use stale")).should be_true
        program.layout_fold_lines.any?(&.includes?("tied to type argument")).should be_true
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
