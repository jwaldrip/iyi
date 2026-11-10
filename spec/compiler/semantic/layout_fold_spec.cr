require "../../spec_helper"

# Settled layout folds at the semantic level.
#
# A fold records itself while typing. Settling replaces only a stale
# expression value, and does so with a new node, so a generic instance that
# holds the old literal as a type variable keeps its value. A type argument is
# never replaced. Under the native gate a stale type argument is an error.

private def layout_fold_program(code : String, iyi_prelude : Bool = true, cleanup : Bool = true) : Program
  program = Program.new
  program.color = false
  program.iyi_prelude = iyi_prelude
  program.define_crystal_constants
  program.semantic(program.normalize(parse(code)), cleanup: cleanup)
  program
end

private def layout_fold_header : String
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

# Grows `M` after the folds above, so their values go stale.
private def layout_fold_growth : String
  "b = G({Int64, Int64}).new({1_i64, 2_i64}).as(M)\n"
end

describe "Semantic: layout folds" do
  describe "recording" do
    it "marks a fold inside a type argument and leaves a plain fold unmarked" do
      program = layout_fold_program(<<-CODE)
        x = sizeof(Int32)
        buf = StaticArray(UInt8, sizeof(Int32)).new(0_u8)
        CODE

      folds = program.layout_folds.values.select { |fold| fold.kind == LayoutFoldKind::Size && fold.subject.to_s == "Int32" }
      folds.size.should eq 2
      folds.count(&.type_argument).should eq 1
    end

    it "marks no fold as a type argument when no fold sits in one" do
      program = layout_fold_program("x = sizeof(Int32)\nx\n")
      program.layout_folds.values.any?(&.type_argument).should be_false
    end
  end

  describe "settling" do
    it "replaces a stale expression with a new node and leaves the old literal's value unchanged" do
      program = layout_fold_program(layout_fold_header + "s1 = sizeof({Int32, M})\n" + layout_fold_growth, cleanup: false)
      fold = program.layout_folds.values.find! { |f| f.kind == LayoutFoldKind::Size && f.subject.to_s == "{Int32, M}" }
      node = fold.node.as(ExpandableNode)
      before = node.expanded.not_nil!
      before.as(NumberLiteral).value.should eq "8"

      program.settle_layout_folds(patch: true)

      after = node.expanded.not_nil!
      after.should_not be(before)
      after.as(NumberLiteral).value.should eq "32"
      before.as(NumberLiteral).value.should eq "8"
    end

    it "keeps the same node for a fold whose value is already final" do
      program = layout_fold_program("x = sizeof(Int32)\nx\n", cleanup: false)
      fold = program.layout_folds.values.find! { |f| f.subject.to_s == "Int32" }
      node = fold.node.as(ExpandableNode)
      before = node.expanded.not_nil!

      program.settle_layout_folds(patch: true)

      node.expanded.should be(before)
    end

    it "corrects a stale expression under --crystal" do
      program = layout_fold_program(layout_fold_header + "s1 = sizeof({Int32, M})\n" + layout_fold_growth, iyi_prelude: false)
      fold = program.layout_folds.values.find! { |f| f.kind == LayoutFoldKind::Size && f.subject.to_s == "{Int32, M}" }
      fold.node.as(ExpandableNode).expanded.as(NumberLiteral).value.should eq "32"
    end

    it "keeps a type argument's fold and the expression tied to it under --crystal" do
      program = layout_fold_program(layout_fold_header + "e = sizeof({Int32, M})\n" + layout_fold_growth + "buf = StaticArray(UInt8, sizeof({Int32, M})).new(0_u8)\n", iyi_prelude: false)
      type_arg = program.layout_folds.values.find! { |f| f.type_argument }
      tied = program.layout_folds.values.find! { |f| !f.type_argument && f.kind == LayoutFoldKind::Size && f.subject.to_s == "{Int32, M}" }
      type_arg.node.as(ExpandableNode).expanded.as(NumberLiteral).value.should eq "8"
      tied.node.as(ExpandableNode).expanded.as(NumberLiteral).value.should eq "8"
    end

    it "refuses a stale type argument under the native gate" do
      expect_raises(Iyi::TypeException, /when it was used as a type argument, but/) do
        layout_fold_program(layout_fold_header + "buf = StaticArray(UInt8, sizeof({Int32, M})).new(0_u8)\n" + layout_fold_growth)
      end
    end

    it "does not refuse that same type argument under --crystal" do
      program = layout_fold_program(layout_fold_header + "buf = StaticArray(UInt8, sizeof({Int32, M})).new(0_u8)\n" + layout_fold_growth, iyi_prelude: false)
      type_arg = program.layout_folds.values.find! { |f| f.type_argument }
      type_arg.node.as(ExpandableNode).expanded.as(NumberLiteral).value.should eq "8"
    end
  end

  describe "constants" do
    it "keeps a settled constant's value a NumberLiteral" do
      program = layout_fold_program(layout_fold_header + "CONST = sizeof({Int32, M})\n" + layout_fold_growth)
      const = program.types["CONST"].as(Const)
      const.value.should be_a(NumberLiteral)
      const.value.as(NumberLiteral).value.should eq "32"
    end

    it "keeps a stable constant's value a NumberLiteral" do
      program = layout_fold_program("CONST = sizeof(Int32)\nCONST\n")
      program.types["CONST"].as(Const).value.as(NumberLiteral).value.should eq "4"
    end
  end
end
