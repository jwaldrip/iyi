require "../spec_helper"
require "../../src/compiler/iyi/syntax/diagnostic_semantic_defaults"

# The gate reflects the compiler's reopened classes, so this file needs the full
# compiler. It refuses to compile without them instead of checking less.
{% unless Iyi::Block.has_method?(:binder) %}
  {% raise "diagnostic_semantic_defaults_full_spec requires the full compiler types (Block#binder)" %}
{% end %}

struct Iyi::SmallNodeList
  def test_set_second(node : Iyi::ASTNode) : Nil
    @second = node
  end

  def test_set_tail(node : Iyi::ASTNode) : Nil
    @tail = [node] of Iyi::ASTNode
  end
end

describe Iyi::DiagnosticSemanticDefaults do
  describe "coverage, both directions" do
    it "matches declared semantic fields to the table for every supported kind" do
      Iyi::DiagnosticSemanticDefaults.verify_coverage!
    end

    it "refuses a table that drops a declared semantic row" do
      missing = Iyi::DiagnosticFieldTable::TABLE.dup
      missing["Call"] = Iyi::DiagnosticFieldTable::TABLE["Call"].reject { |row| row.field == "expanded" }
      expect_raises(ArgumentError, /uncovered=Call\.expanded/) do
        Iyi::DiagnosticSemanticDefaults.verify_coverage!(missing)
      end
    end

    it "refuses a table semantic row that no declaration covers" do
      extra = Iyi::DiagnosticFieldTable::TABLE.dup
      extra["Call"] = Iyi::DiagnosticFieldTable::TABLE["Call"] + [
        Iyi::DiagnosticFieldTable::Row.new("no_such_field", Iyi::DiagnosticAstFieldClass::Infrastructure, Iyi::DiagnosticFieldTable::Role::Infrastructure, Iyi::DiagnosticFieldTable::Coordinate::Single, nil, nil, nil, Iyi::DiagnosticFieldTable::Provenance::Semantic),
      ]
      expect_raises(ArgumentError, /unlisted=Call\.no_such_field/) do
        Iyi::DiagnosticSemanticDefaults.verify_coverage!(extra)
      end
    end

    it "lists the reflected ivars of a kind without an instance" do
      Iyi::DiagnosticSemanticDefaults.reflected_fields("Call").includes?("uses_with_scope").should eq(true)
    end

    it "refuses a kind the reflection does not know" do
      expect_raises(ArgumentError, /unclassified AST kind/) do
        Iyi::DiagnosticSemanticDefaults.reflected_fields("Nope")
      end
    end
  end

  describe "inert nil states on nilable fields" do
    it "accepts a nilable nil-defaulted field while its raw value is nil" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "expanded")
    end

    it "accepts the nilable enclosing_call base field while its raw value is nil" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "enclosing_call")
    end

    it "accepts a nilable nil-defaulted field on a path" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Path.new("Foo"), "target_const")
    end

    it "refuses a nilable field once its real nil property becomes non-nil" do
      call = Iyi::Call.new(nil, "f")
      call.expanded = Iyi::NumberLiteral.new(1)
      expect_raises(ArgumentError, /Call\.expanded: raw value is not nil/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "expanded")
      end
    end

    it "refuses the base enclosing_call once a call is assigned to it" do
      call = Iyi::Call.new(nil, "f")
      call.enclosing_call = Iyi::Call.new(nil, "g")
      expect_raises(ArgumentError, /Call\.enclosing_call: raw value is not nil/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "enclosing_call")
      end
    end

  end

  describe "per-field checks on real nodes" do
    it "accepts a fresh call's false flag, the Bool default" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "uses_with_scope")
    end

    it "accepts a fresh call's empty dependency list, the SmallNodeList default" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "dependencies")
    end

    it "accepts a fresh call's dirty flag, the base Bool default" do
      Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "dirty")
    end

    it "refuses a field that is not declared for the node's class" do
      expect_raises(ArgumentError, /not a declared semantic field/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::NumberLiteral.new(1), "uses_with_scope")
      end
    end

    it "refuses a field the table does not declare at all" do
      expect_raises(ArgumentError, /not a declared semantic field/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(Iyi::Call.new(nil, "f"), "no_such_field")
      end
    end
  end

  describe "mismatched Bool states" do
    it "refuses a call whose uses_with_scope flag is set" do
      call = Iyi::Call.new(nil, "f")
      call.uses_with_scope = true
      expect_raises(ArgumentError, /Call\.uses_with_scope: raw value differs/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "uses_with_scope")
      end
    end

    it "refuses a cast whose upcast flag is set" do
      cast = Iyi::Cast.new(Iyi::Var.new("x"), Iyi::Path.new("Int32"))
      cast.upcast = true
      expect_raises(ArgumentError, /Cast\.upcast: raw value differs/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(cast, "upcast")
      end
    end

    it "refuses a def whose abi_info flag is set" do
      node = Iyi::Def.new("f")
      Iyi::DiagnosticSemanticDefaults.check_field!(node, "abi_info")
      node.abi_info = true
      expect_raises(ArgumentError, /Def\.abi_info: raw value differs/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(node, "abi_info")
      end
    end
  end

  describe "SmallNodeList raw state" do
    it "refuses a dependency list whose raw @first is set" do
      call = Iyi::Call.new(nil, "f")
      call.dependencies.push(Iyi::NumberLiteral.new(1))
      expect_raises(ArgumentError, /Call\.dependencies: raw list is not empty/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "dependencies")
      end
    end

    it "refuses a dependency list with only raw @second set" do
      call = Iyi::Call.new(nil, "f")
      call.dependencies.test_set_second(Iyi::NumberLiteral.new(2))
      expect_raises(ArgumentError, /Call\.dependencies: raw list is not empty/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "dependencies")
      end
    end

    it "refuses a dependency list with only raw @tail set" do
      call = Iyi::Call.new(nil, "f")
      call.dependencies.test_set_tail(Iyi::NumberLiteral.new(3))
      expect_raises(ArgumentError, /Call\.dependencies: raw list is not empty/) do
        Iyi::DiagnosticSemanticDefaults.check_field!(call, "dependencies")
      end
    end
  end

  describe "tree checks" do
    it "refuses a tree with changed semantic state in a child" do
      child = Iyi::Call.new(nil, "f")
      child.expanded = Iyi::NumberLiteral.new(1)
      root = Iyi::Expressions.new([child] of Iyi::ASTNode)
      expect_raises(ArgumentError, /Call\.expanded: raw value is not nil/) do
        Iyi::DiagnosticSemanticDefaults.verify_tree!(root)
      end
    end

    it "refuses mutated semantic state through the inventory entry path" do
      child = Iyi::Call.new(nil, "f")
      root = Iyi::Expressions.new([child] of Iyi::ASTNode)
      before = Iyi::DiagnosticAstInventorySnapshot.new(root).bytes
      before.includes?("Call").should be_true
      child.expanded = Iyi::NumberLiteral.new(1)
      expect_raises(ArgumentError, /Call\.expanded: raw value is not nil/) do
        Iyi::DiagnosticAstInventorySnapshot.new(root)
      end
    end
  end
end
