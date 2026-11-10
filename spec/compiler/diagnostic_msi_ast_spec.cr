require "../support/syntax"
require "../../src/compiler/iyi/syntax/diagnostic_msi_ast"

alias MsiAstWire = Iyi::DiagnosticMsi
alias MsiAstAdapter = Iyi::DiagnosticMsiAst

def msi_ast_envelope : JSON::Any
  MsiAstWire.obj({"entry" => MsiAstWire.str("Parse"), "kind" => MsiAstWire.str("SourceFile")})
end

def msi_ast_bind(root : Iyi::ASTNode, input : Bytes = Bytes.empty) : MsiAstWire::Bundle
  MsiAstAdapter.bind(root, input, "Probe", msi_ast_envelope, "a" * 64)
end

def msi_ast_verify(bundle : MsiAstWire::Bundle) : MsiAstWire::Verified
  MsiAstWire.verify(bundle.root, bundle.shards, MsiAstAdapter.schema)
end

def msi_ast_digest(root : Iyi::ASTNode) : String
  msi_ast_bind(root).root_digest
end

# A chain of `length` nodes: each level is an Expressions over the one below.
def msi_ast_chain(length : Int32) : Iyi::ASTNode
  node = Iyi::NilLiteral.new.as(Iyi::ASTNode)
  (length - 1).times do
    node = Iyi::Expressions.new([node] of Iyi::ASTNode)
  end
  node
end

describe Iyi::DiagnosticMsiAst do
  describe "binding" do
    it "binds a graph of every supported literal kind and verifies it" do
      root = Iyi::Expressions.new([
        Iyi::NumberLiteral.new("42").as(Iyi::ASTNode),
        Iyi::BoolLiteral.new(true).as(Iyi::ASTNode),
        Iyi::CharLiteral.new('x').as(Iyi::ASTNode),
        Iyi::StringLiteral.new("hi").as(Iyi::ASTNode),
        Iyi::SymbolLiteral.new("sym").as(Iyi::ASTNode),
        Iyi::NilLiteral.new.as(Iyi::ASTNode),
        Iyi::Nop.new.as(Iyi::ASTNode),
      ] of Iyi::ASTNode)
      verified = msi_ast_verify(msi_ast_bind(root))
      # the root plus seven distinct children
      verified.node_count.should eq(8_i64)
    end

    it "is deterministic for an identical graph" do
      build = -> { Iyi::Expressions.new([Iyi::NumberLiteral.new("1").as(Iyi::ASTNode), Iyi::NumberLiteral.new("2").as(Iyi::ASTNode)] of Iyi::ASTNode) }
      msi_ast_digest(build.call).should eq(msi_ast_digest(build.call))
    end

    it "binds the input bytes exactly" do
      input = "source text".to_slice
      verified = msi_ast_verify(msi_ast_bind(Iyi::Nop.new, input))
      verified.input.should eq(input)
    end

    it "keeps a shared node as one node and an alias, not two copies" do
      shared = Iyi::NumberLiteral.new("1")
      aliased = Iyi::Expressions.new([shared, shared] of Iyi::ASTNode)
      copied = Iyi::Expressions.new([Iyi::NumberLiteral.new("1"), Iyi::NumberLiteral.new("1")] of Iyi::ASTNode)
      msi_ast_verify(msi_ast_bind(aliased)).node_count.should eq(2_i64)
      msi_ast_verify(msi_ast_bind(copied)).node_count.should eq(3_i64)
      msi_ast_digest(aliased).should_not eq(msi_ast_digest(copied))
    end
  end

  describe "ordered edges and distinctions" do
    it "treats the order of children as part of the graph" do
      a = Iyi::NumberLiteral.new("1")
      b = Iyi::NumberLiteral.new("2")
      forward = Iyi::Expressions.new([a, b] of Iyi::ASTNode)
      reversed = Iyi::Expressions.new([b, a] of Iyi::ASTNode)
      msi_ast_digest(forward).should_not eq(msi_ast_digest(reversed))
    end

    it "distinguishes an empty container from Nop" do
      msi_ast_digest(Iyi::Expressions.new([] of Iyi::ASTNode)).should_not eq(msi_ast_digest(Iyi::Nop.new))
    end

    it "distinguishes an empty string from a present one" do
      msi_ast_digest(Iyi::StringLiteral.new("")).should_not eq(msi_ast_digest(Iyi::StringLiteral.new("x")))
    end

    it "distinguishes the expression keyword" do
      plain = Iyi::Expressions.new([Iyi::NilLiteral.new.as(Iyi::ASTNode)] of Iyi::ASTNode)
      paren = Iyi::Expressions.new([Iyi::NilLiteral.new.as(Iyi::ASTNode)] of Iyi::ASTNode)
      paren.keyword = Iyi::Expressions::Keyword::Paren
      msi_ast_digest(plain).should_not eq(msi_ast_digest(paren))
    end

    it "distinguishes each scalar value and its kind" do
      msi_ast_digest(Iyi::BoolLiteral.new(true)).should_not eq(msi_ast_digest(Iyi::BoolLiteral.new(false)))
      msi_ast_digest(Iyi::NumberLiteral.new("1", :i32)).should_not eq(msi_ast_digest(Iyi::NumberLiteral.new("1", :i64)))
      msi_ast_digest(Iyi::CharLiteral.new('a')).should_not eq(msi_ast_digest(Iyi::CharLiteral.new('b')))
      msi_ast_digest(Iyi::StringInterpolation.new([] of Iyi::ASTNode, 0)).should_not eq(msi_ast_digest(Iyi::StringInterpolation.new([] of Iyi::ASTNode, 2)))
    end

    it "binds a root that is a single Nop" do
      msi_ast_verify(msi_ast_bind(Iyi::Nop.new)).node_count.should eq(1_i64)
    end
  end

  describe "freezing" do
    it "writes the snapshot taken before a later mutation, unchanged" do
      literal = Iyi::StringLiteral.new("alpha")
      root = Iyi::Expressions.new([literal] of Iyi::ASTNode)
      expected = msi_ast_bind(root)
      frozen = MsiAstAdapter.snapshot(root)
      literal.value = "beta"
      root.expressions << Iyi::NilLiteral.new
      replayed = MsiAstWire::Writer.new(MsiAstAdapter.schema).write(frozen, Bytes.empty, "Probe", msi_ast_envelope, "a" * 64)
      replayed.root_digest.should eq(expected.root_digest)
    end
  end

  describe "bounds" do
    it "accepts a chain of exactly the depth limit" do
      msi_ast_verify(msi_ast_bind(msi_ast_chain(129))).node_count.should eq(129_i64)
    end

    it "refuses a chain one level deeper than the limit" do
      expect_raises(ArgumentError) { msi_ast_bind(msi_ast_chain(130)) }
    end

    it "refuses a cycle" do
      looped = Iyi::Expressions.new([] of Iyi::ASTNode)
      looped.expressions << looped
      expect_raises(ArgumentError) { msi_ast_bind(looped) }
    end
  end

  describe "negative controls" do
    it "refuses a node kind with no schema entry" do
      expect_raises(ArgumentError) { msi_ast_bind(Iyi::ArrayLiteral.new) }
    end

    it "refuses an unsupported kind nested under a supported one" do
      root = Iyi::Expressions.new([Iyi::NilLiteral.new.as(Iyi::ASTNode), Iyi::ArrayLiteral.new.as(Iyi::ASTNode)] of Iyi::ASTNode)
      expect_raises(ArgumentError) { msi_ast_bind(root) }
    end

    it "refuses a located node, since locations are structured origin" do
      literal = Iyi::NumberLiteral.new("1")
      literal.location = Iyi::Location.new("source.cr", 1, 1)
      expect_raises(ArgumentError) { msi_ast_bind(literal) }
    end

    it "refuses a located node deep in the graph" do
      literal = Iyi::NumberLiteral.new("1")
      literal.end_location = Iyi::Location.new("source.cr", 1, 2)
      root = Iyi::Expressions.new([Iyi::NilLiteral.new.as(Iyi::ASTNode), Iyi::Expressions.new([literal] of Iyi::ASTNode).as(Iyi::ASTNode)] of Iyi::ASTNode)
      expect_raises(ArgumentError) { msi_ast_bind(root) }
    end

    it "refuses a node that records macro lineage" do
      literal = Iyi::NumberLiteral.new("1")
      literal.diagnostic_macro_lineage = Iyi::DiagnosticMacroLineage::Constructed
      expect_raises(ArgumentError) { msi_ast_bind(literal) }
    end

    it "refuses a node with an explicit external name" do
      literal = Iyi::NumberLiteral.new("1")
      literal.diagnostic_external_explicit = true
      expect_raises(ArgumentError) { msi_ast_bind(literal) }
    end

    it "refuses a real parsed graph, which always carries locations" do
      parsed = Iyi::Parser.parse("1")
      parsed.diagnostic_stored_location.nil?.should eq(false)
      expect_raises(ArgumentError) { msi_ast_bind(parsed) }
    end

    it "refuses a ParseToDef entry" do
      to_def = MsiAstWire.obj({"entry" => MsiAstWire.str("ParseToDef"), "kind" => MsiAstWire.str("SourceFile")})
      expect_raises(ArgumentError) { MsiAstAdapter.bind(Iyi::Nop.new, Bytes.empty, "Probe", to_def, "a" * 64) }
    end

    it "refuses a MacroExpansion input kind" do
      macro_kind = MsiAstWire.obj({"entry" => MsiAstWire.str("Parse"), "kind" => MsiAstWire.str("MacroExpansion")})
      expect_raises(ArgumentError) { MsiAstAdapter.bind(Iyi::Nop.new, Bytes.empty, "Probe", macro_kind, "a" * 64) }
    end

    it "refuses an envelope with no entry or input kind" do
      expect_raises(ArgumentError) { MsiAstAdapter.bind(Iyi::Nop.new, Bytes.empty, "Probe", MsiAstWire.obj({} of String => JSON::Any), "a" * 64) }
      expect_raises(ArgumentError) { MsiAstAdapter.bind(Iyi::Nop.new, Bytes.empty, "Probe", JSON::Any.new("Parse"), "a" * 64) }
    end
  end
end
