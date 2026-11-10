require "../support/syntax"

# The census comes from the ASTNode type hierarchy, not from SUPPORTED. A new
# concrete node, or a new stored field on an existing node, that the schema does
# not classify fails here instead of evading capture.
describe Iyi::DiagnosticAstFieldSchema do
  kinds = Iyi::DiagnosticAstFieldSchema.census_kinds
  pairs = Iyi::DiagnosticAstFieldSchema.census_pairs

  it "enumerates a non-empty census that includes known concrete nodes" do
    kinds.includes?("Call").should eq(true)
    kinds.includes?("Def").should eq(true)
    kinds.includes?("Path").should eq(true)
    kinds.includes?("Nop").should eq(true)
    pairs.includes?({"Call", "name"}).should eq(true)
  end

  it "excludes abstract bases from the census" do
    kinds.includes?("ASTNode").should eq(false)
    kinds.includes?("UnaryExpression").should eq(false)
    kinds.includes?("BinaryOp").should eq(false)
    kinds.includes?("ControlExpression").should eq(false)
  end

  it "classifies every concrete node kind as supported" do
    unsupported = kinds.reject { |kind| Iyi::DiagnosticAstFieldSchema::SUPPORTED.includes?(kind) }
    unsupported.should eq([] of String)
  end

  it "has no SUPPORTED kind without a concrete node behind it" do
    stale = Iyi::DiagnosticAstFieldSchema::SUPPORTED.reject { |kind| kinds.includes?(kind) }
    stale.should eq([] of String)
  end

  it "classifies every stored field of every supported concrete node" do
    unclassified = [] of String
    pairs.each do |kind, field|
      next unless Iyi::DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
      begin
        Iyi::DiagnosticAstFieldSchema.classify(kind, field)
      rescue ArgumentError
        unclassified << "#{kind}.#{field}"
      end
    end
    unclassified.should eq([] of String)
  end
end
