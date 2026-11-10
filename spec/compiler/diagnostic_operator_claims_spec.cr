require "../support/syntax"

# Operator-name claims, parsed with diagnostic capture on and off. The capture
# run must name each operator production by its witnessed tokens, and the
# capture-off run must produce the same tree with no evidence at all.

private def operator_claim_parse(source : String, capture : Bool) : Iyi::ASTNode
  parser = Iyi::Parser.new(source)
  if capture
    parser.filename = "/spec/operator_claims.cr"
    parser.diagnostic_source_file = "/spec/operator_claims.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
  end
  parser.parse
end

private def operator_claim_last(root : Iyi::ASTNode) : Iyi::ASTNode
  root.is_a?(Iyi::Expressions) ? root.expressions.last : root
end

private def operator_claim_primary(node : Iyi::ASTNode) : Iyi::DiagnosticNameValue
  node.diagnostic_name_slots[Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)].first
end

private def operator_claim_derived(node : Iyi::ASTNode) : Iyi::DiagnosticOrigin::DerivedName
  value = operator_claim_primary(node)
  value.should be_a(Iyi::DiagnosticNameValue::Derived)
  value.as(Iyi::DiagnosticNameValue::Derived).origin
end

describe "derived operator names" do
  it "names an op-assign statement by its op token" do
    root = operator_claim_last(operator_claim_parse("x = 0\nx += 1", true))
    root.should be_a(Iyi::OpAssign)
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::OpAssign)
    origin.rendered_text.should eq("+")
    origin.operator_witnesses.map(&.raw_text).should eq(["+="])
  end

  it "names an op-assign method target and keeps the target's observed name" do
    root = operator_claim_parse("f.x += 2", true).as(Iyi::OpAssign)
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::OpAssign)
    origin.rendered_text.should eq("+")
    operator_claim_primary(root.target).should be_a(Iyi::DiagnosticNameValue::Observed)
  end

  it "names a setter call by its identifier and the equals sign" do
    root = operator_claim_parse("f.x = 1", true).as(Iyi::Call)
    root.name.should eq("x=")
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::Setter)
    origin.rendered_text.should eq("x=")
    origin.operator_witnesses.map(&.raw_text).should eq(["x", "="])
  end

  it "names an index read and an index read with a query suffix" do
    read = operator_claim_derived(operator_claim_parse("a[0]", true))
    read.operator_production.should eq(Iyi::DiagnosticOperatorProduction::Index)
    read.operator_witnesses.map(&.raw_text).should eq(["[", "]"])

    query = operator_claim_derived(operator_claim_parse("a[0]?", true))
    query.operator_production.should eq(Iyi::DiagnosticOperatorProduction::IndexQuery)
    query.rendered_text.should eq("[]?")
    query.operator_witnesses.map(&.raw_text).should eq(["[", "]", "?"])
  end

  it "renames an index read to []= over its brackets and the equals sign" do
    root = operator_claim_parse("a[0] = 1", true).as(Iyi::Call)
    root.name.should eq("[]=")
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::IndexAssign)
    origin.rendered_text.should eq("[]=")
    origin.operator_witnesses.map(&.raw_text).should eq(["[", "]", "="])
  end

  it "renames an empty index read to []= over its single [] token" do
    root = operator_claim_parse("a[] = 1", true).as(Iyi::Call)
    root.name.should eq("[]=")
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::IndexAssign)
    origin.operator_witnesses.map(&.raw_text).should eq(["[]", "="])
  end

  it "names a signed number operand by its sign-selected witness" do
    call = operator_claim_parse("y = x-1", true).as(Iyi::Assign).value.as(Iyi::Call)
    call.name.should eq("-")
    origin = operator_claim_derived(call)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::SignedNumber)
    origin.rendered_text.should eq("-")
    origin.operator_witnesses.map(&.raw_text).should eq(["-1"])
    origin.operator_witnesses[0].selection.should eq(Iyi::DiagnosticTokenSelection::SignedNumberSign)
  end

  it "names a regex match index through its lookup derivation" do
    root = operator_claim_last(operator_claim_parse("\"x\" =~ /(x)/\n$1", true)).as(Iyi::Call)
    root.name.should eq("[]")
    operator_claim_primary(root).should be_a(Iyi::DiagnosticNameValue::Derived)
  end

  it "names a backtick command by its opener" do
    root = operator_claim_parse("`ls`", true).as(Iyi::Call)
    root.name.should eq("`")
    origin = operator_claim_derived(root)
    origin.operator_production.should eq(Iyi::DiagnosticOperatorProduction::Command)
    origin.operator_witnesses.map(&.raw_text).should eq(["`"])
  end

  it "keeps spaced binary, dotted operator, and empty index names observed" do
    operator_claim_primary(operator_claim_parse("1 - 1", true).as(Iyi::Call)).should be_a(Iyi::DiagnosticNameValue::Observed)
    operator_claim_primary(operator_claim_parse("f.+(1)", true).as(Iyi::Call)).should be_a(Iyi::DiagnosticNameValue::Observed)
    operator_claim_primary(operator_claim_parse("a[]", true).as(Iyi::Call)).should be_a(Iyi::DiagnosticNameValue::Observed)
  end

  it "builds the same tree and no evidence when capture is off" do
    sources = ["x = 0\nx += 1", "f.x += 2", "f.x = 1", "a[0] = 1", "a[] = 1", "a[0]?",
               "y = x-1", "`ls`", "\"x\" =~ /(x)/\n$1"]
    sources.each do |source|
      plain = operator_claim_parse(source, false)
      captured = operator_claim_parse(source, true)
      plain.to_s.should eq(captured.to_s)
      operator_claim_last(plain).diagnostic_origin.should be_nil
      operator_claim_last(plain).diagnostic_name_slots.should be_empty
    end
  end
end
