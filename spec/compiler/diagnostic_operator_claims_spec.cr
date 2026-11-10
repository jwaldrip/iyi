require "../support/syntax"

# Operator-name and structural-name claims, parsed with diagnostic capture on
# and off. The capture run must name each production by its witnessed tokens,
# and the capture-off run must produce the same tree with no evidence at all.

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

# The FunDefs of a parsed lib, whether it holds one fun or several.
private def operator_claim_funs(root : Iyi::ASTNode) : Array(Iyi::FunDef)
  body = root.as(Iyi::LibDef).body
  items = body.is_a?(Iyi::Expressions) ? body.expressions : [body]
  items.map(&.as(Iyi::FunDef))
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
end

describe "derived structural names" do
  it "names each unnamed lib parameter by its separator and type head" do
    lib_def = operator_claim_parse("lib L\n  fun f(Int32, Char*)\nend", true)
    first, second = operator_claim_funs(lib_def)[0].args
    first.name.should eq("")
    second.name.should eq("")
    [first, second].each do |arg|
      origin = operator_claim_derived(arg)
      origin.derivation_kind.should eq("StructuralName")
      origin.rendered_text.should eq("")
      origin.producer_context.should eq("parameter")
    end
  end

  it "binds each written unnamed lib parameter whatever its head token" do
    # PC-1, PC-4 and PC-5: a CONST head, a `::` head, and the head of a proc notation.
    source = "lib LibC\n  fun abs(Int32) : Int32\n  fun two(Int32, Void*) : Void\n" \
             "  fun h(::Int32) : Void\n  fun k(Int32 -> Void) : Void\nend"
    funs = operator_claim_funs(operator_claim_parse(source, true))
    funs.size.should eq(4)
    funs.each do |fun_def|
      fun_def.args.each do |arg|
        operator_claim_derived(arg).derivation_kind.should eq("StructuralName")
      end
    end
    funs[1].args.size.should eq(2)
  end

  it "leaves a named lib parameter observed and never structural" do
    fun_def = operator_claim_funs(operator_claim_parse("lib L\n  fun n(x : Int32)\nend", true))[0]
    fun_def.args[0].name.should eq("x")
    operator_claim_primary(fun_def.args[0]).should be_a(Iyi::DiagnosticNameValue::Observed)
  end

  it "names a short block argument and its receiver by one fresh local" do
    root = operator_claim_parse("[1].map(&.abs)", true).as(Iyi::Call)
    block = root.block.not_nil!
    param = block.args[0]
    param.as(Iyi::Var).name.should eq("__arg0")
    origin = operator_claim_derived(param)
    origin.derivation_kind.should eq("StructuralName")
    origin.rendered_text.should eq("__arg0")
    origin.producer_context.should eq("local_reference")
    receiver = block.body.as(Iyi::Call).obj.not_nil!
    operator_claim_derived(receiver).rendered_text.should eq("__arg0")
  end

  it "binds a short block argument whose method is the % operator" do
    root = operator_claim_parse("[1].map(&.%(2))", true).as(Iyi::Call)
    param = root.block.not_nil!.args[0]
    operator_claim_derived(param).rendered_text.should eq("__arg0")
  end
end

describe "operator and structural names with capture off" do
  it "builds the same tree and no evidence when capture is off" do
    sources = ["x = 0\nx += 1", "f.x += 2", "f.x = 1", "a[0] = 1", "a[] = 1", "a[0]?",
               "y = x-1", "`ls`", "\"x\" =~ /(x)/\n$1", "[1].map(&.abs)", "[1].map(&.%(2))"]
    sources.each do |source|
      plain = operator_claim_parse(source, false)
      captured = operator_claim_parse(source, true)
      plain.to_s.should eq(captured.to_s)
      operator_claim_last(plain).diagnostic_origin.should be_nil
      operator_claim_last(plain).diagnostic_name_slots.should be_empty
    end
  end

  it "keeps an unnamed lib parameter unnamed when capture is off" do
    fun_def = operator_claim_funs(operator_claim_parse("lib L\n  fun f(Int32)\nend", false))[0]
    fun_def.args[0].diagnostic_name_slots.should be_empty
  end
end
