require "../support/syntax"

private def capture_refs_digest(root : Iyi::ASTNode) : String
  Iyi::DiagnosticAstFrameStream.new(root).stream { |_| }
end

private def capture_refs_collect(root : Iyi::ASTNode) : Array(Iyi::DiagnosticCaptureFieldRef?)
  refs = [] of Iyi::DiagnosticCaptureFieldRef?
  seen = Set(UInt64).new
  visit = uninitialized Proc(Iyi::ASTNode, Nil)
  visit = ->(node : Iyi::ASTNode) do
    if seen.add?(node.object_id)
      refs << node.diagnostic_capture_ref
      Iyi::DiagnosticDirectChildFields.each(node) { |_, _, _, child| visit.call(child) }
    end
    nil
  end
  visit.call(root)
  refs
end

private def capture_refs_record(source : String, path : String)
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = path
  ledger = Iyi::DiagnosticCaptureLedger.new
  root, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
  {root, claim, authority, ledger}
end

describe "capture field references" do
  it "stamps the recorded parse and identical bound replay without changing its digest in either lexical mode" do
    {".iyi", ".cr"}.each do |suffix|
      source = "value = 1\nother = 2\n"
      path = File.tempname("capture-refs", suffix)
      File.write(path, source)
      begin
        root, claim, authority, ledger = capture_refs_record(source, path)
        capture_refs_digest(root).should eq authority.ast_sha256
        live_refs = capture_refs_collect(root)
        live_refs.size.should be > 1
        live_refs.all? { |ref| !ref.nil? && ref.not_nil!.capture_id == claim.capture_key }.should be_true
        root.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(claim.capture_key, "[]", "root")
        ledger.freeze!
        replay = ledger.bind!(claim, authority).root
        capture_refs_collect(replay).should eq live_refs
        capture_refs_digest(replay).should eq authority.ast_sha256
      ensure
        File.delete(path) if File.file?(path)
      end
    end
  end

  it "uses first-visit identity for aliases without changing the framed digest" do
    shared = Iyi::Var.new("a")
    root = Iyi::Expressions.new([shared, shared] of Iyi::ASTNode)
    key = "a" * 64
    digest = capture_refs_digest(root)
    Iyi::DiagnosticCaptureRefs.stamp!(root, key)
    shared.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(key, "[]", "expressions", 0)
    root.expressions[0].same?(root.expressions[1]).should be_true
    capture_refs_digest(root).should eq digest
    shared.clone.diagnostic_capture_ref.should eq shared.diagnostic_capture_ref
  end

  it "distinguishes record children and encodes keyed ancestor steps" do
    key = "b" * 64
    left = Iyi::Var.new("left")
    right = Iyi::Var.new("right")
    literal = Iyi::HashLiteral.new([Iyi::HashLiteral::Entry.new(left, right)] of Iyi::HashLiteral::Entry)
    Iyi::DiagnosticCaptureRefs.stamp!(literal, key)
    left.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(key, "[]", "entries.key", 0)
    right.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(key, "[]", "entries.value", 0)
    left.diagnostic_capture_ref.should_not eq right.diagnostic_capture_ref

    leaf = Iyi::Var.new("leaf")
    nested = Iyi::Expressions.new([leaf] of Iyi::ASTNode)
    definition = Iyi::Def.new("f", [] of Iyi::Arg)
    definition.free_var_bounds = {"T/é" => nested.as(Iyi::ASTNode)}
    Iyi::DiagnosticCaptureRefs.stamp!(definition, key)
    nested.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(key, "[]", "free_var_bounds", nil, "T/é")
    owner_path = [["free_var_bounds", nil, Base64.strict_encode("T/é")]].to_json
    leaf.diagnostic_capture_ref.should eq Iyi::DiagnosticCaptureFieldRef.new(key, owner_path, "expressions", 0)
  end

  it "refuses cycles like the frame stream instead of assigning an alias coordinate" do
    root = Iyi::Expressions.new([] of Iyi::ASTNode)
    root.expressions << root
    expect_raises(ArgumentError, "cyclic AST inventory") { capture_refs_digest(root) }
    expect_raises(ArgumentError, "cyclic AST inventory") { Iyi::DiagnosticCaptureRefs.stamp!(root, "c" * 64) }
  end

  it "does not turn a forged reference into an authority or hide AST mutations" do
    source = "value = 1\n"
    first = File.tempname("capture-ref-first", ".iyi")
    second = File.tempname("capture-ref-second", ".iyi")
    File.write(first, source)
    File.write(second, source)
    begin
      root, claim, authority, ledger = capture_refs_record(source, first)
      _, other_claim, _, _ = capture_refs_record(source, second)
      root.diagnostic_capture_ref = Iyi::DiagnosticCaptureFieldRef.new(other_claim.capture_key, "[]", "root")
      capture_refs_digest(root).should eq authority.ast_sha256
      ledger.freeze!
      expect_raises(ArgumentError, "capture key differs from its authority") { ledger.bind!(other_claim, authority) }
      root.as(Iyi::Assign).value = Iyi::NumberLiteral.new(2)
      capture_refs_digest(root).should_not eq authority.ast_sha256
      ledger.bind!(claim, authority).root.diagnostic_capture_ref.not_nil!.capture_id.should eq claim.capture_key
    ensure
      File.delete(first) if File.file?(first)
      File.delete(second) if File.file?(second)
    end
  end
end
