require "../support/syntax"

# FunDef name and unnamed-parameter controls for the capture binder. Legacy
# controls pin what the byte-level walk accepts and refuses; they authorize
# nothing. Bound controls go through the replay journal and identity. Shared
# replay helpers in diagnostic_replay_binding_spec.cr are file-private, so these
# carry their own copies under distinct names.

private def fun_name_spec_input(source : String, filename : String) : Iyi::AcceptedCaptureInput
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  parser.enable_diagnostic_observations
  parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
    nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
end

# The replay root and journal as `bind!` builds them, so a control can mutate
# the replayed tree before the binders see it.
private def fun_name_spec_replay(source : String, path : String) : {Iyi::AcceptedCaptureInput, Iyi::ASTNode, Iyi::DiagnosticReplayJournal}
  input = fun_name_spec_input(source, path)
  parser = input.replay_parser
  parser.enable_diagnostic_observations
  root = parser.parse
  {input, root, Iyi::DiagnosticReplayJournal.new(parser.diagnostic_lexical_observations)}
end

# The bound walk exactly as `bind!` runs it after the digest check.
private def fun_name_spec_verify(input, root, journal)
  identity = Iyi::DiagnosticModuleIdentity.from(root, input, journal)
  structural = Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
  Iyi::DiagnosticEvidenceBinding.new(input, journal, identity, structural).verify!(root)
end

private def fun_name_spec_funs(root : Iyi::ASTNode) : Array(Iyi::FunDef)
  body = root.as(Iyi::LibDef).body
  items = body.is_a?(Iyi::Expressions) ? body.expressions : [body]
  items.map(&.as(Iyi::FunDef))
end

describe "FunDef real name legacy controls" do
  it "accepts an implicit real name equal to the source name" do
    input, root, _ = fun_name_spec_replay("lib LibC\n  fun abs(x : Int32) : Int32\nend\n", "/spec/binding/fun_implicit.iyi")
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end

  it "accepts an explicit bare real name" do
    input, root, _ = fun_name_spec_replay("lib LibC\n  fun gcollect = GC_gcollect : Void\nend\n", "/spec/binding/fun_explicit.iyi")
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end

  it "accepts an explicit bare real name equal to the name" do
    input, root, _ = fun_name_spec_replay("lib LibC\n  fun abs = abs : Int32\nend\n", "/spec/binding/fun_equal.iyi")
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end

  it "refuses a mutated implicit real name" do
    input, root, _ = fun_name_spec_replay("lib LibC\n  fun abs(x : Int32) : Int32\nend\n", "/spec/binding/fun_mut_implicit.iyi")
    fun_name_spec_funs(root)[0].real_name = "other"
    expect_raises(ArgumentError, "invalid implicit foreign-name observation") do
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end

  it "refuses a mutated explicit real name against its source token" do
    input, root, _ = fun_name_spec_replay("lib LibC\n  fun gcollect = GC_gcollect : Void\nend\n", "/spec/binding/fun_mut_explicit.iyi")
    fun_name_spec_funs(root)[0].real_name = "other"
    expect_raises(ArgumentError, "name field differs from source evidence") do
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end
end

describe "unnamed parameter binder (D1 index counting, U4 swap)" do
  it "binds two written unnamed parameters, then refuses them once their restrictions are swapped" do
    input, root, journal = fun_name_spec_replay("lib LibC\n  fun two(Int32, ::Int32) : Void\nend\n", "/spec/binding/two_unnamed.iyi")
    # Positive baseline first: the second unnamed parameter (index 1) must count its own comma.
    Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root).size.should eq 2
    # Load-bearing mutation: the same two parameters with their restrictions swapped.
    args = fun_name_spec_funs(root)[0].args
    first_restriction = args[0].restriction
    args[0].restriction = args[1].restriction
    args[1].restriction = first_restriction
    expect_raises(ArgumentError, "structural witness differs") do
      Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
    end
  end
end

describe "FunDef name position (D4) bound positive" do
  it "binds two funs in one lib, each name tied to its own fun keyword" do
    input, root, journal = fun_name_spec_replay("lib LibC\n  fun a = A_real : Void\n  fun b(Int32) : Void\nend\n", "/spec/binding/two_funs.iyi")
    fun_name_spec_verify(input, root, journal)
  end
end

describe "bound literal presence (D2 fail-closed)" do
  # A literal node with no replay evidence must not pass in bound mode by omission.
  # The literal is the root of the walk, so no name-bearing parent can fail first.
  it "refuses a StringLiteral with no literal evidence" do
    input, root, journal = fun_name_spec_replay("value = 1\n", "/spec/binding/d2_string.iyi")
    identity = Iyi::DiagnosticModuleIdentity.from(root, input, journal)
    literal = Iyi::StringLiteral.new("abc")
    expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
      Iyi::DiagnosticEvidenceBinding.new(input, journal, identity, Set(UInt64).new).verify!(literal)
    end
  end

  it "refuses a CharLiteral with no literal evidence" do
    input, root, journal = fun_name_spec_replay("value = 1\n", "/spec/binding/d2_char.iyi")
    identity = Iyi::DiagnosticModuleIdentity.from(root, input, journal)
    literal = Iyi::CharLiteral.new('a')
    expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
      Iyi::DiagnosticEvidenceBinding.new(input, journal, identity, Set(UInt64).new).verify!(literal)
    end
  end
end
