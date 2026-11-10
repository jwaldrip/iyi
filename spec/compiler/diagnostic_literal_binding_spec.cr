require "../support/syntax"

private def literal_binding_source(source : String, suffix : String, & : Iyi::DiagnosticBoundCapture ->)
  path = File.tempname("literal-binding", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    yield ledger.bind!(claim, authority)
  ensure
    File.delete(path) if File.file?(path)
  end
end

private def literal_binding_replay(source : String, &)
  path = File.tempname("literal-replay", ".cr")
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, _ = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    replay = claim.replay_parser
    replay.enable_diagnostic_observations
    root = claim.replay_entry(replay)
    journal = Iyi::DiagnosticReplayJournal.new(replay.diagnostic_lexical_observations)
    reducer = Iyi::DiagnosticLiteralReplay.new(claim, journal,
      replay.diagnostic_folded_string_observations, replay.diagnostic_interpolation_observations,
      replay.diagnostic_literal_owner_observations)
    yield root, reducer, replay, journal, claim
  ensure
    File.delete(path) if File.file?(path)
  end
end

describe Iyi::DiagnosticLiteralReplay do
  it "derives a value and rejects a forged decoded value" do
    literal_binding_replay("\"hello\"") do |root, reducer, _parser, _journal, _claim|
      node = root.as(Iyi::StringLiteral)
      literal = node.diagnostic_literal_names[{"value", 0}]
      productions = node.diagnostic_literal_productions[{"value", 0}]
      reducer.value!(literal, productions).should eq("hello")
      forged = Iyi::DiagnosticParsedLiteral.new(literal.input_sha256, literal.input_bytesize,
        literal.lexical_mode, Base64.strict_encode("wrong".to_slice), literal.segments, nil)
      expect_raises(ArgumentError, "literal decoded value differs from scanned tokens") do
        reducer.value!(forged, productions)
      end
    end
  end

  it "rejects a missing opener even when the original source bytes still match" do
    literal_binding_replay("\"hello\"") do |root, reducer, parser, journal, claim|
      node = root.as(Iyi::StringLiteral)
      literal = node.diagnostic_literal_names[{"value", 0}]
      productions = node.diagnostic_literal_productions[{"value", 0}]
      reducer.value!(literal, productions).should eq("hello")
      entries = journal.entries.reject { |entry| entry.token_kind == "DELIMITER_START" }
      damaged = Iyi::DiagnosticReplayJournal.new(entries)
      broken = Iyi::DiagnosticLiteralReplay.new(claim, damaged, parser.diagnostic_folded_string_observations,
        parser.diagnostic_interpolation_observations, parser.diagnostic_literal_owner_observations)
      expect_raises(ArgumentError, "literal witness is not a scanned token") do
        broken.value!(literal, productions)
      end
    end
  end

  it "rejects a mutated stored literal despite an unchanged parser observation" do
    literal_binding_replay("\"hello\"") do |root, reducer, parser, _journal, _claim|
      node = root.as(Iyi::StringLiteral)
      binder = Iyi::DiagnosticLiteralOwnerBinding.new(reducer, parser.diagnostic_literal_owner_observations)
      binder.verify_node!(node)
      node.value = "other"
      expect_raises(ArgumentError, "literal decoded value differs from scanned tokens") do
        binder.verify_node!(node)
      end
    end
  end

  it "rejects a changed asm option flag after replay" do
    literal_binding_replay("asm(\"nop\" : : : : \"volatile\")") do |root, reducer, parser, journal, claim|
      node = root.as(Iyi::Asm)
      binder = Iyi::DiagnosticLiteralOwnerBinding.new(reducer, parser.diagnostic_literal_owner_observations)
      grammar = Iyi::DiagnosticScalarGrammarReplay.new(claim, journal, binder, parser.diagnostic_scalar_grammar_observations)
      grammar.verify!(root)
      node.volatile = false
      mutated = Iyi::DiagnosticScalarGrammarReplay.new(claim, journal, binder, parser.diagnostic_scalar_grammar_observations)
      expect_raises(ArgumentError, "asm options differ") { mutated.verify!(root) }
    end
  end
end

describe Iyi::DiagnosticLiteralReplayAssociations do
  it "rejects reordered owner edges after its baseline snapshot" do
    literal_binding_replay("\"a\"\n\"b\"\n") do |root, _reducer, parser, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, parser, root)
      bundle.verify_graph!(root)
      root.as(Iyi::Expressions).expressions.reverse!
      expect_raises(ArgumentError, "literal replay graph differs") { bundle.verify_graph!(root) }
    end
  end

  it "binds an interpolation with no text piece and rejects replacing its expression" do
    literal_binding_replay("\"\#{name}\"") do |root, _reducer, parser, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, parser, root)
      bundle.verify_relationships!
      root.as(Iyi::StringInterpolation).expressions[0] = Iyi::Var.new("other")
      expect_raises(ArgumentError, "interpolation wrapper differs") { bundle.verify_relationships! }
    end
  end

  it "derives regex modifiers from the journal and rejects changed flags" do
    literal_binding_replay("/hello/im") do |root, _reducer, parser, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, parser, root)
      bundle.verify_relationships!
      root.as(Iyi::RegexLiteral).options = Iyi::RegexOptions::None
      expect_raises(ArgumentError, "regex options differ") { bundle.verify_relationships! }
    end
  end

  it "checks percent array dynamic and splat element boundaries" do
    literal_binding_replay("%W(one \#{name} \#{*items})") do |root, _reducer, parser, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, parser, root)
      bundle.verify_relationships!
      root.as(Iyi::ArrayLiteral).elements.reverse!
      expect_raises(ArgumentError, "percent array association differs") { bundle.verify_relationships! }
    end
  end

  it "does not expose the journal's internal entry array" do
    token = Iyi::DiagnosticRenderedToken.new(0, 3, "CHAR", "'a'", "Crystal", value_base64: "YQ==")
    journal = Iyi::DiagnosticReplayJournal.new([token])
    journal.entries.clear
    exposed = journal.entries.first
    exposed.token_text.to_slice[1] = 'z'.ord.to_u8
    journal.literal_entry!(0, 3, "CHAR", "Crystal").should eq(token)
  end
end

describe "direct capture binding" do
  it "rejects an unfrozen ledger even when called without the ledger facade" do
    source = "value = 1\n"
    path = File.tempname("literal-ledger", ".cr")
    File.write(path, source)
    begin
      parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
      parser.filename = path
      ledger = Iyi::DiagnosticCaptureLedger.new
      _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
      expect_raises(ArgumentError, "capture ledger must be frozen before binding") do
        Iyi::DiagnosticCaptureBinding.bind!(claim, authority)
      end
    ensure
      File.delete(path) if File.file?(path)
    end
  end
end

describe "literal source binding" do
  it "binds ordinary, folded, continued and array literals in both lexical modes" do
    source = "a = \"hello\"\nb = \"pre\#{\"mid\"}post\"\nc = \"a\" \\\n  \"b\"\nd = %w(one two)\ne = %i(one two)\nf = 'x'\n"
    [".cr", ".iyi"].each do |suffix|
      literal_binding_source(source, suffix) { |bound| bound.root.should_not be_nil }
    end
  end

  it "binds asm duplicate options rather than reducing away their occurrences" do
    source = "asm(\"nop\" : : : \"memory\" : \"volatile\", \"volatile\", \"intel\")\n"
    [".cr", ".iyi"].each do |suffix|
      literal_binding_source(source, suffix) { |bound| bound.root.should_not be_nil }
    end
  end

  it "binds require strings, magic constants, regex and command interpolation" do
    source = "require \"./part\"\na = __FILE__\nb = __DIR__\nc = /x\#{a}/\nd = `echo \#{a}`\n"
    [".cr", ".iyi"].each do |suffix|
      literal_binding_source(source, suffix) { |bound| bound.root.should_not be_nil }
    end
  end

  it "binds heredoc indentation and an interpolation" do
    source = "name = \"world\"\na = <<-TEXT\n  hello \#{name}\n  TEXT\n"
    [".cr", ".iyi"].each do |suffix|
      literal_binding_source(source, suffix) { |bound| bound.root.should_not be_nil }
    end
  end
end

describe Iyi::DiagnosticReplayJournal do
  it "derives a character value from the exact scanned token" do
    token = Iyi::DiagnosticRenderedToken.new(0, 4, "CHAR", "'\\n'", "Crystal", value_base64: "Cg==")
    journal = Iyi::DiagnosticReplayJournal.new([token, token])
    witness = Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::StringPiece, 0, 4)
    production = Iyi::DiagnosticLiteralProductionSegment.new(Iyi::DiagnosticLiteralProduction::CharToken,
      0, 4, "J1xuJw==", nil, nil, nil, nil, [witness])
    journal.literal_atom!(production, "Crystal").should eq("\n")
  end

  it "refuses conflicting observations at the same offset" do
    char = Iyi::DiagnosticRenderedToken.new(0, 3, "CHAR", "'a'", "Crystal", value_base64: "YQ==")
    other = Iyi::DiagnosticRenderedToken.new(0, 3, "SYMBOL", "'a'", "Crystal", value_base64: "YQ==")
    journal = Iyi::DiagnosticReplayJournal.new([char, other])
    expect_raises(ArgumentError, "ambiguous scanned token") do
      journal.literal_entry!(0, 3, "CHAR", "Crystal")
    end
  end

  it "accepts only lexer-observed trivia and refuses gaps and mode changes" do
    comment = Iyi::DiagnosticRenderedToken.new(0, 2, "SKIPPED_COMMENT", "#x", "Crystal")
    space = Iyi::DiagnosticRenderedToken.new(2, 3, "SPACE", " ", "Crystal")
    journal = Iyi::DiagnosticReplayJournal.new([comment, space])
    journal.literal_trivia!(0, 3, "Crystal", false)
    expect_raises(ArgumentError, "unwitnessed grammar gap") { journal.literal_trivia!(0, 4, "Crystal", false) }
    expect_raises(ArgumentError, "unwitnessed grammar gap") { journal.literal_trivia!(0, 3, "Iyi", false) }
  end
end
