require "../support/syntax"

# Three literal pieces with identical text, so exchanging two of them is observable.
NUMBER_MACRO_EQUAL_TEXT   = "\n  "
NUMBER_MACRO_EQUAL_PIECES = "macro m\n  {{a}}\n  {{b}}\n  {{c}}\nend\n"

# Positions of the observations whose owners carry the repeated text.
private def number_macro_equal_pieces(macros : Array(Iyi::DiagnosticMacroLiteralObservation)) : Array(Int32)
  positions = macros.each_index.select { |index| macros[index].owner.value == NUMBER_MACRO_EQUAL_TEXT }.to_a
  raise "expected two equal macro pieces" unless positions.size >= 2
  positions
end

NUMBER_MACRO_FULL_BODY = [
  "macro big(a)",
  "  {{a}}",
  "  {% if a %}x{% elsif b %}y{% else %}z{% end %}",
  "  {% unless a %}u{% end %}",
  "  {% for i in [1] %}{{i}}{% end %}",
  "  {% begin %}b{% end %}",
  "  {% verbatim do %}{{v}}{% end %}",
  "  \\{{ x }} \\{% y %} 100\\%",
  "  %var{1}",
  "  %w(text)",
  "  \"\#{x}\"",
  "  # {{x}}",
  "  {% x = 2 %}\\",
  "  same",
  "  same",
  "end",
  "",
].join("\n")

# Binds the source through the public path in one lexical mode, selected by suffix.
private def number_macro_bind(source : String, suffix : String, & : Iyi::DiagnosticBoundCapture ->)
  path = File.tempname("number-macro-binding", suffix)
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

# Binds the source in both lexical modes. Each must bind through bind!.
private def number_macro_accept(source : String)
  [".cr", ".iyi"].each do |suffix|
    number_macro_bind(source, suffix) { |bound| bound.root.should_not be_nil }
  end
end

# Replays the source with observations, as the binder does, and yields the pieces the controls mutate.
private def number_macro_replay(source : String, &)
  path = File.tempname("number-macro-replay", ".cr")
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
    yield root, replay, journal, claim
  ensure
    File.delete(path) if File.file?(path)
  end
end

private def number_macro_numbers(root : Iyi::ASTNode, claim : Iyi::AcceptedCaptureInput,
                                 bundle : Iyi::DiagnosticLiteralReplayAssociations,
                                 numbers : Array(Iyi::DiagnosticNumberObservation),
                                 signed : Array(Iyi::DiagnosticSignedNumberObservation)) : Set(Iyi::DiagnosticCaptureFieldRef)
  Iyi::DiagnosticNumberLiteralBinding.new(claim, bundle, numbers, signed).verify!(root)
end

private def number_macro_macros(root : Iyi::ASTNode, claim : Iyi::AcceptedCaptureInput,
                                bundle : Iyi::DiagnosticLiteralReplayAssociations,
                                macros : Array(Iyi::DiagnosticMacroLiteralObservation)) : Set(Iyi::DiagnosticCaptureFieldRef)
  Iyi::DiagnosticMacroLiteralBinding.new(claim, bundle, macros).verify!(root)
end

private def number_macro_collect(node : Iyi::ASTNode, found : Array(Iyi::ASTNode)) : Array(Iyi::ASTNode)
  found << node
  Iyi::DiagnosticDirectChildFields.each(node) { |_, _, _, child| number_macro_collect(child, found) }
  found
end

private def number_macro_nodes(root : Iyi::ASTNode, type : T.class) : Array(T) forall T
  number_macro_collect(root, [] of Iyi::ASTNode).select(&.is_a?(T)).map { |node| node.as(T) }
end

private def number_macro_ordinal(journal : Iyi::DiagnosticReplayJournal, kind : String) : Int32
  journal.entries.index { |entry| entry.token_kind == kind } || raise "no #{kind} token"
end

private def number_macro_rebuild(journal : Iyi::DiagnosticReplayJournal, & : Iyi::DiagnosticRenderedToken, Int32 -> Iyi::DiagnosticRenderedToken) : Iyi::DiagnosticReplayJournal
  Iyi::DiagnosticReplayJournal.new(journal.entries.map_with_index { |entry, index| yield entry, index })
end

private def number_macro_token(entry : Iyi::DiagnosticRenderedToken, value_base64 : String? = entry.value_base64,
                               number_kind : String? = entry.number_kind,
                               lexical_mode : String = entry.lexical_mode) : Iyi::DiagnosticRenderedToken
  Iyi::DiagnosticRenderedToken.new(entry.input_start, entry.input_end, entry.token_kind, entry.token_text,
    lexical_mode, value_base64: value_base64, delimiter: entry.delimiter,
    passed_backslash_newline: entry.passed_backslash_newline, invalid_escape: entry.invalid_escape,
    line: entry.line, number_kind: number_kind)
end

describe "numeric and macro literal positive binding" do
  it "binds integer kinds and boundary values" do
    ["0", "1", "-1", "+1", "1_000", "2147483648", "-2147483648", "9223372036854775808", "18446744073709551615"].each do |value|
      number_macro_accept("a = #{value}\n")
    end
  end

  it "binds every integer and float suffix" do
    %w(i8 i16 i32 i64 i128 u8 u16 u32 u64 u128).each do |suffix|
      number_macro_accept("a = 1_#{suffix}\n")
    end
    number_macro_accept("a = 1.0_f32\nb = 1.0_f64\n")
  end

  it "binds base forms and the 128-bit extremes" do
    number_macro_accept("a = 0x10\nb = 0b101\nc = 0o17\n")
    number_macro_accept("a = 0xffffffffffffffffffffffffffffffffu128\n")
    number_macro_accept("a = 0x7fffffffffffffff\n")
    number_macro_accept("a = 170141183460469231731687303715884105727i128\n")
    number_macro_accept("a = -170141183460469231731687303715884105728i128\n")
  end

  it "binds floats and scientific notation" do
    number_macro_accept("a = 1e400\nb = 1_000.000_1\nc = 1.5e-3\n")
  end

  it "binds signed number splits as subtraction, addition and multiplication operands" do
    ["x -1", "x +1", "x -0x10", "x -1 * 2", "x -1-1"].each do |tail|
      number_macro_accept("x = 1\n#{tail}\n")
    end
  end

  it "binds equal-valued siblings by occurrence" do
    number_macro_accept("a = [1, 1, 1]\n")
    number_macro_accept("a = {1 => 1}\n")
    number_macro_accept("a = [1.0, 1.00]\n")
  end

  it "binds backreferences with and without a nil query, and a repeated index" do
    number_macro_accept("$0\n")
    number_macro_accept("$1\n")
    number_macro_accept("$2?\n")
    number_macro_accept("$1\n$1\n")
  end

  it "binds __LINE__ twice on one line and as an unobserved default parameter" do
    number_macro_accept("a = [__LINE__, __LINE__]\n")
    number_macro_accept("def f(x = __LINE__)\n  x\nend\n")
  end

  it "binds type arguments and offsetof" do
    number_macro_accept("a = StaticArray(Int32, 8)\n")
    number_macro_accept("a = Int32[4]\n")
    number_macro_accept("a = offsetof(Tuple(Int32, Int32), 1)\n")
  end

  it "binds numbers beside string, percent, heredoc and regex interpolations and folds" do
    number_macro_accept("a = \"x\#{1}\"\n")
    number_macro_accept("a = %W(x\#{1} y)\n")
    number_macro_accept("a = <<-TEXT\n  x\#{1}\n  TEXT\n")
    number_macro_accept("a = /x\#{1}/\n")
    number_macro_accept("a = \"a\#{\"b\"}\"\nb = 2\n")
  end

  it "binds every macro body form in one body" do
    number_macro_accept(NUMBER_MACRO_FULL_BODY)
  end

  it "binds repeated equal text pieces in one macro body" do
    number_macro_accept("macro m\n  {{a}}\n  {{b}}\nend\n")
  end

  it "binds a top-level macro for" do
    number_macro_accept("{% for i in [1, 2] %}{{ i }}{% end %}\n")
  end

  it "binds a macro body containing end! as a do-block end in iyi, and as identifier text in crystal" do
    number_macro_bind("macro m\n  def sum\n    each_item do |i|\n    end!\n    1\n  end\nend\n", ".iyi") do |bound|
      bound.root.to_s.includes?("end!").should be_true
    end
    number_macro_bind("macro m\n  end!\nend\n", ".cr") do |bound|
      bound.root.to_s.includes?("end!").should be_true
    end
  end

  it "refuses a bare end! in an iyi macro body, which closes the macro early" do
    expect_raises(Iyi::SyntaxException, /nothing is open for it to close/) do
      number_macro_bind("macro m\n  end!\nend\n", ".iyi") { |bound| bound.root.should_not be_nil }
    end
  end

  it "binds a macro body whose MacroVar lookahead fails" do
    number_macro_accept("macro m\n  %v x\nend\n")
  end

  it "binds a BOM-prefixed source" do
    number_macro_accept("\uFEFFa = 1\n")
  end
end

describe "numeric and macro literal observation lookahead" do
  it "restores lexer and parser observations after a failed lookahead" do
    parser = Iyi::Parser.new("a = 1\n", nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.enable_diagnostic_observations
    before = parser.diagnostic_lexical_observations.size
    parser.lookahead { parser.parse; false }.should be_false
    parser.diagnostic_lexical_observations.size.should eq before
    parser.diagnostic_number_observations.size.should eq 0
    parser.diagnostic_signed_number_observations.size.should eq 0
    parser.diagnostic_macro_literal_observations.size.should eq 0
  end
end

describe "NumberLiteral binding controls" do
  it "accepts the baseline and rejects forged node values" do
    number_macro_replay("a = 1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations
      signed = replay.diagnostic_signed_number_observations
      number_macro_numbers(root, claim, bundle, numbers, signed).should_not be_empty
      number = number_macro_nodes(root, Iyi::NumberLiteral).first
      number.value = "2"
      expect_raises(ArgumentError, "number literal value differs from scanned token") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
      number.value = "+1"
      expect_raises(ArgumentError, "number literal value differs from scanned token") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
      number.value = "1"
      number.kind = Iyi::NumberKind::I64
      expect_raises(ArgumentError, "number literal kind differs from scanned token") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
    end
  end

  it "rejects a forged float spelling whose value differs only in trailing zeros" do
    number_macro_replay("a = 1.0\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations
      signed = replay.diagnostic_signed_number_observations
      number_macro_nodes(root, Iyi::NumberLiteral).first.value = "1.00"
      expect_raises(ArgumentError, "number literal value differs from scanned token") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
    end
  end

  it "rejects swapped, aliased and replaced equal-valued array elements" do
    number_macro_replay("a = [1, 1]\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations
      signed = replay.diagnostic_signed_number_observations
      number_macro_numbers(root, claim, bundle, numbers, signed).should_not be_empty
      elements = number_macro_nodes(root, Iyi::ArrayLiteral).first.elements
      elements.reverse!
      expect_raises(ArgumentError, "literal replay graph differs") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
      elements.reverse!
      elements[1] = elements[0]
      expect_raises(ArgumentError, "literal replay graph differs") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
      elements[1] = Iyi::NumberLiteral.new("1")
      expect_raises(ArgumentError, "literal replay graph differs") do
        number_macro_numbers(root, claim, bundle, numbers, signed)
      end
    end
  end

  it "rejects a dropped observation as an unbound token" do
    number_macro_replay("a = [1, 1]\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations
      expect_raises(ArgumentError, "unbound number token") do
        number_macro_numbers(root, claim, bundle, numbers[0..0], [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a second observation that reuses the first token" do
    number_macro_replay("a = [1, 1]\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations
      shared = [numbers[0], Iyi::DiagnosticNumberObservation.new(numbers[1].owner, numbers[1].role, numbers[0].token)]
      expect_raises(ArgumentError, "number token consumed twice") do
        number_macro_numbers(root, claim, bundle, shared, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a __LINE__ node whose observation was dropped" do
    number_macro_replay("a = __LINE__\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      expect_raises(ArgumentError, "number literal binding missing") do
        number_macro_numbers(root, claim, bundle, [] of Iyi::DiagnosticNumberObservation, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a journal value and kind removed from the number token" do
    number_macro_replay("a = 1\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "NUMBER")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, value_base64: nil, number_kind: nil) : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "number token lacks a value") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a journal value that differs from the node" do
    number_macro_replay("a = 1\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "NUMBER")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, value_base64: Base64.strict_encode("2".to_slice)) : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "number literal value differs from scanned token") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a journal kind that differs from the node" do
    number_macro_replay("a = 1\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "NUMBER")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, number_kind: "i64") : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "number literal kind differs from scanned token") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a journal token whose mode differs from the input" do
    number_macro_replay("a = 1\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "NUMBER")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, lexical_mode: "Iyi") : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "literal witness is not a scanned token") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a Literal observation that points at a backreference token" do
    number_macro_replay("a = $1 + 1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      backref = Iyi::DiagnosticReplayTokenRef.new(number_macro_ordinal(journal, "GLOBAL_MATCH_DATA_INDEX"))
      numbers = replay.diagnostic_number_observations.map do |item|
        item.role.literal? ? Iyi::DiagnosticNumberObservation.new(item.owner, item.role, backref, item.call) : item
      end
      expect_raises(ArgumentError, "literal witness is not a scanned token") do
        number_macro_numbers(root, claim, bundle, numbers, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a dropped signed-number observation as an unbound token" do
    number_macro_replay("x = 1\nx -1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      expect_raises(ArgumentError, "unbound number token") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a signed call whose operator name differs from the sign" do
    number_macro_replay("x = 1\nx -1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      number_macro_nodes(root, Iyi::Call).find { |call| call.name == "-" }.not_nil!.name = "+"
      expect_raises(ArgumentError, "signed number operator differs") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, replay.diagnostic_signed_number_observations)
      end
    end
  end

  it "rejects a signed operand that is the signed token itself" do
    number_macro_replay("x = 1\nx -1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      signed = replay.diagnostic_signed_number_observations.first
      forged = [Iyi::DiagnosticSignedNumberObservation.new(signed.call, signed.signed, signed.signed)]
      expect_raises(ArgumentError, "signed number operand differs") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, forged)
      end
    end
  end

  it "rejects a backreference whose call name is the nil-query form without a query" do
    number_macro_replay("$1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      number_macro_nodes(root, Iyi::Call).first.name = "[]?"
      expect_raises(ArgumentError, "backreference call differs") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a backreference observation with no call" do
    number_macro_replay("$1\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      numbers = replay.diagnostic_number_observations.map do |item|
        Iyi::DiagnosticNumberObservation.new(item.owner, item.role, item.token, nil)
      end
      expect_raises(ArgumentError, "backreference call association missing") do
        number_macro_numbers(root, claim, bundle, numbers, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects a __LINE__ journal value that differs from the node" do
    number_macro_replay("a = __LINE__\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "__LINE__")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, value_base64: Base64.strict_encode("99".to_slice)) : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "number literal value differs from scanned token") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end

  it "rejects an offset whose journal kind is not i32" do
    number_macro_replay("a = offsetof(Tuple(Int32, Int32), 1)\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "NUMBER")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, number_kind: "i64") : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "offset number kind differs") do
        number_macro_numbers(root, claim, bundle, replay.diagnostic_number_observations, [] of Iyi::DiagnosticSignedNumberObservation)
      end
    end
  end
end

describe "MacroLiteral binding controls" do
  it "accepts the baseline and rejects a forged node value" do
    number_macro_replay("macro m\n  hello\nend\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      macros = replay.diagnostic_macro_literal_observations
      number_macro_macros(root, claim, bundle, macros).should_not be_empty
      number_macro_nodes(root, Iyi::MacroLiteral).first.value = "forged"
      expect_raises(ArgumentError, "macro literal value differs from scanned token") do
        number_macro_macros(root, claim, bundle, macros)
      end
    end
  end

  it "rejects a forged journal and node value whose source bytes do not match" do
    number_macro_replay("macro m\n  hello\nend\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "MACRO_LITERAL")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, value_base64: Base64.strict_encode("forged".to_slice)) : entry
      end
      number_macro_nodes(root, Iyi::MacroLiteral).first.value = "forged"
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "macro literal value differs from its source bytes") do
        number_macro_macros(root, claim, bundle, replay.diagnostic_macro_literal_observations)
      end
    end
  end

  it "rejects a dropped macro literal observation as an unbound token" do
    number_macro_replay("macro m\n  hello\nend\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      expect_raises(ArgumentError, "unbound macro literal token") do
        number_macro_macros(root, claim, bundle, [] of Iyi::DiagnosticMacroLiteralObservation)
      end
    end
  end

  it "rejects a second equal piece that reuses the first piece's token" do
    number_macro_replay(NUMBER_MACRO_EQUAL_PIECES) do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      macros = replay.diagnostic_macro_literal_observations
      equal = number_macro_equal_pieces(macros)
      shared = macros.dup
      shared[equal[1]] = Iyi::DiagnosticMacroLiteralObservation.new(macros[equal[1]].owner, macros[equal[0]].token)
      expect_raises(ArgumentError, "macro literal token consumed twice") do
        number_macro_macros(root, claim, bundle, shared)
      end
    end
  end

  it "rejects swapped equal pieces as a changed replay graph" do
    number_macro_replay(NUMBER_MACRO_EQUAL_PIECES) do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      macros = replay.diagnostic_macro_literal_observations
      body = number_macro_nodes(root, Iyi::Expressions).find { |node| node.expressions.count(&.is_a?(Iyi::MacroLiteral)) >= 2 }.not_nil!
      positions = body.expressions.each_index.select { |index| body.expressions[index].is_a?(Iyi::MacroLiteral) && body.expressions[index].as(Iyi::MacroLiteral).value == NUMBER_MACRO_EQUAL_TEXT }.to_a
      body.expressions[positions[0]], body.expressions[positions[1]] = body.expressions[positions[1]], body.expressions[positions[0]]
      expect_raises(ArgumentError, "literal replay graph differs") do
        number_macro_macros(root, claim, bundle, macros)
      end
    end
  end

  it "rejects exchanged token refs as a changed macro order" do
    number_macro_replay(NUMBER_MACRO_EQUAL_PIECES) do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      macros = replay.diagnostic_macro_literal_observations
      equal = number_macro_equal_pieces(macros)
      first = equal[0]
      second = equal[1]
      swapped = macros.dup
      swapped[first] = Iyi::DiagnosticMacroLiteralObservation.new(macros[first].owner, macros[second].token)
      swapped[second] = Iyi::DiagnosticMacroLiteralObservation.new(macros[second].owner, macros[first].token)
      expect_raises(ArgumentError, "macro literal order differs from scanned tokens") do
        number_macro_macros(root, claim, bundle, swapped)
      end
    end
  end

  it "rejects a journal token with no value" do
    number_macro_replay("macro m\n  hello\nend\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "MACRO_LITERAL")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, value_base64: nil) : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "macro literal token lacks a value") do
        number_macro_macros(root, claim, bundle, replay.diagnostic_macro_literal_observations)
      end
    end
  end

  it "rejects a journal token whose mode differs from the input" do
    number_macro_replay("macro m\n  hello\nend\n") do |root, replay, journal, claim|
      ordinal = number_macro_ordinal(journal, "MACRO_LITERAL")
      damaged = number_macro_rebuild(journal) do |entry, index|
        index == ordinal ? number_macro_token(entry, lexical_mode: "Iyi") : entry
      end
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, damaged, replay, root)
      expect_raises(ArgumentError, "literal witness is not a scanned token") do
        number_macro_macros(root, claim, bundle, replay.diagnostic_macro_literal_observations)
      end
    end
  end

  it "rejects an escaped brace whose node value includes its backslash" do
    number_macro_replay("macro m\n  \\{{ x }}\nend\n") do |root, replay, journal, claim|
      bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
      macros = replay.diagnostic_macro_literal_observations
      number_macro_macros(root, claim, bundle, macros).should_not be_empty
      number_macro_nodes(root, Iyi::MacroLiteral).find { |node| node.value.starts_with?("{") }.not_nil!.value = "\\{"
      expect_raises(ArgumentError, "macro literal value differs from scanned token") do
        number_macro_macros(root, claim, bundle, macros)
      end
    end
  end
end
