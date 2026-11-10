require "../support/syntax"

# Literal and named-entry emission contract (LiteralReplayPlan §3.7 and S5 acceptance
# (a) to (d)). Plain bytes never change. Claims mode attributes literal bytes to
# LiteralValue and structural syntax to StructuredSyntax, and every record is disjoint
# from the claims. Fragment mode writes a bare name with a QuotedName anchor when its
# source was a quoted literal, and the regions reparse must keep that derivation.
#
# Not run by the slice author. Prerequisites that are not yet landed are named where
# they bite, and the examples are left active rather than weakened.

# Every literal witness in a parsed tree, with the pinned claim identity an opener may
# be covered by. An opener is covered by a claim only in these three shapes, each an
# exact Direct claim whose writer is the witness span (plan §3.6 (A), shared contract
# addition for interpolated strings):
#   - the value of a RegexLiteral: (Literal, regex)
#   - the first argument of a command Call named "`": (Call, method)
#   - a StringInterpolation that is not all-literal: (Literal, interpolation)
# An all-literal interpolation has no claim. Its opener is generated text.
private class LiteralWitnessWalk < Iyi::Visitor
  getter nodes = [] of Iyi::ASTNode

  def visit_any(node)
    @nodes << node
    true
  end
end

private def literal_emission_literal_only?(node : Iyi::StringInterpolation) : Bool
  node.expressions.all? { |exp| exp.is_a?(Iyi::StringLiteral) }
end

private def literal_emission_witnesses(root : Iyi::ASTNode) : Array({Int32, Int32, {String, String}?})
  walk = LiteralWitnessWalk.new
  root.accept walk
  pins = {} of UInt64 => {String, String}
  walk.nodes.each do |node|
    case node
    when Iyi::RegexLiteral
      pins[node.value.object_id] = {"Literal", "regex"}
    when Iyi::Call
      if node.name == "`" && (literal = node.args.first?)
        pins[literal.object_id] = {"Call", "method"}
      end
    end
  end
  walk.nodes.each do |node|
    next unless node.is_a?(Iyi::StringInterpolation)
    next if pins.has_key?(node.object_id) || literal_emission_literal_only?(node)
    pins[node.object_id] = {"Literal", "interpolation"}
  end
  witnesses = [] of {Int32, Int32, {String, String}?}
  walk.nodes.each do |node|
    pin = pins[node.object_id]?
    node.diagnostic_literal_productions.each_value do |segments|
      segments.each do |segment|
        segment.witnesses.each do |witness|
          opener_pin = witness.kind.opener? ? pin : nil
          witnesses << {witness.start_offset, witness.end_offset, opener_pin}
        end
      end
    end
  end
  witnesses
end

private def literal_emission_parse(source : String, filename : String) : Iyi::ASTNode
  parser = Iyi::Parser.new(source)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  parser.parse
end

private def literal_emission_claims(node : Iyi::ASTNode) : {String, Array(Iyi::DiagnosticGeneratedText), Array(Iyi::DiagnosticMacroClaim)}
  io = IO::Memory.new
  generated = [] of Iyi::DiagnosticGeneratedText
  claims = [] of Iyi::DiagnosticMacroClaim
  names = [] of Iyi::DiagnosticMacroNameFragment
  node.to_s(io, diagnostic_claims: claims, diagnostic_generated_text: generated, diagnostic_name_fragments: names)
  {io.to_s, generated, claims}
end

private def literal_emission_fragment(node : Iyi::ASTNode)
  io = IO::Memory.new
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  node.to_s(io, diagnostic_fragment: builder)
  text = io.to_s
  {text, builder.finish("fixture", text)}
end

# Every form, as a def body.
private def literal_emission_def_source : String
  [
    "def literal_forms",
    %q(  a = "a\"b"),
    "  b = :sym",
    %q(  c = :"x y"),
    "  d = 'c'",
    %q(  e = /a\/b/i),
    %q(  f = %r()),
    "  g = `ls`",
    %q(  h = "e#{1}f"),
    "  i = <<-EOS",
    "    body",
    "    EOS",
    %q(  asm("nop" : : "r"(d) : : "volatile")),
    "end",
    "",
  ].join("\n")
end

# Records and claims must not overlap (§5(b)).
private def literal_emission_check_disjoint(generated : Array(Iyi::DiagnosticGeneratedText),
                                            claims : Array(Iyi::DiagnosticMacroClaim))
  ranges = generated.map { |item| {item.start_offset, item.end_offset} }
  claims.each { |claim| ranges << {claim.key.writer.start_offset, claim.key.writer.end_offset} }
  ranges.sort_by! { |range| range[0] }
  ranges.each_cons_pair do |first, second|
    raise "literal records overlap at byte #{second[0]}" if first[1] > second[0]
  end
end

# Every byte of every literal witness is covered by generated text, or, for a pinned
# opener only, by a Direct claim whose writer is exactly that witness and whose key
# matches the pin (§5(b)). Offsets are in the expansion text.
private def literal_emission_check_witnesses(generated : Array(Iyi::DiagnosticGeneratedText),
                                             claims : Array(Iyi::DiagnosticMacroClaim),
                                             witnesses : Array({Int32, Int32, {String, String}?}))
  witnesses.each do |start_offset, end_offset, pin|
    if pin
      exact = claims.any? do |claim|
        claim.attachment.is_a?(Iyi::DiagnosticMacroAttachment::Direct) &&
          claim.key.kind == pin[0] && claim.key.role == pin[1] &&
          claim.key.writer.start_offset == start_offset && claim.key.writer.end_offset == end_offset
      end
      next if exact
    end
    (start_offset...end_offset).each do |index|
      next if generated.any? { |item| item.start_offset <= index && index < item.end_offset }
      raise "literal witness byte #{index} (#{start_offset}...#{end_offset}) is not covered by generated text or its pinned claim"
    end
  end
end

# Literal bytes covered by generated text, byte for byte. Independent of parser
# witnesses, so it holds for every form the printer attributes.
private def literal_emission_covers?(text : String, generated : Array(Iyi::DiagnosticGeneratedText), literal : String) : Bool
  start = text.byte_index(literal).not_nil!
  (start...start + literal.bytesize).all? do |index|
    generated.any? { |item| item.start_offset <= index && index < item.end_offset }
  end
end

# The restored derivation must survive the regions reparse in its name slot, as the
# existing provenance model holds it (DiagnosticNameValue::Derived). Its origin must
# equal the one the printer emitted, so source linkage (input sha, bytesize, lexical
# mode, literal span, rendered text) reaches the cross-leg resolution.
private def literal_emission_restored_derivation(node : Iyi::ASTNode, slot : Iyi::DiagnosticNameSlot,
                                                 expected : Iyi::DiagnosticOrigin)
  values = node.diagnostic_name_slots[slot]?
  raise "restored QuotedName slot is missing" unless values
  values.size.should eq(1)
  value = values.first
  value.should be_a(Iyi::DiagnosticNameValue::Derived)
  origin = value.artifact_origin
  origin.should be_a(Iyi::DiagnosticOrigin::DerivedName)
  origin.as(Iyi::DiagnosticOrigin::DerivedName).derivation_kind.should eq("QuotedName")
  origin.to_json.should eq(expected.to_json)
  origin.should eq(expected)
end

# Real macro expansion, then the expansion reparse with its records, as the parser
# receives them in a macro splice. The reparse must consume every claim.
private def literal_emission_splice(macro_source : String)
  macro_parser = Iyi::Parser.new(macro_source)
  macro_parser.filename = "/src/macros/literal.cr"
  macro_parser.diagnostic_source_file = "/src/macros/literal.cr"
  macro_parser.diagnostic_capture = true
  macro_node = macro_parser.parse.as(Iyi::Macro)
  definition = macro_node.diagnostic_origin.not_nil!
  program = Iyi::Program.new
  program.diagnostic_capture = true
  if macro_node.args.empty?
    text, pragmas = program.expand_macro(macro_node.body, program, program)
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 1, "Call", "method")
  else
    call = literal_emission_parse("literal_form(`ls`)", "/src/main.cr").as(Iyi::Call)
    command = call.args.first.as(Iyi::Call)
    command.name.should eq("`")
    text, pragmas = program.expand_macro(macro_node, call, program, program)
    invocation = call.diagnostic_origin.not_nil!
  end
  emissions = (pragmas || {} of Int32 => Array(Iyi::Lexer::LocPragma)).values.flatten.compact_map(&.as?(Iyi::Lexer::LocDiagnosticEmission))
  parser = Iyi::Parser.new(text)
  parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", pragmas)
  expanded = parser.parse
  parser.diagnostic_check_consumed
  {text, emissions, expanded}
end

# One macro per form, so each splice is a single literal. `snippet` is the literal's
# printed bytes that generated text must cover ("" when there is none to check).
private def literal_emission_splice_forms : Hash(String, {String, String})
  {
    "string"           => {%(macro literal_form\n  {{ "a\\"b" }}\nend\n), %("a\\"b")},
    "symbol"           => {%(macro literal_form\n  {{ :"x y" }}\nend\n), %(:"x y")},
    "char"             => {%(macro literal_form\n  {{ 'c' }}\nend\n), %('c')},
    "regex"            => {%(macro literal_form\n  {{ /a\\/b/i }}\nend\n), %(a\\/b)},
    "percent regex"    => {%(macro literal_form\n  {{ %r() }}\nend\n), ""},
    "command"          => {%(macro literal_form(value)\n  {{ value }}\nend\n), "ls"},
    "interpolation"    => {%(macro literal_form\n  {{ "e\#{1}f" }}\nend\n), "e"},
    "heredoc argument" => {"macro literal_form\n  {{ <<-EOS\n  a\n  EOS\n  }}\nend\n", %("a\\n")},
    "verbatim text"    => {"macro literal_form\nx = \"v\"\ny = :w\nz = 'c'\nend\n", %(x = "v")},
  }
end

describe "literal emission in plain mode" do
  it "prints literal forms with unchanged bytes" do
    [
      %("ab"), %("a\\"b"), %(:sym), %(:"x y"), %('c'), %(/a\\/b/i), %(%r()), %(`ls`), %("a\#{1}b"),
    ].each do |source|
      literal_emission_parse(source, "/spec/emit/plain.iyi").to_s.should eq(source)
    end
  end
end

describe "literal emission in claims mode" do
  it "attributes a string literal's printed bytes, quotes included, to LiteralValue" do
    text, generated, claims = literal_emission_claims(Iyi::StringLiteral.new("a\"b"))
    text.should eq("\"a\\\"b\"")
    generated.should eq([Iyi::DiagnosticGeneratedText.new(0, text.bytesize, nil, Iyi::DiagnosticMacroProducer::LiteralValue)])
    claims.should be_empty
  end

  it "attributes symbol and char bytes, quotes included, to LiteralValue" do
    _, symbol_generated, _ = literal_emission_claims(Iyi::SymbolLiteral.new("x y"))
    symbol_generated.should eq([Iyi::DiagnosticGeneratedText.new(0, 6, nil, Iyi::DiagnosticMacroProducer::LiteralValue)])
    _, char_generated, _ = literal_emission_claims(Iyi::CharLiteral.new('c'))
    char_generated.should eq([Iyi::DiagnosticGeneratedText.new(0, 3, nil, Iyi::DiagnosticMacroProducer::LiteralValue)])
  end

  it "prints an all-literal interpolation as one StringLiteral with no interpolation claim" do
    node = Iyi::StringInterpolation.new([Iyi::StringLiteral.new("a"), Iyi::StringLiteral.new("b")] of Iyi::ASTNode)
    text, generated, claims = literal_emission_claims(node)
    text.should eq("\"ab\"")
    generated.should eq([Iyi::DiagnosticGeneratedText.new(0, 4, nil, Iyi::DiagnosticMacroProducer::LiteralValue)])
    claims.should be_empty
  end

  it "records interpolation delimiters as StructuredSyntax and literal runs as LiteralValue" do
    node = Iyi::StringInterpolation.new([Iyi::StringLiteral.new("a"), Iyi::BoolLiteral.new(true)] of Iyi::ASTNode)
    node.diagnostic_macro_lineage = Iyi::DiagnosticMacroLineage::Constructed
    text, generated, _ = literal_emission_claims(node)
    text.should eq("\"a\#{true}\"")
    generated.should eq([
      Iyi::DiagnosticGeneratedText.new(1, 2, nil, Iyi::DiagnosticMacroProducer::LiteralValue),
      Iyi::DiagnosticGeneratedText.new(2, 4, nil, Iyi::DiagnosticMacroProducer::StructuredSyntax),
      Iyi::DiagnosticGeneratedText.new(8, 9, nil, Iyi::DiagnosticMacroProducer::StructuredSyntax),
      Iyi::DiagnosticGeneratedText.new(9, 10, nil, Iyi::DiagnosticMacroProducer::StructuredSyntax),
    ])
  end

  it "records macro verbatim text as MacroVerbatim" do
    _, generated, _ = literal_emission_claims(Iyi::MacroLiteral.new("abc"))
    generated.should eq([Iyi::DiagnosticGeneratedText.new(0, 3, nil, Iyi::DiagnosticMacroProducer::MacroVerbatim)])
  end

  it "attributes asm text, constraint and options to LiteralValue, byte for byte" do
    node = literal_emission_parse(%(asm("nop" : : "r"(x) : : "volatile")), "/spec/emit/asm.iyi")
    text, generated, claims = literal_emission_claims(node)
    text.should eq(node.to_s)
    literal_emission_covers?(text, generated, %("nop")).should be_true
    literal_emission_covers?(text, generated, %("r")).should be_true
    literal_emission_covers?(text, generated, %("volatile")).should be_true
    literal_emission_check_disjoint(generated, claims)
  end
end

describe "literal emission in fragment mode" do
  it "keeps bytes identical across plain, claims and fragment printing" do
    node = literal_emission_parse(literal_emission_def_source, "/spec/emit/def.iyi")
    plain = node.to_s
    claims_text, generated, claims = literal_emission_claims(node)
    fragment_text, _ = literal_emission_fragment(node)
    claims_text.should eq(plain)
    fragment_text.should eq(plain)
    literal_emission_check_disjoint(generated, claims)
  end

  it "captures every literal form in both modes and restores it through the regions reparse" do
    node = literal_emission_parse(literal_emission_def_source, "/spec/emit/def_capture.iyi")
    text = node.to_s
    captures = Iyi::DiagnosticModeCaptures.capture(text, [] of Iyi::SourcePosition) do |mode|
      io = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new(mode)
      node.to_s(io, diagnostic_fragment: builder)
      {io.to_s, [] of Iyi::SourcePosition, builder}
    end
    captures.crystal.should be_a(Iyi::DiagnosticModeCaptureResult::Success)
    captures.iyi.should be_a(Iyi::DiagnosticModeCaptureResult::Success)
    fragment = captures.fragment("literal_forms", "Crystal")
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    restored_node = restored.parse
    restored.diagnostic_check_consumed
    restored_node.to_s.should eq(text)
  end

  it "restores a quoted named-tuple key's QuotedName derivation through the regions reparse" do
    node = literal_emission_parse(%({"a": 1}), "/spec/emit/quoted_tuple.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should eq("{a: 1}")
    expected = fragment.anchors.find { |anchor| anchor.kind == "Name" && anchor.role == "named_entry" }.not_nil!.origin
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    tuple = restored.parse.as(Iyi::NamedTupleLiteral)
    restored.diagnostic_check_consumed
    literal_emission_restored_derivation(tuple, Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::NamedEntry, 0), expected)
    tuple.to_s.should eq(text)
  end

  it "restores a quoted parameter external name's QuotedName derivation through the regions reparse" do
    node = literal_emission_parse(%(def f("e" x)\nend\n), "/spec/emit/quoted_arg.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should contain("e x")
    expected = fragment.anchors.find { |anchor| anchor.origin.is_a?(Iyi::DiagnosticOrigin::DerivedName) }.not_nil!.origin
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    def_node = restored.parse.as(Iyi::Def)
    restored.diagnostic_check_consumed
    literal_emission_restored_derivation(def_node.args.first, Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::ExternalName), expected)
    def_node.to_s.should eq(text)
  end

  it "restores a fun real name taken from a quoted literal through the regions reparse" do
    node = literal_emission_parse(%(lib LibC\n  fun f = "c" : Void\nend\n), "/spec/emit/fun_real.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should contain("fun f = c")
    expected = fragment.anchors.find { |anchor| anchor.role == "method_name" && anchor.origin.is_a?(Iyi::DiagnosticOrigin::DerivedName) }.not_nil!.origin
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    lib_def = restored.parse.as(Iyi::LibDef)
    restored.diagnostic_check_consumed
    body = lib_def.body
    fun_def = (body.is_a?(Iyi::Expressions) ? body.expressions.first : body).as(Iyi::FunDef)
    literal_emission_restored_derivation(fun_def, Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::ExternalName), expected)
    lib_def.to_s.should eq(text)
  end
end

describe "literal emission through macro splices" do
  literal_emission_splice_forms.each do |form, (source, snippet)|
    it "reparses a #{form} splice with byte identity, disjoint records and literal bytes covered" do
      text, emissions, expanded = literal_emission_splice(source)
      expanded.to_s.strip.should eq(text.strip)
      generated = emissions.flat_map(&.generated_text)
      claims = emissions.flat_map(&.claims)
      if form == "command"
        expanded.as(Iyi::Call).name.should eq("`")
        opener = text.byte_index('`').not_nil!
        claims.any? do |claim|
          claim.key.kind == "Call" && claim.key.role == "method" &&
            claim.key.writer.start_offset == opener && claim.key.writer.end_offset == opener + 1 &&
            claim.attachment.is_a?(Iyi::DiagnosticMacroAttachment::Direct)
        end.should be_true
      end
      literal_emission_check_disjoint(generated, claims)
      literal_emission_covers?(text, generated, snippet).should be_true unless snippet.empty?
    end

    it "covers every #{form} splice witness byte through generated text or its pinned claim" do
      text, emissions, expanded = literal_emission_splice(source)
      generated = emissions.flat_map(&.generated_text)
      claims = emissions.flat_map(&.claims)
      witnesses = literal_emission_witnesses(expanded)
      witnesses.should_not be_empty
      literal_emission_check_witnesses(generated, claims, witnesses)
    end
  end
end
