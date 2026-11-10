require "../support/syntax"

# Literal and named-entry emission contract (LiteralReplayPlan §3.7 and S5 acceptance
# (a) to (d)). Plain bytes never change. Claims mode attributes literal bytes to
# LiteralValue and structural syntax to StructuredSyntax, and every record is disjoint
# from the claims. Fragment mode writes a bare name with a QuotedName anchor when its
# source was a quoted literal, and the regions reparse restores it.
#
# Not run by the slice author: the integrator runs this file after the slices land.

# Witness spans of every literal in a parsed tree, read from the replay evidence the
# parser records on each node. Each span carries whether a claim may cover it: only an
# Opener of a regex, a command or an interpolated string. Those three are the openers
# that carry a Direct claim (`Literal/regex`, `Call/method`, `Literal/interpolation`).
private class LiteralWitnessWalk < Iyi::Visitor
  getter spans = [] of {Int32, Int32, Bool}

  def visit_any(node)
    claim_may_cover = node.is_a?(Iyi::RegexLiteral) || node.is_a?(Iyi::StringInterpolation) ||
                      (node.is_a?(Iyi::Call) && node.name == "`")
    node.diagnostic_literal_productions.each_value do |segments|
      segments.each do |segment|
        segment.witnesses.each do |witness|
          @spans << {witness.start_offset, witness.end_offset, claim_may_cover && witness.kind.opener?}
        end
      end
    end
    true
  end
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

# Every form, as a def body. Crystal syntax, written as lines so each form is explicit.
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
    %q(  asm("nop" : : "r"(d) : "volatile")),
    "end",
    "",
  ].join("\n")
end

# Witness spans of a restored or expanded tree.
private def literal_emission_witness_spans(node : Iyi::ASTNode) : Array({Int32, Int32, Bool})
  walk = LiteralWitnessWalk.new
  node.accept walk
  walk.spans
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

# Every byte of every literal witness token is covered by generated text, or by the
# claim that covers an opener (§5(b)). The witness spans are offsets in `text`.
private def literal_emission_check_witnesses(text : String, generated : Array(Iyi::DiagnosticGeneratedText),
                                             claims : Array(Iyi::DiagnosticMacroClaim),
                                             spans : Array({Int32, Int32, Bool}))
  covered = Array(Bool).new(text.bytesize, false)
  generated.each do |item|
    (item.start_offset...item.end_offset).each { |index| covered[index] = true }
  end
  claimed = Array(Bool).new(text.bytesize, false)
  claims.each do |claim|
    (claim.key.writer.start_offset...claim.key.writer.end_offset).each { |index| claimed[index] = true }
  end
  spans.each do |start_offset, end_offset, claim_may_cover|
    (start_offset...end_offset).each do |index|
      next if covered[index]
      next if claim_may_cover && claimed[index]
      raise "literal witness byte #{index} is not covered by generated text"
    end
  end
end

# Covered by generated text, byte for byte (used for asm, whose witnesses are not reachable).
private def literal_emission_covers?(text : String, generated : Array(Iyi::DiagnosticGeneratedText), literal : String) : Bool
  start = text.byte_index(literal).not_nil!
  (start...start + literal.bytesize).all? do |index|
    generated.any? { |item| item.start_offset <= index && index < item.end_offset }
  end
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
  text, pragmas = program.expand_macro(macro_node.body, program, program)
  emissions = (pragmas || {} of Int32 => Array(Iyi::Lexer::LocPragma)).values.flatten.compact_map(&.as?(Iyi::Lexer::LocDiagnosticEmission))
  invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 1, "Call", "method")
  parser = Iyi::Parser.new(text)
  parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", pragmas)
  expanded = parser.parse
  parser.diagnostic_check_consumed
  {text, emissions, expanded}
end

# One macro per form, so each splice is a single literal. The last is verbatim template text.
private def literal_emission_splice_forms : Hash(String, String)
  {
    "string"          => %(macro literal_form\n  {{ "a\\"b" }}\nend\n),
    "symbol"          => %(macro literal_form\n  {{ :"x y" }}\nend\n),
    "char"            => %(macro literal_form\n  {{ 'c' }}\nend\n),
    "regex"           => %(macro literal_form\n  {{ /a\\/b/i }}\nend\n),
    "percent regex"   => %(macro literal_form\n  {{ %r() }}\nend\n),
    "command"         => %(macro literal_form\n  {{ `ls` }}\nend\n),
    "interpolation"   => %(macro literal_form\n  {{ "e\#{1}f" }}\nend\n),
    "heredoc argument" => %(macro literal_form\n  {{ <<-EOS }}\n  a\n  EOS\nend\n),
    "verbatim text"   => %(macro literal_form\n  x = "v"\n  y = :w\n  z = 'c'\nend\n),
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
    node = literal_emission_parse(%(asm("nop" : : "r"(x) : "volatile")), "/spec/emit/asm.iyi")
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

  it "restores a quoted named-tuple key as a QuotedName through the regions reparse" do
    node = literal_emission_parse(%({"a": 1}), "/spec/emit/quoted_tuple.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should eq("{a: 1}")
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    tuple = restored.parse.as(Iyi::NamedTupleLiteral)
    restored.diagnostic_check_consumed
    origin = tuple.diagnostic_name_slots[Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::NamedEntry, 0)]?
      .try(&.first?).try(&.artifact_origin)
    origin.should be_a(Iyi::DiagnosticOrigin::DerivedName)
    origin.as(Iyi::DiagnosticOrigin::DerivedName).derivation_kind.should eq("QuotedName")
  end

  it "restores a quoted parameter external name as a QuotedName through the regions reparse" do
    node = literal_emission_parse(%(def f("e" x)\nend\n), "/spec/emit/quoted_arg.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should contain("e x")
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    def_node = restored.parse.as(Iyi::Def)
    restored.diagnostic_check_consumed
    origin = def_node.args.first.diagnostic_name_slots[Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::ExternalName)]?
      .try(&.first?).try(&.artifact_origin)
    origin.should be_a(Iyi::DiagnosticOrigin::DerivedName)
    origin.as(Iyi::DiagnosticOrigin::DerivedName).derivation_kind.should eq("QuotedName")
  end

  it "restores a fun real name taken from a quoted literal as a QuotedName through the regions reparse" do
    node = literal_emission_parse(%(lib LibC\n  fun f = "c" : Void\nend\n), "/spec/emit/fun_real.iyi")
    text, fragment = literal_emission_fragment(node)
    text.should contain("fun f = c")
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    lib_def = restored.parse.as(Iyi::LibDef)
    restored.diagnostic_check_consumed
    body = lib_def.body
    fun_def = (body.is_a?(Iyi::Expressions) ? body.expressions.first : body).as(Iyi::FunDef)
    origin = fun_def.diagnostic_name_slots[Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::ExternalName)]?
      .try(&.first?).try(&.artifact_origin)
    origin.should be_a(Iyi::DiagnosticOrigin::DerivedName)
    origin.as(Iyi::DiagnosticOrigin::DerivedName).derivation_kind.should eq("QuotedName")
  end
end

describe "literal emission through macro splices" do
  literal_emission_splice_forms.each do |form, source|
    it "reparses a #{form} splice with byte identity, disjoint records and every witness covered" do
      text, emissions, expanded = literal_emission_splice(source)
      expanded.to_s.strip.should eq(text.strip)
      generated = emissions.flat_map(&.generated_text)
      claims = emissions.flat_map(&.claims)
      spans = literal_emission_witness_spans(expanded)
      spans.should_not be_empty
      literal_emission_check_disjoint(generated, claims)
      literal_emission_check_witnesses(text, generated, claims, spans)
    end
  end
end
