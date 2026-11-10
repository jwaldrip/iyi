require "../spec_helper"
require "./spec_helper"

# Operator and structural names (derived-name tags 7 and 8) through the diagnostic table codec. Every supported
# production round-trips with equal JSON, equal origins and a byte-identical rewrite. Interning emits the anchor and
# every witness dependency before the derivation. Malformed bytes are refused by the layer that owns the check.
#
# Byte layout of a derivation that is the second table entry (its anchor is entry 0), with d the digest index:
#   d-11 origin tag (4)      d-10 derivation tag (7 or 8)   d-9 production
#   d-8..d-5 anchor index    d-4..d-1 digest length prefix  d    digest text

DERIVED_NAMES_DIGEST = "d" * 64

private def derived_names_written(offset : Int32, kind : String = "Call", role : String = "method") : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::Written.new("derived", "derived.cr", offset, kind, role)
end

private def derived_names_witness(start : Int32, raw : String, kind : String = raw,
                                  selection : Iyi::DiagnosticTokenSelection = Iyi::DiagnosticTokenSelection::Whole,
                                  event : Iyi::DiagnosticTokenEvent? = nil) : Iyi::DiagnosticOperatorWitness
  Iyi::DiagnosticOperatorWitness.new(start, start + raw.bytesize, kind, raw, selection, event)
end

private def derived_names_part(start : Int32, finish : Int32,
                               producer : Iyi::DiagnosticMacroProducer = Iyi::DiagnosticMacroProducer::MacroTemplate) : Iyi::DiagnosticEmissionPart
  Iyi::DiagnosticEmissionPart::Generated.new(start, finish, nil, producer).as(Iyi::DiagnosticEmissionPart)
end

# A name fragment spliced from a CONST source token (a valid path segment in Crystal mode).
private def derived_names_name_part(start : Int32, text : String) : Iyi::DiagnosticEmissionPart
  origin = Iyi::DiagnosticOrigin::Written.new("derived", "derived.cr", 0, "Name", "path_segment")
  token = Iyi::DiagnosticSourceNameToken.new(origin, nil, "path_segment", DERIVED_NAMES_DIGEST, text.bytesize,
    0, text.bytesize, "Crystal", "CONST", text)
  Iyi::DiagnosticEmissionPart::NameSplice.new(start, start + text.bytesize, nil,
    Iyi::DiagnosticNameValue::Observed.new(token)).as(Iyi::DiagnosticEmissionPart)
end

private def derived_names_event(start : Int32, raw : String, kind : String = raw,
                                selection : Iyi::DiagnosticTokenSelection = Iyi::DiagnosticTokenSelection::Whole,
                                producer : Iyi::DiagnosticMacroProducer = Iyi::DiagnosticMacroProducer::MacroTemplate) : Iyi::DiagnosticTokenEvent
  finish = selection.whole? ? start + raw.bytesize : start + 1
  Iyi::DiagnosticTokenEvent.new(start, start + raw.bytesize, kind, raw, "Crystal", selection,
    [derived_names_part(start, finish, producer)] of Iyi::DiagnosticEmissionPart)
end

# The FunDef keyword as an expansion anchor: an IDENT token with text `fun`.
private def derived_names_keyword(start : Int32) : Iyi::DiagnosticTokenEvent
  Iyi::DiagnosticTokenEvent.new(start, start + 3, "IDENT", "fun", "Crystal", Iyi::DiagnosticTokenSelection::Whole,
    [derived_names_part(start, start + 3)] of Iyi::DiagnosticEmissionPart)
end

private def derived_names_expanded(event : Iyi::DiagnosticTokenEvent, kind : String = "Call",
                                   role : String = "method") : Iyi::DiagnosticOrigin
  invocation = derived_names_written(0)
  macro_origin = Iyi::DiagnosticOrigin::Written.new("derived", "derived.cr", 0, "Macro", "keyword")
  Iyi::DiagnosticOrigin::Expanded.new(invocation, macro_origin, "sha256:#{DERIVED_NAMES_DIGEST}", kind, role, nil, event,
    Iyi::DiagnosticAnchorUse::Direct.new)
end

private def derived_names_operator(production : Iyi::DiagnosticOperatorProduction, anchor : Iyi::DiagnosticOrigin,
                                   witnesses : Array(Iyi::DiagnosticOperatorWitness),
                                   input_bytesize : Int32 = 16) : Iyi::DiagnosticOrigin::DerivedName
  Iyi::DiagnosticOrigin::DerivedName.operator_name(production, anchor, DERIVED_NAMES_DIGEST, input_bytesize,
    "Crystal", witnesses)
end

private def derived_names_structural(production : Iyi::DiagnosticStructuralProduction, anchor : Iyi::DiagnosticOrigin,
                                     witnesses : Array(Iyi::DiagnosticOperatorWitness), input_bytesize : Int32,
                                     fresh_index : Int32? = nil) : Iyi::DiagnosticOrigin::DerivedName
  Iyi::DiagnosticOrigin::DerivedName.structural_name(production, anchor, DERIVED_NAMES_DIGEST, input_bytesize,
    "Crystal", witnesses, fresh_index)
end

private def derived_names_bytes(origin : Iyi::DiagnosticOrigin) : {Bytes, UInt32}
  table = Iyi::IyiMod::DiagnosticOrigins.new
  index = table.intern(origin)
  io = IO::Memory.new
  table.write(io)
  {io.to_slice.dup, index}
end

private def derived_names_read(bytes : Bytes) : Iyi::IyiMod::DiagnosticOrigins
  Iyi::IyiMod::DiagnosticOrigins.read(IO::Memory.new(bytes))
end

private def derived_names_position(bytes : Bytes, needle : Bytes) : Int32
  (0..bytes.size - needle.size).each do |start|
    return start if bytes[start, needle.size] == needle
  end
  raise "needle absent from the encoded table"
end

private def derived_names_set_u32(bytes : Bytes, at : Int32, value : UInt32) : Nil
  4.times { |offset| bytes[at + offset] = ((value >> (8 * offset)) & 0xFF).to_u8 }
end

# Canonical JSON, equal origin, and a byte-identical rewrite of the decoded table.
private def derived_names_assert_round_trip(origin : Iyi::DiagnosticOrigin) : Nil
  bytes, index = derived_names_bytes(origin)
  restored = derived_names_read(bytes)
  restored.parent(index).should eq(origin)
  restored.parent(index).to_json.should eq(origin.to_json)
  rewritten = IO::Memory.new
  restored.write(rewritten)
  rewritten.to_slice.should eq(bytes)
end

private def derived_names_written_operator_bytes : {Bytes, Int32}
  bytes, _ = derived_names_bytes(derived_names_operator(Iyi::DiagnosticOperatorProduction::OpAssign,
    derived_names_written(2), [derived_names_witness(2, "+=")], 6))
  {bytes, derived_names_position(bytes, DERIVED_NAMES_DIGEST.to_slice)}
end

describe "operator and structural name transport" do
  it "round-trips every written operator production" do
    {
      {Iyi::DiagnosticOperatorProduction::OpAssign, 2, [derived_names_witness(2, "+=")], 6},
      {Iyi::DiagnosticOperatorProduction::SignedNumber, 2,
       [derived_names_witness(2, "-1", "NUMBER", Iyi::DiagnosticTokenSelection::SignedNumberSign)], 4},
      {Iyi::DiagnosticOperatorProduction::Index, 1, [derived_names_witness(1, "["), derived_names_witness(3, "]")], 4},
      {Iyi::DiagnosticOperatorProduction::IndexQuery, 1,
       [derived_names_witness(1, "["), derived_names_witness(3, "]"), derived_names_witness(4, "?")], 5},
      {Iyi::DiagnosticOperatorProduction::IndexAssign, 1,
       [derived_names_witness(1, "["), derived_names_witness(3, "]"), derived_names_witness(5, "=")], 8},
      {Iyi::DiagnosticOperatorProduction::IndexAssign, 1,
       [derived_names_witness(1, "[]"), derived_names_witness(4, "=")], 8},
      {Iyi::DiagnosticOperatorProduction::Setter, 2,
       [derived_names_witness(2, "x", "IDENT"), derived_names_witness(4, "=")], 6},
      {Iyi::DiagnosticOperatorProduction::Command, 0, [derived_names_witness(0, "`", "DELIMITER_START")], 3},
    }.each do |production, offset, witnesses, bytesize|
      derived_names_assert_round_trip(derived_names_operator(production, derived_names_written(offset), witnesses, bytesize))
    end
  end

  it "round-trips written unnamed-parameter and short-block structural names" do
    derived_names_assert_round_trip(derived_names_structural(Iyi::DiagnosticStructuralProduction::UnnamedFunParameter,
      derived_names_written(0, "FunDef", "keyword"),
      [derived_names_witness(5, "("), derived_names_witness(6, "Int32", "CONST")], 12))
    derived_names_assert_round_trip(derived_names_structural(Iyi::DiagnosticStructuralProduction::ShortBlockArgument,
      derived_names_written(3, "Block", "ampersand"),
      [derived_names_witness(3, "&"), derived_names_witness(4, ".")], 8, 7))
  end

  it "round-trips expanded operator names with witness events from mixed producers" do
    derived_names_assert_round_trip(derived_names_operator(Iyi::DiagnosticOperatorProduction::IndexAssign,
      derived_names_expanded(derived_names_event(1, "[")),
      [derived_names_witness(1, "["),
       derived_names_witness(3, "]", event: derived_names_event(3, "]", producer: Iyi::DiagnosticMacroProducer::MacroVar)),
       derived_names_witness(5, "=", event: derived_names_event(5, "=", producer: Iyi::DiagnosticMacroProducer::StructuredSyntax))],
      8))
    derived_names_assert_round_trip(derived_names_operator(Iyi::DiagnosticOperatorProduction::SignedNumber,
      derived_names_expanded(derived_names_event(2, "-1", "NUMBER", selection: Iyi::DiagnosticTokenSelection::SignedNumberSign)),
      [derived_names_witness(2, "-1", "NUMBER", Iyi::DiagnosticTokenSelection::SignedNumberSign)], 4))
    derived_names_assert_round_trip(derived_names_operator(Iyi::DiagnosticOperatorProduction::Command,
      derived_names_expanded(derived_names_event(0, "`", "DELIMITER_START")),
      [derived_names_witness(0, "`", "DELIMITER_START")], 3))
  end

  it "round-trips an expanded unnamed parameter whose type head is a name splice" do
    anchor = derived_names_expanded(derived_names_keyword(0), "FunDef", "keyword")
    separator = derived_names_event(5, "(", producer: Iyi::DiagnosticMacroProducer::MacroVar)
    head = Iyi::DiagnosticTokenEvent.new(6, 11, "CONST", "Int32", "Crystal", Iyi::DiagnosticTokenSelection::Whole,
      [derived_names_name_part(6, "Int32")] of Iyi::DiagnosticEmissionPart)
    origin = derived_names_structural(Iyi::DiagnosticStructuralProduction::UnnamedFunParameter, anchor,
      [derived_names_witness(5, "(", event: separator), derived_names_witness(6, "Int32", "CONST", event: head)], 12)
    origin.rendered_text.should eq("")
    origin.producer_context.should eq("parameter")
    derived_names_assert_round_trip(origin)
  end

  it "round-trips an expanded short block argument whose anchor carries the ampersand" do
    anchor = derived_names_expanded(derived_names_event(3, "&"), "Block", "ampersand")
    origin = derived_names_structural(Iyi::DiagnosticStructuralProduction::ShortBlockArgument, anchor,
      [derived_names_witness(3, "&"), derived_names_witness(4, ".", event: derived_names_event(4, "."))], 8, 7)
    origin.rendered_text.should eq("__arg7")
    derived_names_assert_round_trip(origin)
  end

  it "interns the anchor and every witness dependency before the derivation" do
    anchor = derived_names_expanded(derived_names_event(1, "["))
    macro_origin = Iyi::DiagnosticOrigin::Written.new("derived", "derived.cr", 0, "Macro", "keyword")
    origin = derived_names_operator(Iyi::DiagnosticOperatorProduction::IndexAssign, anchor,
      [derived_names_witness(1, "["),
       derived_names_witness(3, "]", event: derived_names_event(3, "]", producer: Iyi::DiagnosticMacroProducer::MacroVar)),
       derived_names_witness(5, "=", event: derived_names_event(5, "=", producer: Iyi::DiagnosticMacroProducer::StructuredSyntax))], 8)

    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    index.to_i32.should eq(table.entries.size - 1)
    earlier = table.entries[0...index.to_i32]
    earlier.any? { |entry| entry == anchor }.should be_true
    earlier.any? { |entry| entry == macro_origin }.should be_true
    table.intern(origin).should eq(index)
    table.entries.size.should eq(index.to_i32 + 1)

    restored = derived_names_read(derived_names_bytes(origin)[0])
    restored.entries.size.should eq(table.entries.size)
  end

  it "keeps input identities distinct" do
    table = Iyi::IyiMod::DiagnosticOrigins.new
    witnesses = [derived_names_witness(1, "["), derived_names_witness(3, "]")]
    first = derived_names_operator(Iyi::DiagnosticOperatorProduction::Index, derived_names_written(1), witnesses, 4)
    other_digest = Iyi::DiagnosticOrigin::DerivedName.operator_name(Iyi::DiagnosticOperatorProduction::Index,
      derived_names_written(1), "e" * 64, 4, "Crystal", witnesses)
    indices = [table.intern(first), table.intern(other_digest)]
    indices.uniq.size.should eq(2)
  end

  it "refuses an unknown operator production byte" do
    bytes, digest = derived_names_written_operator_bytes
    bytes[digest - 11].should eq(4_u8)
    bytes[digest - 10].should eq(7_u8)
    bytes[digest - 9] = 99_u8
    expect_raises(ArgumentError, /unknown diagnostic operator production/) { derived_names_read(bytes) }
  end

  it "refuses an unknown structural production byte" do
    bytes, _ = derived_names_bytes(derived_names_structural(Iyi::DiagnosticStructuralProduction::ShortBlockArgument,
      derived_names_written(3, "Block", "ampersand"), [derived_names_witness(3, "&"), derived_names_witness(4, ".")], 8, 7))
    digest = derived_names_position(bytes, DERIVED_NAMES_DIGEST.to_slice)
    bytes[digest - 10].should eq(8_u8)
    bytes[digest - 9] = 9_u8
    expect_raises(ArgumentError, /unknown diagnostic structural production/) { derived_names_read(bytes) }
  end

  it "refuses a forward or self anchor reference" do
    bytes, digest = derived_names_written_operator_bytes
    # The derivation is entry 1, so an anchor reference of 1 names itself.
    derived_names_set_u32(bytes, digest - 8, 1_u32)
    expect_raises(ArgumentError, /invalid diagnostic origin parent index/) { derived_names_read(bytes) }
  end

  it "refuses an invalid operator input digest and invalid UTF-8 in an origin string" do
    bytes, digest = derived_names_written_operator_bytes

    spelled = bytes.dup
    spelled[digest] = 'z'.ord.to_u8
    expect_raises(ArgumentError, /invalid operator input digest/) { derived_names_read(spelled) }

    utf8 = bytes.dup
    utf8[digest] = 0xFF_u8
    expect_raises(ArgumentError, /invalid UTF-8 in diagnostic section/) { derived_names_read(utf8) }
  end

  it "refuses an unknown input mode" do
    bytes, digest = derived_names_written_operator_bytes
    # digest (64 bytes), input byte size (four bytes), then the mode byte.
    bytes[digest + 64 + 4].should eq(0_u8)
    bytes[digest + 64 + 4] = 7_u8
    expect_raises(ArgumentError, /unknown diagnostic enum value/) { derived_names_read(bytes) }
  end

  it "refuses witness counts outside the production's permitted range before allocating" do
    bytes, digest = derived_names_written_operator_bytes
    count_at = digest + 64 + 4 + 1
    bytes[count_at].should eq(1_u8)

    [0_u32, 4_u32, UInt32::MAX].each do |count|
      tampered = bytes.dup
      derived_names_set_u32(tampered, count_at, count)
      expect_raises(ArgumentError, /witness count is not permitted/) { derived_names_read(tampered) }
    end

    # Three is permitted for an operator, but the remaining bytes cannot hold three witnesses.
    exceeds = bytes.dup
    derived_names_set_u32(exceeds, count_at, 3_u32)
    expect_raises(ArgumentError, /exceed remaining bytes/) { derived_names_read(exceeds) }
  end

  it "refuses an invalid witness event marker and an unknown selection" do
    bytes, _ = derived_names_bytes(derived_names_operator(Iyi::DiagnosticOperatorProduction::Setter,
      derived_names_written(2), [derived_names_witness(2, "x", "IDENT"), derived_names_witness(4, "=")], 6))
    kind = derived_names_position(bytes, "IDENT".to_slice)
    # kind text (5), raw length (4), raw text (1), selection (1), then the event marker.
    bytes[kind + 5 + 4 + 1 + 1].should eq(0_u8)
    marked = bytes.dup
    marked[kind + 5 + 4 + 1 + 1] = 2_u8
    expect_raises(ArgumentError, /invalid diagnostic name witness event marker/) { derived_names_read(marked) }

    selected = bytes.dup
    selected[kind + 5 + 4 + 1] = 9_u8
    expect_raises(ArgumentError, /unknown diagnostic enum value/) { derived_names_read(selected) }
  end

  it "refuses an invalid structural fresh-index marker" do
    bytes, _ = derived_names_bytes(derived_names_structural(Iyi::DiagnosticStructuralProduction::ShortBlockArgument,
      derived_names_written(3, "Block", "ampersand"), [derived_names_witness(3, "&"), derived_names_witness(4, ".")], 8, 7))
    # The fresh marker precedes the four-byte index, and the index ends the table.
    bytes[bytes.size - 5].should eq(1_u8)
    bytes[bytes.size - 5] = 2_u8
    expect_raises(ArgumentError, /invalid structural fresh index marker/) { derived_names_read(bytes) }
  end

  it "refuses every proper prefix of a derived-name table" do
    [
      derived_names_operator(Iyi::DiagnosticOperatorProduction::OpAssign, derived_names_written(2), [derived_names_witness(2, "+=")], 6),
      derived_names_operator(Iyi::DiagnosticOperatorProduction::IndexAssign,
        derived_names_expanded(derived_names_event(1, "[")),
        [derived_names_witness(1, "["),
         derived_names_witness(3, "]", event: derived_names_event(3, "]", producer: Iyi::DiagnosticMacroProducer::MacroVar)),
         derived_names_witness(5, "=", event: derived_names_event(5, "=", producer: Iyi::DiagnosticMacroProducer::StructuredSyntax))],
        8),
    ].each do |origin|
      bytes, _ = derived_names_bytes(origin)
      (0...bytes.size).each do |cut|
        expect_raises(Exception) { derived_names_read(bytes[0, cut]) }
      end
    end
  end

  it "refuses an origin string beyond the graph budget before allocating it" do
    bytes, digest = derived_names_written_operator_bytes
    # Six unfolded bytes per spelled byte: 1_500_000 bytes exceed the 8 MiB budget, and the payload is present.
    oversized = IO::Memory.new
    oversized.write(bytes[0, digest - 4])
    oversized.write_bytes(1_500_000_u32, Iyi::IyiMod::FORMAT)
    oversized.write(Bytes.new(1_500_000, 'd'.ord.to_u8))
    expect_raises(ArgumentError, /exceeds graph budget/) { derived_names_read(oversized.to_slice) }
  end

  it "refuses an emission part count beyond the graph budget before allocating the parts" do
    io = IO::Memory.new
    io.write_bytes(0_u32, Iyi::IyiMod::FORMAT)
    io.write_bytes(1_u32, Iyi::IyiMod::FORMAT)
    Iyi::IyiMod::DiagnosticOrigins.write_string(io, "IDENT")
    Iyi::IyiMod::DiagnosticOrigins.write_string(io, "x")
    io.write_byte 0_u8 # Crystal
    io.write_byte 0_u8 # Whole
    io.write_bytes(9_000_u32, Iyi::IyiMod::FORMAT)
    io.write(Bytes.new(200_000))
    io.rewind
    expect_raises(ArgumentError, /exceed graph budget/) do
      Iyi::IyiMod::DiagnosticOrigins.new.read_token_event(io)
    end
  end
end

describe "bare splat parameter transport" do
  it "round-trips written bare splats on a Def and on a Macro" do
    derived_names_assert_round_trip(derived_names_structural(Iyi::DiagnosticStructuralProduction::BareSplatParameter,
      derived_names_written(0, "Def", "keyword"),
      [derived_names_witness(6, "*"), derived_names_witness(7, ",")], 11))
    derived_names_assert_round_trip(derived_names_structural(Iyi::DiagnosticStructuralProduction::MacroBareSplatParameter,
      derived_names_written(0, "Macro", "keyword"),
      [derived_names_witness(8, "*"), derived_names_witness(9, ",")], 13))
  end

  it "round-trips an expanded bare splat whose star and comma each carry their own event" do
    anchor = derived_names_expanded(derived_names_event(0, "def", "IDENT"), "Def", "keyword")
    origin = derived_names_structural(Iyi::DiagnosticStructuralProduction::BareSplatParameter, anchor,
      [derived_names_witness(6, "*", event: derived_names_event(6, "*", producer: Iyi::DiagnosticMacroProducer::StructuredSyntax)),
       derived_names_witness(7, ",", event: derived_names_event(7, ",", producer: Iyi::DiagnosticMacroProducer::StructuredSyntax))], 11)
    origin.rendered_text.should eq("")
    origin.producer_context.should eq("parameter")
    derived_names_assert_round_trip(origin)
  end

  it "refuses a bare splat table whose witness count is not exactly two" do
    bytes, _ = derived_names_bytes(derived_names_structural(Iyi::DiagnosticStructuralProduction::BareSplatParameter,
      derived_names_written(0, "Def", "keyword"), [derived_names_witness(6, "*"), derived_names_witness(7, ",")], 11))
    digest = derived_names_position(bytes, DERIVED_NAMES_DIGEST.to_slice)
    # digest (64 bytes), input byte size (four bytes), the mode byte, then the witness count.
    count_at = digest + 64 + 4 + 1
    bytes[count_at].should eq(2_u8)

    [1_u32, 3_u32].each do |count|
      tampered = bytes.dup
      derived_names_set_u32(tampered, count_at, count)
      expect_raises(ArgumentError, /witness count is not permitted/) { derived_names_read(tampered) }
    end
  end
end
