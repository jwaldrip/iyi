require "../support/syntax"

# Canonical pragma snapshots (`DiagnosticPragmaSnapshot.read`) and the J2 replay
# binding (`DiagnosticCaptureBinding.bind!`).
#
# A decoded snapshot is the real `Hash(Int32, Array(Lexer::LocPragma))`, and it
# must round-trip: `new(read(bytes)).bytes == bytes`. Insertion order is kept.
# Refusals come from `read` itself. The emission cases are built from the public
# constructors of each type, then mutated at their canonical bytes.

private def pragma_spec_pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  pragmas[3] = [Iyi::Lexer::LocSetPragma.new("/spec/pragma/a.iyi", 7, 1, nil), Iyi::Lexer::LocPushPragma.new] of Iyi::Lexer::LocPragma
  pragmas[9] = [Iyi::Lexer::LocOriginPragma.new(12), Iyi::Lexer::LocPopPragma.new] of Iyi::Lexer::LocPragma
  pragmas
end

# The same content inserted 9 first, then 3.
private def pragma_spec_reversed : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  pragmas[9] = [Iyi::Lexer::LocOriginPragma.new(12), Iyi::Lexer::LocPopPragma.new] of Iyi::Lexer::LocPragma
  pragmas[3] = [Iyi::Lexer::LocSetPragma.new("/spec/pragma/a.iyi", 7, 1, nil), Iyi::Lexer::LocPushPragma.new] of Iyi::Lexer::LocPragma
  pragmas
end

PRAGMA_SPEC_LIVE_TEXT = %({"present":true,"entries":[{"offset":3,"pragmas":[{"kind":"Set","filename":"/spec/pragma/a.iyi","line":7,"column":1,"artifact":null},{"kind":"Push"}]},{"offset":9,"pragmas":[{"kind":"Origin","line":12},{"kind":"Pop"}]}]})

PRAGMA_SPEC_REVERSED_TEXT = %({"present":true,"entries":[{"offset":9,"pragmas":[{"kind":"Origin","line":12},{"kind":"Pop"}]},{"offset":3,"pragmas":[{"kind":"Set","filename":"/spec/pragma/a.iyi","line":7,"column":1,"artifact":null},{"kind":"Push"}]}]})

# A DiagnosticEmission built from every evidence kind, every attachment head kind,
# every emission part kind, and every name value kind.

private def emission_spec_origin(anchor : String, role : String) : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::Written.new("source-file:/spec/emit/a.iyi", "/spec/emit/a.iyi", 0, anchor, role)
end

private def emission_spec_key(start : Int32, finish : Int32) : Iyi::DiagnosticMacroClaimKey
  Iyi::DiagnosticMacroClaimKey.new(Iyi::DiagnosticWriterRef.new(start, finish), "Call", "method")
end

private def emission_spec_name_token : Iyi::DiagnosticSourceNameToken
  Iyi::DiagnosticSourceNameToken.new(emission_spec_origin("Call", "method"), nil, "method_name", "a" * 64, 3, 0, 3, "Iyi", "IDENT", "foo")
end

private def emission_spec_name_event : Iyi::DiagnosticTokenEvent
  part = Iyi::DiagnosticEmissionPart::NameSplice.new(0, 3, nil, Iyi::DiagnosticNameValue::Observed.new(emission_spec_name_token)).as(Iyi::DiagnosticEmissionPart)
  Iyi::DiagnosticTokenEvent.new(0, 3, "IDENT", "foo", "Iyi", Iyi::DiagnosticTokenSelection::Whole, [part] of Iyi::DiagnosticEmissionPart)
end

private def emission_spec_open_event : Iyi::DiagnosticTokenEvent
  part = Iyi::DiagnosticEmissionPart::Generated.new(0, 1, nil, Iyi::DiagnosticMacroProducer::ConstructedAst).as(Iyi::DiagnosticEmissionPart)
  Iyi::DiagnosticTokenEvent.new(0, 1, "DELIMITER_START", "(", "Iyi", Iyi::DiagnosticTokenSelection::Whole, [part] of Iyi::DiagnosticEmissionPart)
end

private def emission_spec_equals_event : Iyi::DiagnosticTokenEvent
  part = Iyi::DiagnosticEmissionPart::AstAnchor.new(3, 4, nil, emission_spec_origin("Call", "method")).as(Iyi::DiagnosticEmissionPart)
  Iyi::DiagnosticTokenEvent.new(3, 4, "=", "=", "Iyi", Iyi::DiagnosticTokenSelection::Whole, [part] of Iyi::DiagnosticEmissionPart)
end

private def emission_spec_value : Iyi::Lexer::LocDiagnosticEmission
  witnesses = [
    Iyi::DiagnosticSyntaxWitness.new(Iyi::DiagnosticWitnessRole::Open, emission_spec_open_event),
    Iyi::DiagnosticSyntaxWitness.new(Iyi::DiagnosticWitnessRole::Equals, emission_spec_equals_event),
    Iyi::DiagnosticSyntaxWitness.new(Iyi::DiagnosticWitnessRole::Comma, emission_spec_name_event),
  ] of Iyi::DiagnosticSyntaxWitness
  claims = [
    Iyi::DiagnosticMacroClaim.new(emission_spec_key(0, 4), Iyi::DiagnosticAnchorEvidence::Constructed.new(Iyi::DiagnosticMacroProducer::ConstructedAst),
      Iyi::DiagnosticMacroAttachment::Direct.new(Iyi::DiagnosticWriterRef.new(0, 4)), nil),
    Iyi::DiagnosticMacroClaim.new(emission_spec_key(0, 4), Iyi::DiagnosticAnchorEvidence::Spliced.new(emission_spec_origin("Call", "method")),
      Iyi::DiagnosticMacroAttachment::HeadOf.new(Iyi::DiagnosticHeadRule::NamedArrayHead, Iyi::DiagnosticMacroHead::Anchor.new(Iyi::DiagnosticWriterRef.new(0, 1))),
      emission_spec_origin("MacroDirective", "expression")),
    Iyi::DiagnosticMacroClaim.new(emission_spec_key(0, 1), Iyi::DiagnosticAnchorEvidence::RawSyntax.new(witnesses),
      Iyi::DiagnosticMacroAttachment::Direct.new(Iyi::DiagnosticWriterRef.new(0, 1)), nil),
    Iyi::DiagnosticMacroClaim.new(emission_spec_key(1, 2), Iyi::DiagnosticAnchorEvidence::DerivedFromOwner.new,
      Iyi::DiagnosticMacroAttachment::HeadOf.new(Iyi::DiagnosticHeadRule::NamedHashHead,
        Iyi::DiagnosticMacroHead::Syntax.new(Iyi::DiagnosticHeadSyntax::FirstSplat, Iyi::DiagnosticWriterRef.new(1, 2), Iyi::DiagnosticWriterRef.new(0, 1))), nil),
    Iyi::DiagnosticMacroClaim.new(emission_spec_key(2, 3), Iyi::DiagnosticAnchorEvidence::Constructed.new(Iyi::DiagnosticMacroProducer::EmptyTupleProjection),
      Iyi::DiagnosticMacroAttachment::PayloadOf.new(Iyi::DiagnosticPayloadRule::RegexInterpolationPayload, emission_spec_key(0, 4)),
      emission_spec_origin("MacroDirective", "control")),
  ] of Iyi::DiagnosticMacroClaim
  generated = [
    Iyi::DiagnosticGeneratedText.new(0, 4, emission_spec_origin("MacroDirective", "expression"), Iyi::DiagnosticMacroProducer::ConstructedAst),
    Iyi::DiagnosticGeneratedText.new(4, 5, nil, Iyi::DiagnosticMacroProducer::MacroTemplate),
  ] of Iyi::DiagnosticGeneratedText
  names = [
    Iyi::DiagnosticMacroNameFragment.new(0, 3, nil, Iyi::DiagnosticNameValue::Observed.new(emission_spec_name_token)),
  ] of Iyi::DiagnosticMacroNameFragment
  Iyi::Lexer::LocDiagnosticEmission.new(5, claims, generated, names)
end

private def emission_spec_pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  pragmas[3] = [emission_spec_value] of Iyi::Lexer::LocPragma
  pragmas
end

describe "DiagnosticPragmaSnapshot.read" do
  it "writes live entries in insertion order, not sorted" do
    Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_pragmas).bytes.should eq PRAGMA_SPEC_LIVE_TEXT
    Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_reversed).bytes.should eq PRAGMA_SPEC_REVERSED_TEXT
  end

  it "differs in bytes when only the insertion order differs" do
    Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_pragmas).bytes.should_not eq Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_reversed).bytes
  end

  it "round-trips in-order live bytes to the same typed hash" do
    live = Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_pragmas).bytes
    decoded = Iyi::DiagnosticPragmaSnapshot.read(live).not_nil!
    decoded.keys.should eq [3, 9]
    decoded[3].size.should eq 2
    Iyi::DiagnosticPragmaSnapshot.new(decoded).bytes.should eq live
  end

  it "round-trips out-of-order live bytes, keeping 9 before 3" do
    reversed = Iyi::DiagnosticPragmaSnapshot.new(pragma_spec_reversed).bytes
    decoded = Iyi::DiagnosticPragmaSnapshot.read(reversed).not_nil!
    decoded.keys.should eq [9, 3]
    Iyi::DiagnosticPragmaSnapshot.new(decoded).bytes.should eq reversed
  end

  it "accepts hand-written out-of-order canonical bytes and preserves their order" do
    decoded = Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_REVERSED_TEXT).not_nil!
    decoded.keys.should eq [9, 3]
    Iyi::DiagnosticPragmaSnapshot.new(decoded).bytes.should eq PRAGMA_SPEC_REVERSED_TEXT
  end

  it "round-trips an absent snapshot to nil" do
    live = Iyi::DiagnosticPragmaSnapshot.new(nil).bytes
    live.should eq %({"present":false,"entries":[]})
    Iyi::DiagnosticPragmaSnapshot.read(live).should be_nil
    Iyi::DiagnosticPragmaSnapshot.new(Iyi::DiagnosticPragmaSnapshot.read(live)).bytes.should eq live
  end

  it "round-trips a typed DiagnosticEmission built from every evidence, attachment, part and name kind" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    decoded = Iyi::DiagnosticPragmaSnapshot.read(live).not_nil!
    emission = decoded[3].first.as(Iyi::Lexer::LocDiagnosticEmission)
    emission.claims.size.should eq 5
    emission.claims[1].attachment.should be_a(Iyi::DiagnosticMacroAttachment::HeadOf)
    emission.claims[2].evidence.should be_a(Iyi::DiagnosticAnchorEvidence::RawSyntax)
    Iyi::DiagnosticPragmaSnapshot.new(decoded).bytes.should eq live
  end

  it "refuses a repeated offset" do
    expect_raises(ArgumentError, /repeats offset 3/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":true,"entries":[{"offset":3,"pragmas":[]},{"offset":3,"pragmas":[]}]}))
    end
  end

  it "refuses an unknown macro producer in a forged emission" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown macro producer Forged/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"producer\":\"ConstructedAst\"", "\"producer\":\"Forged\""))
    end
  end

  it "refuses an unknown evidence kind" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown evidence kind Stolen/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"kind\":\"Spliced\"", "\"kind\":\"Stolen\""))
    end
  end

  it "refuses an unknown witness role" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown witness role Shut/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"role\":\"Open\"", "\"role\":\"Shut\""))
    end
  end

  it "refuses an unknown head rule" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown head rule Stolen/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"rule\":\"NamedArrayHead\"", "\"rule\":\"Stolen\""))
    end
  end

  it "refuses an unknown token selection" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown token selection Partial/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"selection\":\"Whole\"", "\"selection\":\"Partial\""))
    end
  end

  it "refuses an unknown name value kind" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /unknown name value kind Forged/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"kind\":\"Observed\"", "\"kind\":\"Forged\""))
    end
  end

  it "refuses an extra field inside an emission claim key" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /claim key keys are not writer, kind, role/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"role\":\"method\"", "\"role\":\"method\",\"extra\":1"))
    end
  end

  it "refuses an emission whose bytes are not the canonical encoding" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /not in canonical encoding/) do
      Iyi::DiagnosticPragmaSnapshot.read(live.sub("\"end\":5", "\"end\": 5"))
    end
  end

  it "refuses a truncated emission" do
    live = Iyi::DiagnosticPragmaSnapshot.new(emission_spec_pragmas).bytes
    expect_raises(ArgumentError, /not parseable JSON/) do
      Iyi::DiagnosticPragmaSnapshot.read(live[0, live.bytesize - 5])
    end
  end

  it "refuses origin content beyond the shared decode budget" do
    big = "a" * (3 * 1024 * 1024)
    origin = %({"kind":"Written","source_identity":{"module":"m","file":"#{big}"},"input_byte_offset":0,"anchor_kind":"Call","role":"method"})
    claim = %({"key":{"writer":{"start":0,"end":1},"kind":"Call","role":"method"},"evidence":{"kind":"Spliced","source_origin":#{origin}},"attachment":{"kind":"Direct","writer":{"start":0,"end":1}},"emitter_origin":#{origin}})
    text = %({"present":true,"entries":[{"offset":3,"pragmas":[{"kind":"DiagnosticEmission","end":4,"claims":[#{claim},#{claim}],"generated_text":[],"name_fragments":[]}]}]})
    expect_raises(ArgumentError, /graph exceeds size limit/) do
      Iyi::DiagnosticPragmaSnapshot.read(text)
    end
  end

  it "refuses a truncated snapshot" do
    expect_raises(ArgumentError, /not parseable JSON/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT[0, PRAGMA_SPEC_LIVE_TEXT.bytesize - 1])
    end
  end

  it "refuses trailing whitespace as non-canonical" do
    expect_raises(ArgumentError, /not in canonical encoding/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT + " ")
    end
  end

  it "refuses a duplicated top-level key" do
    expect_raises(ArgumentError, /not in canonical encoding/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT.sub("{\"present\":true", "{\"present\":true,\"present\":true"))
    end
  end

  it "refuses an unknown top-level key" do
    expect_raises(ArgumentError, /keys are not present, entries/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT.sub("{\"present\":true", "{\"extra\":0,\"present\":true"))
    end
  end

  it "refuses an unknown pragma kind" do
    expect_raises(ArgumentError, /unknown pragma kind/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT.sub("\"kind\":\"Push\"", "\"kind\":\"Shove\""))
    end
  end

  it "refuses an escaped spelling of a known kind as non-canonical" do
    expect_raises(ArgumentError, /not in canonical encoding/) do
      Iyi::DiagnosticPragmaSnapshot.read(PRAGMA_SPEC_LIVE_TEXT.sub("\"kind\":\"Push\"", "\"kind\":\"\\u0050ush\""))
    end
  end

  it "refuses a negative offset" do
    expect_raises(ArgumentError, /offset is negative/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":true,"entries":[{"offset":-1,"pragmas":[]}]}))
    end
  end

  it "refuses entries when the snapshot is not present" do
    expect_raises(ArgumentError, /has entries but is not present/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":false,"entries":[{"offset":1,"pragmas":[]}]}))
    end
  end

  it "refuses a fractional offset" do
    expect_raises(ArgumentError, /offset is not an integer/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":true,"entries":[{"offset":3.0,"pragmas":[]}]}))
    end
  end

  it "refuses nesting beyond the JSON parser's limit" do
    expect_raises(ArgumentError, /not parseable JSON/) do
      Iyi::DiagnosticPragmaSnapshot.read("[" * 2000 + "]" * 2000)
    end
  end

  it "refuses bytes that are not UTF-8" do
    expect_raises(ArgumentError, /not UTF-8/) do
      Iyi::DiagnosticPragmaSnapshot.read(String.new(Bytes[0xff]))
    end
  end

  it "refuses a present flag that is not a boolean" do
    expect_raises(ArgumentError, /present is not a boolean/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":null,"entries":[]}))
    end
    expect_raises(ArgumentError, /present is not a boolean/) do
      Iyi::DiagnosticPragmaSnapshot.read(%({"present":0,"entries":[]}))
    end
  end

  it "refuses input over the size limit before parsing" do
    expect_raises(ArgumentError, /exceeds size limit/) do
      Iyi::DiagnosticPragmaSnapshot.read("x" * (Iyi::DiagnosticPragmaSnapshot::MAX_BYTES + 1))
    end
  end
end

# J2 replay binding. A claim binds only against the authority its live parse
# recorded, and its replay must reproduce that authority's key and digest.

private def binding_spec_parser(source : String, filename : String) : Iyi::Parser
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  parser.enable_diagnostic_observations
  parser
end

private def binding_spec_input(source : String, filename : String, logical_module : String? = nil) : Iyi::AcceptedCaptureInput
  binding_spec_parser(source, filename).diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
    logical_module, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
end

# Runs the block with `source` written to a temp file, removed afterward. The
# recorder classifies a capture by reading that file, so the bytes must be on disk.
private def binding_spec_with_file(source : String, stem : String, & : String ->)
  path = File.tempname(stem, ".iyi")
  File.write(path, source)
  begin
    yield path
  ensure
    File.delete(path) if File.file?(path)
  end
end

# Records `source` through the live recorder over `path`, which must hold the same
# bytes. Returns the ledger (not yet frozen), the claim and its authority.
private def binding_spec_record(source : String, path : String) : {Iyi::DiagnosticCaptureLedger, Iyi::AcceptedCaptureInput, Iyi::DiagnosticCaptureAuthority}
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = path
  ledger = Iyi::DiagnosticCaptureLedger.new
  _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
  {ledger, claim, authority}
end

# Writes, records, freezes and binds one source. The bound capture's identity uses
# the temp path, so callers read it from `bound.input.original_file`.
private def binding_spec_bind(source : String, stem : String) : Iyi::DiagnosticBoundCapture
  binding_spec_with_file(source, stem) do |path|
    ledger, claim, authority = binding_spec_record(source, path)
    ledger.freeze!
    ledger.bind!(claim, authority)
  end
end

BINDING_SPEC_HEADER  = "module sample/identity\nvalue = 1\n"
BINDING_SPEC_PLAIN   = "value = 1\n"
BINDING_SPEC_LITERAL = "value = \"abc\"\n"
BINDING_SPEC_FORGED  = "value = \"xyz\"\n"

describe "DiagnosticCaptureBinding.bind!" do
  it "binds a header source whose replay reproduces its recorded authority" do
    bound = binding_spec_bind(BINDING_SPEC_HEADER, "identity")
    bound.identity.declared.should eq "sample/identity"
    bound.identity.expected_module(0).should eq "sample/identity"
  end

  it "takes module identity from the real header, not a decoy in a comment" do
    bound = binding_spec_bind("# module decoy/name\nmodule sample/identity\nvalue = 1\n", "decoy")
    bound.identity.declared.should eq "sample/identity"
  end

  it "gives a headerless source the source-file unit at every offset" do
    bound = binding_spec_bind(BINDING_SPEC_PLAIN, "plain")
    bound.identity.declared.should be_nil
    bound.identity.expected_module(0).should eq "source-file:#{bound.input.original_file}"
  end

  it "refuses the forged abc-to-xyz pair: a claim cannot bind to another recording's authority" do
    binding_spec_with_file(BINDING_SPEC_LITERAL, "literal") do |literal_path|
      binding_spec_with_file(BINDING_SPEC_FORGED, "forged") do |forged_path|
        _, literal_claim, _ = binding_spec_record(BINDING_SPEC_LITERAL, literal_path)
        ledger, _, forged_authority = binding_spec_record(BINDING_SPEC_FORGED, forged_path)
        ledger.freeze!
        expect_raises(ArgumentError, /capture key differs from its authority/) do
          ledger.bind!(literal_claim, forged_authority)
        end
      end
    end
  end

  it "refuses a source whose bytes bind to another source's authority (wrong source)" do
    binding_spec_with_file(BINDING_SPEC_PLAIN, "plain") do |plain_path|
      binding_spec_with_file(BINDING_SPEC_HEADER, "header") do |header_path|
        _, plain_claim, _ = binding_spec_record(BINDING_SPEC_PLAIN, plain_path)
        ledger, _, header_authority = binding_spec_record(BINDING_SPEC_HEADER, header_path)
        ledger.freeze!
        expect_raises(ArgumentError, /capture key differs from its authority/) do
          ledger.bind!(plain_claim, header_authority)
        end
      end
    end
  end

  it "refuses a caller-supplied module identity on a source file (wrong module)" do
    binding_spec_with_file(BINDING_SPEC_PLAIN, "plain") do |path|
      ledger, _, authority = binding_spec_record(BINDING_SPEC_PLAIN, path)
      ledger.freeze!
      forged = binding_spec_input(BINDING_SPEC_PLAIN, path, "forged/module")
      expect_raises(ArgumentError, /capture key differs from its authority/) do
        ledger.bind!(forged, authority)
      end
    end
  end

  it "fails closed on a string literal until its journal binding (C-L) lands" do
    expect_raises(ArgumentError, /literal evidence requires journal literal binding/) do
      binding_spec_bind(BINDING_SPEC_LITERAL, "literal")
    end
  end
end

# E2 and E3: witness events rebuilt from the pinned emission records.

private def witness_spec_generated(start : Int32, finish : Int32, producer : Iyi::DiagnosticMacroProducer) : Iyi::DiagnosticGeneratedText
  Iyi::DiagnosticGeneratedText.new(start, finish, nil, producer)
end

private def witness_spec_name(start : Int32, finish : Int32) : Iyi::DiagnosticMacroNameFragment
  Iyi::DiagnosticMacroNameFragment.new(start, finish, nil, Iyi::DiagnosticNameValue::Observed.new(emission_spec_name_token))
end

describe "DiagnosticWitnessEventReplay" do
  it "rebuilds an IDENT witness covered by a name splice" do
    event = Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "IDENT", "foo", "Iyi",
      [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    event.byte_parts.size.should eq 1
    event.byte_parts[0].should be_a(Iyi::DiagnosticEmissionPart::NameSplice)
  end

  it "accepts a recorded event that equals the rebuilt one" do
    event = Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "IDENT", "foo", "Iyi",
      [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    witness = Iyi::DiagnosticOperatorWitness.new(0, 3, "IDENT", "foo", Iyi::DiagnosticTokenSelection::Whole, event)
    Iyi::DiagnosticWitnessEventReplay.verify!(witness, "Iyi", [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
  end

  it "refuses a recorded Generated part where the emission has a NameSplice" do
    recorded = Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "IDENT", "foo", "Iyi",
      [witness_spec_generated(0, 3, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticGeneratedText, [] of Iyi::DiagnosticMacroNameFragment)
    witness = Iyi::DiagnosticOperatorWitness.new(0, 3, "IDENT", "foo", Iyi::DiagnosticTokenSelection::Whole, recorded)
    expect_raises(ArgumentError, /witness event differs from macro emission/) do
      Iyi::DiagnosticWitnessEventReplay.verify!(witness, "Iyi", [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    end
  end

  it "refuses a missing event where E2 requires one" do
    witness = Iyi::DiagnosticOperatorWitness.new(0, 3, "IDENT", "foo", Iyi::DiagnosticTokenSelection::Whole, nil)
    expect_raises(ArgumentError, /witness event differs from macro emission/) do
      Iyi::DiagnosticWitnessEventReplay.verify!(witness, "Iyi", [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    end
  end

  it "refuses a witness byte that no emission record attributes" do
    expect_raises(ArgumentError, /witness bytes not attributed by macro emission/) do
      Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "IDENT", "foo", "Iyi",
        [] of Iyi::DiagnosticGeneratedText, [] of Iyi::DiagnosticMacroNameFragment)
    end
  end

  it "refuses a name splice on a witness that is not CONST or IDENT" do
    expect_raises(ArgumentError, /name splice requires a CONST or IDENT witness/) do
      Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "DELIMITER_START", "foo", "Iyi",
        [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    end
  end

  it "refuses a witness whose selection is not whole" do
    event = Iyi::DiagnosticWitnessEventReplay.expected_event(0, 3, "IDENT", "foo", "Iyi",
      [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    witness = Iyi::DiagnosticOperatorWitness.new(0, 3, "IDENT", "foo", Iyi::DiagnosticTokenSelection::SignedNumberSign, event)
    expect_raises(ArgumentError, /witness selection is not whole/) do
      Iyi::DiagnosticWitnessEventReplay.verify!(witness, "Iyi", [] of Iyi::DiagnosticGeneratedText, [witness_spec_name(0, 3)])
    end
  end
end

describe "DiagnosticUnnamedParamBinder (Written chain)" do
  it "binds a lib fun whose unnamed parameter witnesses are Written" do
    bound = binding_spec_bind("lib LibC\n  fun abs(Int32) : Int32\nend\n", "lib")
    bound.should be_a(Iyi::DiagnosticBoundCapture)
  end
end

# D4 controls: the binder and the name evidence, run on replayed trees.

# The replay root and journal exactly as `bind!` builds them (3782-3788), so a
# control can mutate the replayed tree before the binders see it.
private def binder_spec_replay(source : String, path : String) : {Iyi::AcceptedCaptureInput, Iyi::ASTNode, Iyi::DiagnosticReplayJournal}
  input = binding_spec_input(source, path)
  parser = input.replay_parser
  parser.enable_diagnostic_observations
  root = parser.parse
  {input, root, Iyi::DiagnosticReplayJournal.new(parser.diagnostic_lexical_observations)}
end

# The rest of `bind!` after the digest check: module identity, the unnamed
# parameter binder, then the evidence walk.
private def binder_spec_verify(input, root, journal)
  identity = Iyi::DiagnosticModuleIdentity.from(root, input, journal)
  structural = Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
  Iyi::DiagnosticEvidenceBinding.new(input, journal, identity, structural).verify!(root)
end

private def binder_spec_funs(root : Iyi::ASTNode) : Array(Iyi::FunDef)
  body = root.as(Iyi::LibDef).body
  items = body.is_a?(Iyi::Expressions) ? body.expressions : [body]
  items.map(&.as(Iyi::FunDef))
end

describe "DiagnosticCaptureBinding.bind! unnamed parameters and name evidence" do
  it "binds a written `::` head as an unnamed lib parameter (PC-4)" do
    bound = binding_spec_bind("lib LibC\n  fun h(::Int32) : Void\nend\n", "pc4")
    bound.should be_a(Iyi::DiagnosticBoundCapture)
  end

  it "binds a written proc-notation head as an unnamed lib parameter (PC-5)" do
    bound = binding_spec_bind("lib LibC\n  fun k((Int32) -> Void) : Void\nend\n", "pc5")
    bound.should be_a(Iyi::DiagnosticBoundCapture)
  end

  it "refuses a string real name as literal evidence, not as a misplaced separator" do
    expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
      binding_spec_bind("lib LibC\n  fun f = \"c_f\"(Int32) : Int32\nend\n", "cf")
    end
  end

  it "binds an explicit real name on a lib fun" do
    bound = binding_spec_bind("lib LibC\n  fun gcollect = GC_gcollect : Void\nend\n", "gcollect")
    bound.should be_a(Iyi::DiagnosticBoundCapture)
  end
end

describe "DiagnosticUnnamedParamBinder and FunDef name controls" do
  it "refuses a name set on a written unnamed parameter (NC-1)" do
    input, root, journal = binder_spec_replay("lib LibC\n  fun abs(Int32) : Int32\nend\n", "/spec/binding/nc1.iyi")
    binder_spec_funs(root)[0].args[0].name = "x"
    expect_raises(ArgumentError, "structural witness differs") do
      Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
    end
  end

  it "refuses two written unnamed parameters whose restrictions are swapped (U4)" do
    input, root, journal = binder_spec_replay("lib LibC\n  fun two(Int32, ::Int32) : Void\nend\n", "/spec/binding/u4.iyi")
    args = binder_spec_funs(root)[0].args
    first_restriction = args[0].restriction
    args[0].restriction = args[1].restriction
    args[1].restriction = first_restriction
    expect_raises(ArgumentError, "structural witness differs") do
      Iyi::DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
    end
  end

  it "refuses a mutated name field against its source token" do
    input, root, journal = binder_spec_replay("lib LibC\n  fun gcollect = GC_gcollect : Void\nend\n", "/spec/binding/gcollect_name.iyi")
    binder_spec_funs(root)[0].name = "other"
    expect_raises(ArgumentError, "name field differs from source evidence") do
      binder_spec_verify(input, root, journal)
    end
  end

  it "refuses a mutated implicit real name" do
    input, root, journal = binder_spec_replay("lib LibC\n  fun abs(Int32) : Int32\nend\n", "/spec/binding/abs_implicit.iyi")
    binder_spec_funs(root)[0].real_name = "other"
    expect_raises(ArgumentError, "invalid implicit foreign-name observation") do
      binder_spec_verify(input, root, journal)
    end
  end

  it "keeps the legacy check green on a named lib parameter" do
    input, root, _ = binder_spec_replay("lib LibC\n  fun abs(x : Int32) : Int32\nend\n", "/spec/binding/legacy.iyi")
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end
end
