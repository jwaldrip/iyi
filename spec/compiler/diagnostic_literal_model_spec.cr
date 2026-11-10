require "../support/syntax"
require "base64"

private DERIVED_SOURCE = "%w(a)"

private def literal_model_sha(source : String) : String
  ::Crystal::Digest::SHA256.hexdigest(source)
end

private def literal_model_origin : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::Written.new("spec", "/spec/literal_model.cr", 0, "TypeSyntax", "token")
end

private def percent_witness(kind : String, raw : String) : Iyi::DiagnosticSourceSyntaxToken
  Iyi::DiagnosticSourceSyntaxToken.new(literal_model_origin, literal_model_sha(DERIVED_SOURCE),
    DERIVED_SOURCE.bytesize, 0, raw.bytesize, "Crystal", kind, raw)
end

private def quoted(context : String = "named_entry", sha : String = literal_model_sha("abc x"),
                   bytesize : Int32 = 10, mode : String = "Crystal", start : Int32 = 0,
                   finish : Int32 = 10, text : String = "abc") : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::DerivedName.quoted_name(context, sha, bytesize, mode, start, finish, text)
end

describe "S1 literal journal model" do
  it "accepts a CHAR value and rejects a value on an identifier" do
    token = Iyi::DiagnosticRenderedToken.new(0, 3, "CHAR", "'a'", "Crystal", Base64.strict_encode("a".to_slice))
    token.value_base64.should eq(Base64.strict_encode("a".to_slice))
    expect_raises(ArgumentError, "rendered value on a non-string token") do
      Iyi::DiagnosticRenderedToken.new(0, 1, "IDENT", "a", "Crystal", Base64.strict_encode("a".to_slice))
    end
  end

  it "accepts a magic value longer than its token text, bounded by the unfolded limit" do
    long = "/some/long/dir/" * 40
    token = Iyi::DiagnosticRenderedToken.new(0, 8, "MAGIC_FILE", "__FILE__", "Crystal", Base64.strict_encode(long.to_slice))
    token.value_base64.should eq(Base64.strict_encode(long.to_slice))
    Iyi::DiagnosticRenderedToken.value_bound("MAGIC_FILE", "__FILE__").should eq(Iyi::DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i32)
    Iyi::DiagnosticRenderedToken.value_bound("STRING", "\"ab\"").should eq(4)
  end

  it "refuses a value on STRING_CONTINUATION" do
    expect_raises(ArgumentError, "rendered value on a non-string token") do
      Iyi::DiagnosticRenderedToken.new(0, 4, "STRING_CONTINUATION", "\\\n  ", "Crystal", Base64.strict_encode(" ".to_slice))
    end
  end

  it "accepts a delimiter on STRING_CONTINUATION and the array delimiters, refuses it on SPACE" do
    delimiter = Iyi::DiagnosticRenderedDelimiter.new("STRING", "\"", "\"", true, 0)
    Iyi::DiagnosticRenderedToken.new(3, 7, "STRING_CONTINUATION", "\\\n   ", "Crystal", nil, delimiter).token_kind.should eq("STRING_CONTINUATION")
    %w(STRING_ARRAY_START SYMBOL_ARRAY_START STRING_ARRAY_END).each do |kind|
      Iyi::DiagnosticRenderedToken.new(0, 3, kind, "%w(", "Crystal", nil, delimiter).token_kind.should eq(kind)
    end
    expect_raises(ArgumentError, "rendered delimiter on a non-delimiter token") do
      Iyi::DiagnosticRenderedToken.new(0, 1, "SPACE", " ", "Crystal", nil, delimiter)
    end
  end

  it "accepts the backslash-newline flag on SPACE only" do
    Iyi::DiagnosticRenderedToken.new(0, 2, "SPACE", " \n", "Crystal", nil, nil, true).passed_backslash_newline.should eq(true)
    expect_raises(ArgumentError, "backslash-newline flag on a non-space token") do
      Iyi::DiagnosticRenderedToken.new(0, 4, "STRING_CONTINUATION", "\\\n  ", "Crystal", nil, nil, true)
    end
  end
end

describe "S1 LiteralValue producer" do
  it "is appended to the macro producer enum and parses by name" do
    Iyi::DiagnosticMacroProducer.parse("LiteralValue").should eq(Iyi::DiagnosticMacroProducer::LiteralValue)
    Iyi::DiagnosticMacroProducer::LiteralValue.value.should eq(Iyi::DiagnosticMacroProducer::ArtifactSemanticRenderer.value + 1)
  end
end

describe "S1 TypeSugar additions" do
  it "appends the enum values" do
    Iyi::DiagnosticTypeSugar::StringArray.value.should eq(10)
    Iyi::DiagnosticTypeSugar::SymbolArray.value.should eq(11)
    Iyi::DiagnosticTypeSugarResult::String.value.should eq(8)
    Iyi::DiagnosticTypeSugarResult::Symbol.value.should eq(9)
  end

  it "builds StringArray only from a percent-array opener, and SymbolArray from %i" do
    string_sugar = Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
      [percent_witness("STRING_ARRAY_START", "%w(")], Iyi::DiagnosticTypeSugarResult::String, 0)
    string_sugar.rendered_text.should eq("String")
    Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
      [percent_witness("STRING_ARRAY_START", "%W[")], Iyi::DiagnosticTypeSugarResult::String, 0)
    Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::SymbolArray,
      [percent_witness("SYMBOL_ARRAY_START", "%i<")], Iyi::DiagnosticTypeSugarResult::Symbol, 0)
  end

  it "refuses a StringArray with the wrong opener, token, result, index or witness count" do
    expect_raises(ArgumentError, "invalid type-sugar derivation") do
      Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
        [percent_witness("SYMBOL_ARRAY_START", "%i(")], Iyi::DiagnosticTypeSugarResult::String, 0)
    end
    expect_raises(ArgumentError, "invalid type-sugar derivation") do
      Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
        [percent_witness("STRING_ARRAY_START", "%w(")], Iyi::DiagnosticTypeSugarResult::Symbol, 0)
    end
    expect_raises(ArgumentError, "invalid type-sugar derivation") do
      Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
        [percent_witness("STRING_ARRAY_START", "%w(")], Iyi::DiagnosticTypeSugarResult::String, 1)
    end
    expect_raises(ArgumentError, "invalid type-sugar derivation") do
      Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
        [percent_witness("STRING_ARRAY_START", "%w("), percent_witness("STRING_ARRAY_START", "%w(")],
        Iyi::DiagnosticTypeSugarResult::String, 0)
    end
  end

  it "refuses a non-percent opener as a witness token" do
    expect_raises(ArgumentError, "invalid observed type-syntax token") do
      percent_witness("STRING_ARRAY_START", "%w")
    end
    expect_raises(ArgumentError, "invalid observed type-syntax token") do
      percent_witness("STRING_ARRAY_START", "%wx")
    end
    expect_raises(ArgumentError, "invalid observed type-syntax token") do
      percent_witness("IDENT", "%w(")
    end
  end
end

describe "S1 QuotedName" do
  it "exposes its fields and anchors only as a Name in its own context" do
    derived = quoted
    derived.valid_for_anchor?("Name", "named_entry").should eq(true)
    derived.valid_for_anchor?("Name", "method_name").should eq(false)
    derived.as(Iyi::DiagnosticOrigin::DerivedName).producer_context.should eq("named_entry")
    derived.as(Iyi::DiagnosticOrigin::DerivedName).rendered_text.should eq("abc")
  end

  it "accepts a method_name context and a CONST spelling" do
    quoted(context: "method_name", text: "bar").as(Iyi::DiagnosticOrigin::DerivedName).producer_context.should eq("method_name")
    quoted(text: "Foo").as(Iyi::DiagnosticOrigin::DerivedName).rendered_text.should eq("Foo")
  end

  it "round-trips byte-equal through JSON with an exact key set" do
    text = quoted.to_json
    JSON.parse(text).as_h.keys.sort.should eq(
      %w(context derivation_kind input_bytesize input_sha256 kind lexical_mode literal_end literal_start rendered_text))
    Iyi::DiagnosticOrigin.from_json(JSON.parse(text)).to_json.should eq(text)
  end

  it "refuses an extra JSON key" do
    object = JSON.parse(quoted.to_json).as_h
    object["extra"] = JSON::Any.new("x")
    expect_raises(ArgumentError, "invalid diagnostic origin fields") do
      Iyi::DiagnosticOrigin.from_json(JSON::Any.new(object))
    end
  end

  it "refuses text that needs quotes or is not a name" do
    ["a b", "bar?", "", "_", "1a", "a-b", "é"].each do |text|
      expect_raises(ArgumentError, "invalid quoted name") { quoted(text: text) }
    end
  end

  it "refuses a context, digest, mode or span that is wrong" do
    expect_raises(ArgumentError, "invalid quoted name") { quoted(context: "path_segment") }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(sha: literal_model_sha("x").upcase) }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(sha: "abc") }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(mode: "Other") }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(start: -1) }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(finish: 11) }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(start: 3, finish: 3) }
    expect_raises(ArgumentError, "invalid quoted name") { quoted(finish: 4) }
  end
end
