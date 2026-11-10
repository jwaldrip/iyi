require "../support/syntax"

private def number_macro_parse(source : String, var_scopes = [Set(String).new],
                               filename = "/spec/number_macro.cr") : {Iyi::ASTNode, Iyi::Parser}
  parser = Iyi::Parser.new(source, nil, var_scopes)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  {parser.parse, parser}
end

private def number_macro_token(parser : Iyi::Parser, ref : Iyi::DiagnosticReplayTokenRef) : Iyi::DiagnosticRenderedToken
  parser.diagnostic_lexical_observations[ref.ordinal]
end

describe "number and macro literal parser observations" do
  it "records a literal number against its own NUMBER token" do
    source = "1 + 22"
    root, parser = number_macro_parse(source)
    observations = parser.diagnostic_number_observations
    observations.size.should eq(2)
    observations.each { |observation| observation.role.literal?.should be_true }
    token = number_macro_token(parser, observations[1].token)
    token.token_kind.should eq("NUMBER")
    source.byte_slice(token.input_start, token.input_end - token.input_start).should eq("22")
    observations[0].owner.should_not be(observations[1].owner)
  end

  it "records the $n backreference against its token and its call" do
    source = "$1"
    root, parser = number_macro_parse(source)
    observation = parser.diagnostic_number_observations.first
    observation.role.backreference?.should be_true
    observation.call.should be(root)
    token = number_macro_token(parser, observation.token)
    token.token_kind.should eq("GLOBAL_MATCH_DATA_INDEX")
  end

  it "records __LINE__ as a line derivation" do
    root, parser = number_macro_parse("__LINE__")
    observation = parser.diagnostic_number_observations.first
    observation.role.line?.should be_true
    observation.owner.should be(root)
  end

  it "records a signed number split with both token references" do
    ["/spec/number_macro.cr", "/spec/number_macro.iyi"].each do |filename|
      source = "a -1"
      root, parser = number_macro_parse(source, [Set{"a"}], filename)
      signed_observations = parser.diagnostic_signed_number_observations
      signed_observations.size.should eq(1)
      signed = signed_observations.first
      signed.call.should be(root)
      signed_token = number_macro_token(parser, signed.signed)
      unsigned_token = number_macro_token(parser, signed.unsigned)
      source.byte_slice(signed_token.input_start, signed_token.input_end - signed_token.input_start).should eq("-1")
      source.byte_slice(unsigned_token.input_start, unsigned_token.input_end - unsigned_token.input_start).should eq("1")
    end
  end

  it "reads an undeclared name before a signed number as a command argument" do
    root, parser = number_macro_parse("a -1")
    call = root.as(Iyi::Call)
    call.obj.should be_nil
    call.name.should eq("a")
    call.args.size.should eq(1)
    call.args.first.as(Iyi::NumberLiteral).value.should eq("-1")
    parser.diagnostic_signed_number_observations.should be_empty
  end

  it "records each macro literal against its MACRO_LITERAL token" do
    source = "macro f\n  one\n  two\nend"
    root, parser = number_macro_parse(source)
    observations = parser.diagnostic_macro_literal_observations
    observations.size.should be > 0
    observations.each do |observation|
      token = number_macro_token(parser, observation.token)
      token.token_kind.should eq("MACRO_LITERAL")
    end
  end

  it "drops number and macro observations rolled back by a failed lookahead" do
    root, parser = number_macro_parse("1")
    before_numbers = parser.diagnostic_number_observations.size
    before_signed = parser.diagnostic_signed_number_observations.size
    before_macro = parser.diagnostic_macro_literal_observations.size
    parser.lookahead do
      parser.diagnostic_number_observations.size.should eq(before_numbers)
      false
    end
    parser.diagnostic_number_observations.size.should eq(before_numbers)
    parser.diagnostic_signed_number_observations.size.should eq(before_signed)
    parser.diagnostic_macro_literal_observations.size.should eq(before_macro)
  end
end
