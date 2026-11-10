require "../support/syntax"
require "base64"

# The journal of a whole source, lexed the way the parser drives the lexer:
# code through `next_token`, and each string literal's contents through
# `next_string_token` until its closing delimiter. End of file is left out.
private def lex_journal(source : String, iyi : Bool = false) : Array(Iyi::DiagnosticRenderedToken)
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations
  while !(token = lexer.next_token).type.eof?
    next unless token.type.delimiter_start?
    state = token.delimiter_state
    loop do
      break unless lexer.next_string_token(state).type.string?
    end
  end
  lexer.diagnostic_lexical_observations.reject { |observation| observation.token_kind == "EOF" }
end

private def decoded(observation : Iyi::DiagnosticRenderedToken) : Bytes
  Base64.decode(observation.value_base64.not_nil!)
end

describe "Iyi::Lexer diagnostic journal" do
  [{"Crystal", false}, {"Iyi", true}].each do |mode, iyi|
    describe "in #{mode} mode" do
      it "records a plain string with its delimiter and decoded value" do
        observations = lex_journal("\"ab\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "DELIMITER_END"]
        observations.map(&.lexical_mode).should eq [mode, mode, mode]
        observations.map(&.token_text).should eq ["\"", "ab", "\""]
        observations[0].value_base64.should be_nil
        observations[0].delimiter.should eq({"STRING", "\"", "\"", true})
        decoded(observations[1]).should eq "ab".to_slice
        observations[1].delimiter.should eq({"STRING", "\"", "\"", true})
        observations[2].delimiter.should eq({"STRING", "\"", "\"", true})
        observations.map(&.passed_backslash_newline).should eq [false, false, false]
        observations.map(&.invalid_escape).should eq [false, false, false]
      end

      it "records each escape as its own piece with the decoded bytes" do
        observations = lex_journal("\"\\n\\t\\u00e9\\xFF\"", iyi)
        strings = observations.select { |observation| observation.token_kind == "STRING" }
        strings.map { |observation| decoded(observation) }.should eq [
          "\n".to_slice, "\t".to_slice, "\u00e9".to_slice, Bytes[0xff],
        ]
        strings.all? { |observation| !observation.invalid_escape }.should be_true
      end

      it "records an escaped delimiter as the delimiter's own byte" do
        observations = lex_journal("\"a\\\"b\"", iyi)
        strings = observations.select { |observation| observation.token_kind == "STRING" }
        strings.map { |observation| String.new(decoded(observation)) }.should eq ["a", "\"", "b"]
      end

      it "records interpolation markers around the code they wrap" do
        lexer = Iyi::Lexer.new("\"a\#{b}c\"")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        state = lexer.next_token.delimiter_state
        lexer.next_string_token(state)
        lexer.next_string_token(state)
        lexer.next_token
        lexer.next_token
        lexer.next_string_token(state)
        lexer.next_string_token(state)
        observations = lexer.diagnostic_lexical_observations
        observations.size.should eq 7
        observations[0].token_kind.should eq "DELIMITER_START"
        observations[1].token_kind.should eq "STRING"
        observations[2].token_kind.should eq "INTERPOLATION_START"
        observations[2].value_base64.should be_nil
        observations[2].delimiter.should eq({"STRING", "\"", "\"", true})
        observations[3].token_kind.should eq "IDENT"
        observations[5].token_kind.should eq "STRING"
        observations[6].token_kind.should eq "DELIMITER_END"
        observations[6].delimiter.should eq({"STRING", "\"", "\"", true})
        String.new(decoded(observations[1])).should eq "a"
        String.new(decoded(observations[5])).should eq "c"
      end

      it "records a symbol's own value" do
        observations = lex_journal(":foo", iyi)
        observations.map(&.token_kind).should eq ["SYMBOL"]
        String.new(decoded(observations[0])).should eq "foo"
      end

      it "flags an unknown escape as an invalid escape with the character it kept" do
        observations = lex_journal("\"\\q\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "DELIMITER_END"]
        observations[0].invalid_escape.should be_false
        observations[1].invalid_escape.should be_true
        String.new(decoded(observations[1])).should eq "q"
        observations[2].invalid_escape.should be_false
      end

      it "records a percent literal's delimiter with escapes off" do
        observations = lex_journal("%q(a\\nb)", iyi)
        observations.map(&.token_kind).first.should eq "DELIMITER_START"
        observations[0].delimiter.should eq({"STRING", "(", ")", false})
        strings = observations.select { |observation| observation.token_kind == "STRING" }
        strings.all? { |observation| observation.delimiter == {"STRING", "(", ")", false} }.should be_true
        strings.map { |observation| String.new(decoded(observation)) }.join.should eq "a\\nb"
      end

      it "marks the SPACE that follows a backslash newline continuation" do
        observations = lex_journal("\"a\" \\\n\"b\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "DELIMITER_END", "SPACE", "DELIMITER_START", "STRING", "DELIMITER_END"]
        observations.map(&.passed_backslash_newline).should eq [false, false, false, true, false, false, false]
      end

      it "records a string's own backslash newline without repeating the piece after it" do
        observations = lex_journal("\"a\\\nb\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "STRING", "DELIMITER_END"]
        observations[1..2].map { |observation| String.new(decoded(observation)) }.should eq ["a", "b"]
        observations.map(&.passed_backslash_newline).should eq [false, false, false, false]
      end

      it "keeps input offsets exact after a byte order mark" do
        lexer = Iyi::Lexer.new("\uFEFF\"a\"")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        state = lexer.next_token.delimiter_state
        lexer.next_string_token(state)
        lexer.next_string_token(state)
        observations = lexer.diagnostic_lexical_observations
        observations.map { |observation| {observation.input_start, observation.input_end} }.should eq [{3, 4}, {4, 5}, {5, 6}]
        observations.map(&.token_text).should eq ["\"", "a", "\""]
      end

      it "records nothing while the journal is off" do
        lexer = Iyi::Lexer.new("\"ab\"")
        lexer.iyi = iyi
        state = lexer.next_token.delimiter_state
        lexer.next_string_token(state).value.should eq "ab"
        lexer.next_string_token(state).type.delimiter_end?.should be_true
        lexer.diagnostic_lexical_observations.should be_empty
      end

      it "drops the entries of a lookahead that rolls back and keeps those of one that succeeds" do
        lexer = Iyi::Lexer.new("\"a\" b")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        lexer.next_token
        before = lexer.diagnostic_lexical_observations.size
        lexer.lookahead do
          lexer.next_token
          lexer.next_token
          false
        end
        lexer.diagnostic_lexical_observations.size.should eq before
        lexer.lookahead do
          lexer.next_token
          true
        end
        lexer.diagnostic_lexical_observations.size.should eq before + 1
      end
    end
  end
end
