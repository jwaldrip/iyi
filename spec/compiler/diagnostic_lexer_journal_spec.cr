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

# A source that begins with a heredoc opener, lexed the way the parser drives
# it: the opener, the NEWLINE that ends its line, then the body through
# `next_string_token` until the closer.
private def lex_heredoc(source : String, iyi : Bool = false) : Array(Iyi::DiagnosticRenderedToken)
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations
  state = lexer.next_token.delimiter_state
  loop do
    token = lexer.next_token
    break if token.type.newline? || token.type.eof?
  end
  loop do
    break unless lexer.next_string_token(state).type.string?
  end
  lexer.diagnostic_lexical_observations.reject { |observation| observation.token_kind == "EOF" }
end

private def decoded(observation : Iyi::DiagnosticRenderedToken) : Bytes
  Base64.decode(observation.value_base64.not_nil!)
end

private def delimiter(kind : String, nest : String, end_delimiter : String, allow_escapes : Bool,
                      heredoc_indent : Int32 = 0) : Iyi::DiagnosticRenderedDelimiter
  Iyi::DiagnosticRenderedDelimiter.new(kind, nest, end_delimiter, allow_escapes, heredoc_indent: heredoc_indent)
end

describe "Iyi::Lexer diagnostic journal" do
  [{"Crystal", false}, {"Iyi", true}].each do |mode, iyi|
    describe "in #{mode} mode" do
      it "records a plain string with its delimiter and decoded value" do
        observations = lex_journal("\"ab\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "DELIMITER_END"]
        observations.map(&.lexical_mode).should eq [mode, mode, mode]
        observations.map(&.token_text).should eq ["\"", "ab", "\""]
        observations.map(&.line).should eq [1, 1, 1]
        observations[0].value_base64.should be_nil
        observations[0].delimiter.should eq(delimiter("STRING", "\"", "\"", true))
        decoded(observations[1]).should eq "ab".to_slice
        observations[1].delimiter.should eq(delimiter("STRING", "\"", "\"", true))
        observations[2].delimiter.should eq(delimiter("STRING", "\"", "\"", true))
        observations.map(&.passed_backslash_newline).should eq [false, false, false]
        observations.map(&.invalid_escape).should eq [false, false, false]
      end

      it "records the line each token starts on, as the lexer reports it" do
        observations = lex_journal("x\ny", iyi)
        observations.map(&.token_kind).should eq ["IDENT", "NEWLINE", "IDENT"]
        observations.map(&.line).should eq [1, 1, 2]

        observations = lex_journal("\"a\nb\"", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "STRING", "STRING", "DELIMITER_END"]
        observations.map(&.line).should eq [1, 1, 2, 2, 2]
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
        observations[2].delimiter.should eq(delimiter("STRING", "\"", "\"", true))
        observations[3].token_kind.should eq "IDENT"
        observations[5].token_kind.should eq "STRING"
        observations[6].token_kind.should eq "DELIMITER_END"
        observations[6].delimiter.should eq(delimiter("STRING", "\"", "\"", true))
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
        observations[0].delimiter.should eq(delimiter("STRING", "(", ")", false))
        strings = observations.select { |observation| observation.token_kind == "STRING" }
        strings.all? { |observation| observation.delimiter == delimiter("STRING", "(", ")", false) }.should be_true
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

      it "records a heredoc opener, its body and its closer with the closer's indentation" do
        observations = lex_heredoc("<<-EOS\n  a\n  EOS\n", iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "NEWLINE", "STRING", "DELIMITER_END"]
        observations.map(&.line).should eq [1, 1, 2, 3]
        observations[0].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 0))
        decoded(observations[2]).should eq "  a".to_slice
        # A body piece carries the state the parser passed, which is the opener's.
        observations[2].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 0))
        observations[3].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 2))
      end

      it "records an indentation of four and an indentation of none" do
        four = lex_heredoc("<<-EOS\n    a\n    EOS\n", iyi)
        four[3].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 4))
        decoded(four[2]).should eq "    a".to_slice

        none = lex_heredoc("<<-EOS\na\nEOS\n", iyi)
        none[3].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 0))
      end

      it "records a quoted heredoc with escapes off" do
        observations = lex_heredoc("<<-'EOS'\n  a\nEOS\n", iyi)
        observations[0].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", false, 0))
        observations.last.delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", false, 0))
      end

      it "records a long identifier as both the nest and the end" do
        observations = lex_heredoc("<<-EXCLUSION_FREE_BODY\n  a\n  EXCLUSION_FREE_BODY\n", iyi)
        observations[0].delimiter.should eq(delimiter("HEREDOC", "EXCLUSION_FREE_BODY", "EXCLUSION_FREE_BODY", true, 0))
        observations.last.delimiter.should eq(delimiter("HEREDOC", "EXCLUSION_FREE_BODY", "EXCLUSION_FREE_BODY", true, 2))
      end

      it "records each of two heredocs on one line with its own identifier and closer" do
        lexer = Iyi::Lexer.new("f(<<-EXCLUSION_FREE_BODY, <<-SECOND_LONG_BODY)\n  x\n  EXCLUSION_FREE_BODY\n  y\n  SECOND_LONG_BODY\n")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        lexer.next_token # f
        lexer.next_token # (
        first = lexer.next_token.delimiter_state
        lexer.next_token # ,
        lexer.next_token # space
        second = lexer.next_token.delimiter_state
        lexer.next_token # )
        lexer.next_token # newline
        loop do
          break unless lexer.next_string_token(first).type.string?
        end
        loop do
          break unless lexer.next_string_token(second).type.string?
        end
        observations = lexer.diagnostic_lexical_observations
        starts = observations.select { |observation| observation.token_kind == "DELIMITER_START" }
        ends = observations.select { |observation| observation.token_kind == "DELIMITER_END" }
        starts.map { |observation| observation.delimiter.not_nil!.end_delimiter }.should eq ["EXCLUSION_FREE_BODY", "SECOND_LONG_BODY"]
        starts.map(&.line).should eq [1, 1]
        ends.map { |observation| observation.delimiter.not_nil!.end_delimiter }.should eq ["EXCLUSION_FREE_BODY", "SECOND_LONG_BODY"]
        ends.map { |observation| observation.delimiter.not_nil!.heredoc_indent }.should eq [2, 2]
        ends.map(&.line).should eq [3, 5]
      end

      it "records the interpolation inside a heredoc body and the closer after it" do
        lexer = Iyi::Lexer.new("<<-EOS\n  a\#{b}\n  EOS\n")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        state = lexer.next_token.delimiter_state
        lexer.next_token # newline
        lexer.next_string_token(state) # "  a"
        lexer.next_string_token(state) # #{
        lexer.next_token               # b
        lexer.next_token               # }
        lexer.next_string_token(state) # closer
        observations = lexer.diagnostic_lexical_observations
        observations.size.should eq 7
        observations.first(4).map(&.token_kind).should eq ["DELIMITER_START", "NEWLINE", "STRING", "INTERPOLATION_START"]
        observations[4].token_kind.should eq "IDENT"
        observations[6].token_kind.should eq "DELIMITER_END"
        observations[6].delimiter.should eq(delimiter("HEREDOC", "EOS", "EOS", true, 2))
        observations.map(&.line).should eq [1, 1, 2, 2, 2, 2, 3]
      end

      it "records nothing while the journal is off, and the closer still carries its indentation" do
        lexer = Iyi::Lexer.new("<<-EOS\n  a\n  EOS\n")
        lexer.iyi = iyi
        state = lexer.next_token.delimiter_state
        lexer.next_token
        lexer.next_string_token(state).value.should eq "  a"
        closer = lexer.next_string_token(state)
        closer.type.delimiter_end?.should be_true
        closer.delimiter_state.heredoc_indent.should eq 2
        lexer.diagnostic_lexical_observations.should be_empty
      end

      it "records nothing while the journal is off, for a plain string" do
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

      it "drops the entries of a heredoc opener that a lookahead rolls back" do
        lexer = Iyi::Lexer.new("f(<<-EOS)\n  a\n  EOS\n")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        lexer.next_token # f
        lexer.lookahead do
          lexer.next_token # (
          lexer.next_token # opener
          false
        end
        lexer.diagnostic_lexical_observations.size.should eq 1
        lexer.next_token # (
        lexer.next_token.delimiter_start?.should be_true
        lexer.diagnostic_lexical_observations.map(&.token_kind).last.should eq "DELIMITER_START"
        lexer.diagnostic_lexical_observations.size.should eq 3
      end
    end
  end
end
