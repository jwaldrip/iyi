require "../support/syntax"
require "base64"

# Lexes a source through `next_token`, and each literal body through `next_string_token`
# until its closer, so the journal holds what the parser's own driving produces.
private def lex_literal_journal(source : String, iyi : Bool = false, filename : String? = nil) : Array(Iyi::DiagnosticRenderedToken)
  lexer = Iyi::Lexer.new(source)
  lexer.filename = filename if filename
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations
  while !(token = lexer.next_token).type.eof?
    next unless token.type.delimiter_start? || token.type.string_array_start? || token.type.symbol_array_start?
    state = token.delimiter_state
    loop do
      kind = lexer.next_string_token(state).type
      break if kind.delimiter_end? || kind.string_array_end? || kind.eof?
    end
  end
  lexer.diagnostic_lexical_observations.reject { |observation| observation.token_kind == "EOF" }
end

# Each token as the parser reads it: kind, value, span and line. Journal on and off must agree.
private def literal_token_stream(source : String, iyi : Bool, journal : Bool) : Array({String, String, Int32, Int32, Int32})
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations if journal
  stream = [] of {String, String, Int32, Int32, Int32}
  while !(token = lexer.next_token).type.eof?
    stream << {token.type.to_s, token.value.inspect, token.input_offset, token.input_end, token.line_number}
    next unless token.type.delimiter_start? || token.type.string_array_start? || token.type.symbol_array_start?
    state = token.delimiter_state
    loop do
      body = lexer.next_string_token(state)
      stream << {body.type.to_s, body.value.inspect, body.input_offset, body.input_end, body.line_number}
      break if body.type.delimiter_end? || body.type.string_array_end?
    end
  end
  stream
end

private def literal_bytes(observation : Iyi::DiagnosticRenderedToken) : Bytes
  Base64.decode(observation.value_base64.not_nil!)
end

private def literal_delimiter(kind : String, nest : String, end_delimiter : String, allow_escapes : Bool) : Iyi::DiagnosticRenderedDelimiter
  Iyi::DiagnosticRenderedDelimiter.new(kind, nest, end_delimiter, allow_escapes, heredoc_indent: 0)
end

private def trivia_token_stream(source : String, iyi : Bool, journal : Bool, docs : Bool, comments : Bool)
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.doc_enabled = docs
  lexer.comments_enabled = comments
  lexer.enable_diagnostic_observations if journal
  stream = [] of {String, String, Int32, Int32, Int32, Int32}
  loop do
    token = lexer.next_token
    stream << {token.type.to_s, token.value.inspect, token.input_offset, token.input_end,
               token.line_number, token.column_number}
    break if token.type.eof?
  end
  stream
end

# The observations start at the source's first byte, end at its last, and each begins where the one before ends.
private def expect_tiled(observations : Array(Iyi::DiagnosticRenderedToken), source : String) : Nil
  observations.first.input_start.should eq 0
  observations.last.input_end.should eq source.bytesize
  observations.each_cons(2) { |pair| pair[0].input_end.should eq pair[1].input_start }
end

describe "Iyi::Lexer literal journal" do
  [{"Crystal", false}, {"Iyi", true}].each do |mode, iyi|
    describe "in #{mode} mode" do
      it "journals a char literal with the UTF-8 of the character it decodes" do
        observations = lex_literal_journal("'\\u{1F600}'", iyi)
        observations.map(&.token_kind).should eq ["CHAR"]
        observations[0].token_text.should eq "'\\u{1F600}'"
        observations[0].input_start.should eq 0
        observations[0].input_end.should eq 11
        observations[0].line.should eq 1
        observations[0].delimiter.should be_nil
        literal_bytes(observations[0]).should eq Bytes[0xF0, 0x9F, 0x98, 0x80]
      end

      it "journals the bytes of plain, escaped and multibyte chars" do
        literal_bytes(lex_literal_journal("'a'", iyi)[0]).should eq Bytes[0x61]
        literal_bytes(lex_literal_journal("'\\n'", iyi)[0]).should eq Bytes[0x0A]
        literal_bytes(lex_literal_journal("'\\''", iyi)[0]).should eq Bytes[0x27]
        literal_bytes(lex_literal_journal("'é'", iyi)[0]).should eq Bytes[0xC3, 0xA9]
      end

      it "journals __FILE__ and __DIR__ with the expansion the parser makes for the same location" do
        filename = iyi ? "magic_probe.iyi" : "magic_probe.cr"
        location = Iyi::Location.new(filename, 1, 1, nil)

        observations = lex_literal_journal("__FILE__", iyi, filename)
        observations.map(&.token_kind).should eq ["__FILE__"]
        observations[0].token_text.should eq "__FILE__"
        observations[0].delimiter.should be_nil
        literal_bytes(observations[0]).should eq Iyi::MagicConstant.expand_file(location).to_slice

        observations = lex_literal_journal("__DIR__", iyi, filename)
        observations.map(&.token_kind).should eq ["__DIR__"]
        observations[0].token_text.should eq "__DIR__"
        literal_bytes(observations[0]).should eq Iyi::MagicConstant.expand_dir(location).to_slice
      end

      it "journals a string continuation as its own span between the pieces it joins" do
        source = "\"a\\\n   b\""
        observations = lex_literal_journal(source, iyi)
        observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "STRING_CONTINUATION", "STRING", "DELIMITER_END"]
        observations.map(&.token_text).should eq ["\"", "a", "\\\n   ", "b", "\""]
        observations.map(&.line).should eq [1, 1, 1, 2, 2]
        expect_tiled(observations, source)

        continuation = observations[2]
        continuation.value_base64.should be_nil
        continuation.delimiter.should eq literal_delimiter("STRING", "\"", "\"", true)
        continuation.passed_backslash_newline.should be_false
        continuation.invalid_escape.should be_false
      end

      it "keeps the whole line break in the continuation and counts every line it crosses" do
        source = "\"a\\\r\n   b\""
        observations = lex_literal_journal(source, iyi)
        observations[2].token_text.should eq "\\\r\n   "
        observations.map(&.line).should eq [1, 1, 1, 2, 2]
        expect_tiled(observations, source)

        source = "\"a\\\n\n  b\""
        observations = lex_literal_journal(source, iyi)
        observations[2].token_text.should eq "\\\n\n  "
        observations.map(&.line).should eq [1, 1, 1, 3, 3]
        expect_tiled(observations, source)
      end

      it "journals the delimiter of %w and %i arrays on their start and end" do
        observations = lex_literal_journal("%w(a)", iyi)
        observations.first.token_kind.should eq "STRING_ARRAY_START"
        observations.first.token_text.should eq "%w("
        observations.first.delimiter.should eq literal_delimiter("STRING_ARRAY", "(", ")", false)
        observations.last.token_kind.should eq "STRING_ARRAY_END"
        observations.last.token_text.should eq ")"
        observations.last.delimiter.should eq literal_delimiter("STRING_ARRAY", "(", ")", false)

        observations = lex_literal_journal("%i(a b)", iyi)
        observations.first.token_kind.should eq "SYMBOL_ARRAY_START"
        observations.first.token_text.should eq "%i("
        observations.first.delimiter.should eq literal_delimiter("SYMBOL_ARRAY", "(", ")", false)
        observations.last.token_kind.should eq "STRING_ARRAY_END"
        observations.last.delimiter.should eq literal_delimiter("SYMBOL_ARRAY", "(", ")", false)
      end

      it "leaves no entries from a lookahead that fails, and records the continuation once when read again" do
        lexer = Iyi::Lexer.new("\"a\\\n b\"")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        state = lexer.next_token.delimiter_state
        lexer.next_string_token(state).type.string?.should be_true
        before = lexer.diagnostic_lexical_observations.size

        lexer.lookahead { lexer.next_string_token(state); false }.should be_false
        lexer.diagnostic_lexical_observations.size.should eq before

        lexer.next_string_token(state).type.string?.should be_true
        lexer.next_string_token(state).type.delimiter_end?.should be_true
        lexer.diagnostic_lexical_observations.map(&.token_kind).should eq ["DELIMITER_START", "STRING", "STRING_CONTINUATION", "STRING", "DELIMITER_END"]
      end

      it "records only actually skipped comments and exact byte spans" do
        source = "x # héllo\r\n# last"
        observations = lex_literal_journal(source, iyi)
        skipped = observations.select { |entry| entry.token_kind == "SKIPPED_COMMENT" }
        skipped.map(&.token_text).should eq ["# héllo\r", "# last"]
        skipped.map(&.line).should eq [1, 2]
        skipped.each do |entry|
          source.byte_slice(entry.input_start, entry.input_end - entry.input_start).should eq entry.token_text
          entry.lexical_mode.should eq mode
          entry.value_base64.should be_nil
          entry.delimiter.should be_nil
        end

        lexer = Iyi::Lexer.new("# visible\nx")
        lexer.iyi = iyi
        lexer.comments_enabled = true
        lexer.enable_diagnostic_observations
        lexer.next_token.type.comment?.should be_true
        lexer.diagnostic_lexical_observations.map(&.token_kind).should eq ["COMMENT"]
      end
      it "uses absolute byte offsets for skipped trivia after a byte order mark" do
        source = "\uFEFF# note\nx"
        observations = lex_literal_journal(source, iyi)
        comment = observations.find { |entry| entry.token_kind == "SKIPPED_COMMENT" }.not_nil!
        comment.input_start.should eq 3
        comment.input_end.should eq 9
        comment.token_text.should eq "# note"
        source.byte_slice(comment.input_start, comment.input_end - comment.input_start).should eq comment.token_text
      end


      it "distinguishes skipped doc comments and leaves returned token streams unchanged" do
        source = "# doc\r\nx # ordinary\n"
        lexer = Iyi::Lexer.new(source)
        lexer.iyi = iyi
        lexer.doc_enabled = true
        lexer.enable_diagnostic_observations
        loop { break if lexer.next_token.type.eof? }
        observations = lexer.diagnostic_lexical_observations
        skipped = observations.select { |entry| entry.token_kind.starts_with?("SKIPPED_") }
        skipped.map(&.token_kind).should eq ["SKIPPED_DOC_COMMENT", "SKIPPED_COMMENT"]
        skipped.map(&.token_text).should eq ["# doc\r", "# ordinary"]
        skipped.each do |entry|
          source.byte_slice(entry.input_start, entry.input_end - entry.input_start).should eq entry.token_text
          entry.lexical_mode.should eq mode
        end
        [{false, false}, {true, false}, {false, true}, {true, true}].each do |docs, comments|
          trivia_token_stream(source, iyi, false, docs, comments).should eq trivia_token_stream(source, iyi, true, docs, comments)
        end
      end

      it "records a location pragma as a single skipped span, not its internal filename tokens" do
        source = "#<loc:\"file.cr\",12,3>x"
        observations = lex_literal_journal(source, iyi)
        observations.map(&.token_kind).should eq ["SKIPPED_LOC_PRAGMA", "IDENT"]
        pragma = observations.first
        pragma.token_text.should eq "#<loc:\"file.cr\",12,3>"
        pragma.input_start.should eq 0
        pragma.input_end.should eq pragma.token_text.bytesize
        pragma.line.should eq 1
        pragma.lexical_mode.should eq mode
        pragma.value_base64.should be_nil
        pragma.delimiter.should be_nil
        expect_tiled(observations, source)
        trivia_token_stream(source, iyi, false, false, false).should eq trivia_token_stream(source, iyi, true, false, false)
      end

      it "rolls back skipped trivia and pragma internals on failed lookahead" do
        source = "#<loc:\"file.cr\",12,3># note\nx"
        lexer = Iyi::Lexer.new(source)
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        lexer.lookahead { lexer.next_token; false }.should be_false
        lexer.diagnostic_lexical_observations.should be_empty
        lexer.next_token
        observations = lexer.diagnostic_lexical_observations
        observations.map(&.token_kind).should eq ["SKIPPED_LOC_PRAGMA", "SKIPPED_COMMENT", "NEWLINE"]
        observations[0].token_text.should eq "#<loc:\"file.cr\",12,3>"
        observations[1].token_text.should eq "# note"
        expect_tiled(observations, source.byte_slice(0, observations.last.input_end))
      end

      it "returns the same token stream with the journal on and off" do
        [
          "'\\u{1F600}' 'a' '\\''",
          "__FILE__ __DIR__",
          "\"a\\\n   b\"",
          "\"a\\\r\n   b\"",
          "%w(a b\\ c)",
          "%i(a b)",
          "%W(a\\\n b)",
          "x = \"a\\n\\u00e9\"\ny",
        ].each do |source|
          literal_token_stream(source, iyi, false).should eq literal_token_stream(source, iyi, true)
        end
      end
    end
  end
end
