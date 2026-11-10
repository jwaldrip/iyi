require "../support/syntax"
require "../../src/compiler/iyi/syntax/heredoc_indent"

# A heredoc marker for the pure cases. The function must return this object
# itself, not a copy, and must never look inside it.
class HeredocSpecMarker
  getter id : Int32

  def initialize(@id : Int32)
  end
end

# One call of the parser's own `remove_heredoc_indent` with the pieces it was
# given, the indent, and what it returned or refused with.
record HeredocSpecCall, input : Array(Iyi::HeredocIndent::Piece(Iyi::ASTNode)), indent : Int32,
  output : Array(Iyi::ASTNode)?, refusal : String?

# A parser that records every call to `remove_heredoc_indent` and then runs the
# real method. The pieces it records are the ones the expression parser built,
# so balanced interpolation, nested strings, and nested braces are consumed by
# the parser itself and not reimplemented here.
class HeredocSpecRecordingParser < Iyi::Parser
  getter calls : Array(HeredocSpecCall)

  def initialize(source : String)
    super(source)
    @calls = [] of HeredocSpecCall
  end

  def remove_heredoc_indent(pieces : Array, indent)
    input = pieces.map { |piece| Iyi::HeredocIndent::Piece(Iyi::ASTNode).new(piece.value, piece.line_number) }
    output = begin
      super(pieces, indent)
    rescue ex : SyntaxException
      @calls << HeredocSpecCall.new(input, indent, nil, ex.message.to_s)
      ::raise ex
    end
    @calls << HeredocSpecCall.new(input, indent, output, nil)
    output
  end
end

# What one side does with a heredoc source: the pieces' value, or the refusal
# as its exception message. Exactly one of the two is set.
record HeredocSpecOutcome, value : Array(String | Int32)?, refusal : String?

private def heredoc_piece(value : String | Int32, line : Int32) : Iyi::HeredocIndent::Piece(Int32)
  Iyi::HeredocIndent::Piece(Int32).new(value, line)
end

# The pieces the lexer produces for a heredoc body, and the closer's indent,
# read as `Parser#consume_heredoc` and `Parser#consume_delimiter` read them.
# This flat reader is only valid when an interpolation holds no nested string
# or brace. It refuses to guess when it meets one, so a nested interpolation
# fails loudly here and is covered by the parser recording instead.
private def heredoc_body(source : String) : {Array(Iyi::HeredocIndent::Piece(Int32)), Int32}
  lexer = Lexer.new(source)
  lexer.next_token.type.should eq(Token::Kind::DELIMITER_START)
  newline = lexer.next_token
  newline.type.should eq(Token::Kind::NEWLINE)

  pieces = [] of Iyi::HeredocIndent::Piece(Int32)
  markers = 0
  state = newline.delimiter_state
  token = lexer.next_string_token(state)
  state = token.delimiter_state

  done = false
  indent = 0
  until done
    case token.type
    when Token::Kind::STRING
      pieces << heredoc_piece(token.value.to_s, token.line_number)
      token = lexer.next_string_token(state)
      state = token.delimiter_state
    when Token::Kind::INTERPOLATION_START
      marker_line = nil
      inner = lexer.next_token
      until inner.type == Token::Kind::OP_RCURLY
        if inner.type == Token::Kind::DELIMITER_START || inner.type.to_s.includes?("LCURLY")
          raise "nested #{inner.type} inside an interpolation: use the parser recording, not the flat reader"
        end
        if marker_line.nil? && inner.type != Token::Kind::SPACE && inner.type != Token::Kind::NEWLINE
          marker_line = inner.line_number
        end
        inner = lexer.next_token
      end
      pieces << heredoc_piece(markers, marker_line || raise "interpolation has no expression")
      markers += 1
      token = lexer.next_string_token(state)
      state = token.delimiter_state
    when Token::Kind::DELIMITER_END
      indent = token.delimiter_state.heredoc_indent
      done = true
    else
      raise "unexpected #{token.type} in heredoc body"
    end
  end

  {pieces, indent}
end

# The parser's heredoc value as strings and marker positions: a string
# constituent is its value, and any other expression is the next marker index.
private def parsed_pieces(root : Iyi::ASTNode) : Array(String | Int32)
  interpolation = root.as(Iyi::StringInterpolation)
  result = [] of String | Int32
  markers = 0
  interpolation.expressions.each do |expression|
    if expression.is_a?(Iyi::StringLiteral)
      result << expression.value
    else
      result << markers
      markers += 1
    end
  end
  result
end

# The parser's outcome on a source. Only the refusal this stage can raise is
# captured; any other exception is a finding and propagates.
private def parser_outcome(source : String) : HeredocSpecOutcome
  HeredocSpecOutcome.new(parsed_pieces(parse(source)), nil)
rescue ex : SyntaxException
  HeredocSpecOutcome.new(nil, ex.message.to_s)
end

# The pure function's outcome on the same source, read the way the parser reads it.
private def pure_outcome(source : String) : HeredocSpecOutcome
  pieces, indent = heredoc_body(source)
  HeredocSpecOutcome.new(Iyi::HeredocIndent.remove(pieces, indent), nil)
rescue ex : SyntaxException
  HeredocSpecOutcome.new(nil, ex.message.to_s)
rescue ex : Iyi::HeredocIndent::Error
  HeredocSpecOutcome.new(nil, ex.message.to_s)
end

# The parser and the pure function reach the same outcome on the same source:
# the same value, or the same refusal message. A refusal is compared by message,
# because the parser raises SyntaxException where the pure function raises
# HeredocIndent::Error. Returns the parser's outcome.
private def expect_agreement(source : String) : HeredocSpecOutcome
  parser = parser_outcome(source)
  parser.should eq(pure_outcome(source))
  parser
end

# The parser and the pure function both refuse the same source with the same message.
private def expect_same_refusal(source : String, message : String) : Nil
  expect_raises(SyntaxException, message) { parse(source) }
  pieces, indent = heredoc_body(source)
  expect_raises(Iyi::HeredocIndent::Error, message) { Iyi::HeredocIndent.remove(pieces, indent) }
end

# The parser and the pure function agree on the same source.
private def expect_parity(source : String) : Nil
  pieces, indent = heredoc_body(source)
  expected = Iyi::HeredocIndent.remove(pieces, indent)
  parsed_pieces(parse(source)).should eq(expected)
end

# The parser's recorded output with each marker replaced by its index. A marker
# is recognised by identity, so a nested string literal that is a marker is not
# mistaken for a heredoc string.
private def normalize_parser(output : Array(Iyi::ASTNode), markers : Array(Iyi::ASTNode)) : Array(String | Int32)
  result = [] of String | Int32
  output.each do |node|
    index = markers.index { |marker| marker.same?(node) }
    if index
      result << index
    else
      result << node.as(Iyi::StringLiteral).value
    end
  end
  result
end

# The pure function's output with each marker replaced by its index.
private def normalize_pure(output : Array(String | Iyi::ASTNode), markers : Array(Iyi::ASTNode)) : Array(String | Int32)
  result = [] of String | Int32
  output.each do |item|
    if item.is_a?(String)
      result << item
    else
      index = markers.index { |marker| marker.same?(item) }
      index.should_not be_nil
      result << index.not_nil!
    end
  end
  result
end

# Parses a source with the recording parser and checks the pure function
# against the parser's own `remove_heredoc_indent` call on the same pieces. A
# refusal from that call must be the refusal the parse reports. Returns the
# normalized value, or nil when the call refused.
private def expect_nested_agreement(source : String) : Array(String | Int32)?
  recorder = HeredocSpecRecordingParser.new(source)
  parse_refusal : String? = nil
  begin
    recorder.parse
  rescue ex : SyntaxException
    parse_refusal = ex.message.to_s
  end

  recorder.calls.size.should eq(1)
  call = recorder.calls.first
  markers = call.input.select { |piece| !piece.value.is_a?(String) }.map { |piece| piece.value.as(Iyi::ASTNode) }

  pure_output : Array(String | Iyi::ASTNode)? = nil
  pure_refusal : String? = nil
  begin
    pure_output = Iyi::HeredocIndent.remove(call.input, call.indent)
  rescue ex : Iyi::HeredocIndent::Error
    pure_refusal = ex.message.to_s
  end

  if refusal = call.refusal
    pure_refusal.should eq(refusal)
    parse_refusal.should eq(refusal)
    return nil
  end

  pure_refusal.should be_nil
  parse_refusal.should be_nil
  parser_value = normalize_parser(call.output.not_nil!, markers)
  parser_value.should eq(normalize_pure(pure_output.not_nil!, markers))
  parser_value
end

describe Iyi::HeredocIndent do
  describe "agreement with the parser" do
    it "removes the closer's indent from each line" do
      expect_parity "<<-FOO\n  a\n  b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  a\n  b\n  FOO")).should eq(["a\nb"])
    end

    it "keeps everything when the closer has no indent" do
      expect_parity "<<-FOO\nhello\nFOO"
      parsed_pieces(parse("<<-FOO\nhello\nFOO")).should eq(["hello"])
    end

    it "counts a tab as one indent character" do
      expect_parity "<<-FOO\n\t1\n\tFOO"
      parsed_pieces(parse("<<-FOO\n\t1\n\tFOO")).should eq(["1"])
    end

    it "counts mixed tabs and spaces as characters" do
      expect_parity "<<-FOO\n \t a\n \tb\n \tFOO"
      parsed_pieces(parse("<<-FOO\n \t a\n \tb\n \tFOO")).should eq([" a\nb"])
    end

    it "keeps empty lines" do
      expect_parity "<<-FOO\n  a\n\n  b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  a\n\n  b\n  FOO")).should eq(["a\n\nb"])
    end

    it "keeps whitespace past the indent on a blank line" do
      expect_parity "<<-FOO\n  a\n   \n  b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  a\n   \n  b\n  FOO")).should eq(["a\n \nb"])
    end

    it "turns a blank line shorter than the indent into a bare newline" do
      expect_parity "<<-FOO\n  a\n \n  b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  a\n \n  b\n  FOO")).should eq(["a\n\nb"])
    end

    it "handles a CRLF line ending" do
      expect_parity "<<-XML\r\n  foo\r\n  bar\r\n  XML"
      parsed_pieces(parse("<<-XML\r\n  foo\r\n  bar\r\n  XML")).should eq(["foo\r\nbar"])
    end

    it "counts multi-byte characters, not bytes" do
      expect_parity "<<-FOO\n\t日本\n\tæ\n\tFOO"
      parsed_pieces(parse("<<-FOO\n\t日本\n\tæ\n\tFOO")).should eq(["日本\næ"])
    end

    it "treats an escaped newline as a line break" do
      expect_parity "<<-FOO\n  a\\nb\n  FOO"
      expect_parity "<<-FOO\n  a\\n  b\n  FOO"
    end

    it "does not process escapes or interpolation in a quoted heredoc" do
      expect_parity "<<-'FOO'\n  hello \\n world\n  \#{1}\n  FOO"
      parsed_pieces(parse("<<-'FOO'\n  hello \\n world\n  \#{1}\n  FOO")).should eq(["hello \\n world\n\#{1}"])
    end

    it "keeps interpolations at their boundaries" do
      expect_parity "<<-FOO\n  a\#{1}b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  a\#{1}b\n  FOO")).should eq(["a", 0, "b"])
    end

    it "keeps text after an interpolation on its line" do
      expect_parity "<<-FOO\n  x\#{1}\n  y\n  FOO"
      parsed_pieces(parse("<<-FOO\n  x\#{1}\n  y\n  FOO")).should eq(["x", 0, "\ny"])
    end

    it "handles an interpolation at the start of a line" do
      expect_parity "<<-FOO\n  \#{1}\n  b\n  FOO"
      parsed_pieces(parse("<<-FOO\n  \#{1}\n  b\n  FOO")).should eq([0, "\nb"])
    end

    it "handles adjacent interpolations" do
      expect_parity "<<-FOO\n  \#{1}\#{2}\n  FOO"
      parsed_pieces(parse("<<-FOO\n  \#{1}\#{2}\n  FOO")).should eq([0, 1])
    end

    it "handles an interpolation at the start of an unindented heredoc" do
      expect_parity "<<-FOO\n\#{1}\nb\nFOO"
      parsed_pieces(parse("<<-FOO\n\#{1}\nb\nFOO")).should eq([0, "\nb"])
    end

    it "handles spaces inside an interpolation" do
      expect_parity "<<-FOO\n  a\#{ 1 }b\n  FOO"
    end

    it "keeps a string inside an interpolation whole" do
      source = "<<-FOO\n  a\#{\"x\\ny\"}b\n  FOO"
      expected = Iyi::HeredocIndent.remove([heredoc_piece("  a", 2), heredoc_piece(0, 2), heredoc_piece("b", 2)], 2)
      expected.should eq(["a", 0, "b"])
      root = parse(source).as(Iyi::StringInterpolation)
      root.expressions.size.should eq(3)
      root.expressions[0].as(Iyi::StringLiteral).value.should eq("a")
      root.expressions[1].as(Iyi::StringLiteral).value.should eq("x\ny")
      root.expressions[2].as(Iyi::StringLiteral).value.should eq("b")
    end
  end

  describe "nested strings and braces in an interpolation (parser recording)" do
    it "keeps a closing brace inside a nested string" do
      expect_nested_agreement("<<-FOO\n  a\#{\"x}y\"}b\n  FOO").should eq(["a", 0, "b"])
    end

    it "keeps the braces of a nested block" do
      expect_nested_agreement("<<-FOO\n  a\#{ [1].map { |x| x } }b\n  FOO").should eq(["a", 0, "b"])
    end

    it "keeps a block whose braces span lines" do
      expect_nested_agreement("<<-FOO\n  a\#{[1].map { |x|\n    x }}b\n  FOO").should eq(["a", 0, "b"])
    end

    it "does not dedent a line inside a nested multiline string" do
      expect_nested_agreement("<<-FOO\n  a\#{\n  \"x\n  y\"\n  }b\n  FOO").should eq(["a", 0, "b"])
    end

    it "keeps a line that starts with a brace inside a nested string" do
      expect_nested_agreement("<<-FOO\n  \#{\"\n}\"}\n  FOO").should eq([0])
    end

    it "keeps an escaped quote and a brace inside a nested string" do
      expect_nested_agreement("<<-FOO\n  \#{\"\\\"}\"}b\n  FOO").should eq([0, "b"])
    end

    it "keeps a nested interpolation inside a nested string" do
      expect_nested_agreement("<<-FOO\n  \#{\"a\#{1}b\"}c\n  FOO").should eq([0, "c"])
    end

    it "keeps parentheses that span lines" do
      expect_nested_agreement("<<-FOO\n  a\#{(\n  1\n  )}b\n  FOO").should eq(["a", 0, "b"])
    end

    it "refuses a short line that begins a multiline nested string, as the parser does" do
      expect_nested_agreement("<<-FOO\n \#{\"\n  x\"}\n  FOO").should be_nil
    end
  end

  describe "invalid UTF-8 body bytes" do
    # Each source is compared by outcome. The parser decides whether it succeeds
    # or refuses, and the pure function must reach the same result.
    it "agrees on an invalid byte inside indented content" do
      expect_agreement "<<-FOO\n  a\xFFb\n  FOO"
    end

    it "agrees on an invalid byte at column zero with no indent" do
      expect_agreement "<<-FOO\n\xFFa\nFOO"
    end

    it "agrees on a truncated multi-byte sequence at the end of a line" do
      expect_agreement "<<-FOO\n  a\xC3\n  FOO"
    end

    it "agrees on an invalid byte in the indent region" do
      expect_agreement "<<-FOO\n \xFFa\n  FOO"
    end

    it "agrees on an encoded surrogate code point" do
      expect_agreement "<<-FOO\n  a\xED\xA0\x80b\n  FOO"
    end

    it "agrees on an invalid byte immediately before an interpolation" do
      expect_agreement "<<-FOO\n  \xFF\#{1}\n  b\n  FOO"
    end

    it "agrees on an invalid byte immediately after an interpolation" do
      expect_agreement "<<-FOO\n  a\#{1}\xFF\n  FOO"
    end

    it "agrees on an invalid byte on a blank line" do
      expect_agreement "<<-FOO\n  a\n\xFF\n  b\n  FOO"
    end

    it "agrees on an invalid byte in a quoted heredoc" do
      expect_agreement "<<-'FOO'\n  a\xFFb\n  FOO"
    end
  end

  describe "multiline interpolation" do
    it "agrees on an interpolation that spans lines" do
      outcome = expect_agreement "<<-FOO\n  a\#{\n  1}b\n  FOO"
      outcome.value.should eq(["a", 0, "b"])
    end

    it "agrees on an interpolation that spans lines and closes on its own line" do
      expect_agreement "<<-FOO\n  \#{\n  1\n  }\n  FOO"
    end

    it "agrees on a multiline interpolation between indented lines" do
      expect_agreement "<<-FOO\n  a\n  \#{\n  1}\n  b\n  FOO"
    end

    it "agrees on a multiline interpolation followed by more lines" do
      outcome = expect_agreement "<<-FOO\n  a\#{\n  1\n  }b\n  c\n  FOO"
      outcome.value.should eq(["a", 0, "b\nc"])
    end

    it "agrees on a blank line inside an interpolation" do
      expect_agreement "<<-FOO\n  a\#{\n\n  1}b\n  FOO"
    end

    it "agrees on whitespace and newlines around the expression" do
      expect_agreement "<<-FOO\n  a\#{ \n  1 \n }b\n  FOO"
    end

    it "agrees on a multiline interpolation at zero indent" do
      outcome = expect_agreement "<<-FOO\n\#{\n1}\nb\nFOO"
      outcome.value.should eq([0, "\nb"])
    end

    it "agrees on a multiline interpolation with CRLF line endings" do
      expect_agreement "<<-FOO\r\n  a\#{\r\n  1}b\r\n  FOO"
    end

    it "agrees on a multiline interpolation whose first line is too short for the indent" do
      expect_agreement "<<-FOO\n  a\n \#{\n  1}\n  FOO"
    end
  end

  describe "refusals" do
    it "refuses a line that does not begin with the indent" do
      expect_same_refusal "<<-HERE\n   One\n wrong\n  Zero\n  HERE",
        "heredoc line must have an indent greater than or equal to 2"
      expect_same_refusal "<<-FOO\n  a\n b\n  FOO",
        "heredoc line must have an indent greater than or equal to 2"
    end

    it "refuses non-whitespace in the indent region of a multi-byte line" do
      expect_same_refusal "<<-FOO\n日\n\tFOO",
        "heredoc line must have an indent greater than or equal to 1"
    end

    it "refuses an interpolation that starts a line too short for the indent" do
      expect_same_refusal "<<-HERE\n   One\n \#{1}\n  Zero\n  HERE",
        "heredoc line must have an indent greater than or equal to 2"
    end

    it "reports the line of a refused final line" do
      pieces = [heredoc_piece("  a", 4), heredoc_piece("\n b", 5)]
      error = expect_raises(Iyi::HeredocIndent::Error, "heredoc line must have an indent greater than or equal to 2") do
        Iyi::HeredocIndent.remove(pieces, 2)
      end
      error.line.should eq(5)
    end

    it "reports the line of a refused interpolation" do
      pieces = [heredoc_piece("  a", 2), heredoc_piece("\n ", 3), heredoc_piece(0, 3)]
      error = expect_raises(Iyi::HeredocIndent::Error, "heredoc line must have an indent greater than or equal to 2") do
        Iyi::HeredocIndent.remove(pieces, 2)
      end
      error.line.should eq(3)
    end

    it "refuses a negative indent" do
      expect_raises(ArgumentError, "heredoc indent must not be negative: -1") do
        Iyi::HeredocIndent.remove([heredoc_piece("a", 1)], -1)
      end
    end
  end

  describe "the output model" do
    it "returns an empty body as an empty output" do
      Iyi::HeredocIndent.remove([] of Iyi::HeredocIndent::Piece(Int32), 0).should eq([] of String | Int32)
    end

    it "removes nothing with a zero indent" do
      Iyi::HeredocIndent.remove([heredoc_piece("abc", 2)], 0).should eq(["abc"])
    end

    it "merges strings and keeps markers in order" do
      pieces = [heredoc_piece("  a", 2), heredoc_piece("\n  b", 3), heredoc_piece(7, 4), heredoc_piece("c", 4)]
      Iyi::HeredocIndent.remove(pieces, 2).should eq(["a\nb", 7, "c"])
    end

    it "returns each marker as the same object" do
      first = HeredocSpecMarker.new(1)
      pieces = [Iyi::HeredocIndent::Piece(HeredocSpecMarker).new("  x", 2),
                Iyi::HeredocIndent::Piece(HeredocSpecMarker).new(first, 2),
                Iyi::HeredocIndent::Piece(HeredocSpecMarker).new("\n  y", 3)]
      result = Iyi::HeredocIndent.remove(pieces, 2)
      result.size.should eq(3)
      result[0].should eq("x")
      result[1].as(HeredocSpecMarker).should be(first)
      result[2].should eq("\ny")
    end

    it "does not change its input" do
      pieces = [heredoc_piece("  a", 2), heredoc_piece(0, 2), heredoc_piece("\n  b", 3)]
      before = pieces.map { |piece| {piece.value, piece.line} }
      first = Iyi::HeredocIndent.remove(pieces, 2)
      second = Iyi::HeredocIndent.remove(pieces, 2)
      pieces.map { |piece| {piece.value, piece.line} }.should eq(before)
      first.should eq(second)
    end
  end
end
