require "../support/syntax"
require "../../src/compiler/iyi/syntax/heredoc_indent"

# A heredoc marker for the pure cases. The function must return this object
# itself, not a copy, and must never look inside it.
class HeredocSpecMarker
  getter id : Int32

  def initialize(@id : Int32)
  end
end

private def heredoc_piece(value : String | Int32, line : Int32) : Iyi::HeredocIndent::Piece(Int32)
  Iyi::HeredocIndent::Piece(Int32).new(value, line)
end

# The pieces the lexer produces for a heredoc body, and the closer's indent,
# read as `Parser#consume_heredoc` and `Parser#consume_delimiter` read them.
# Each interpolation becomes a marker numbered in source order, at the line of
# the first token after its opening that is neither a space nor a newline.
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

# The parser and the pure function agree on the same source.
private def expect_parity(source : String) : Nil
  pieces, indent = heredoc_body(source)
  expected = Iyi::HeredocIndent.remove(pieces, indent)
  parsed_pieces(parse(source)).should eq(expected)
end

# The parser and the pure function both refuse the same source with the same message.
private def expect_same_refusal(source : String, message : String) : Nil
  expect_raises(SyntaxException, message) { parse(source) }
  pieces, indent = heredoc_body(source)
  expect_raises(Iyi::HeredocIndent::Error, message) { Iyi::HeredocIndent.remove(pieces, indent) }
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
