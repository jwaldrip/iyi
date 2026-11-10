require "../spec_helper"
require "../../src/compiler/iyi/syntax/macro_line_origins"

# The frozen original: `Program#line_origins_of` exactly as it stands in HEAD
# (src/compiler/iyi/macros/macros.cr), before macros.cr began calling the
# port. Once the call site is the port, nothing in src computes the original,
# so this copy is the only oracle the replay contract has. The port is checked
# against it, never against itself. Keep it verbatim: an edit here changes what
# the differential proves.
def frozen_macro_line_origins(source : String, pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma))?) : Hash(Int32, Int32)?
  return nil unless pragmas
  starts = [] of {Int32, Int32}
  pragmas.each do |position, list|
    list.each do |pragma|
      starts << {position, pragma.line_number} if pragma.is_a?(Iyi::Lexer::LocOriginPragma)
    end
  end
  return nil if starts.empty?

  # The expansion's line at each byte where a line starts.
  line_starts = [0]
  source.each_byte.with_index { |byte, index| line_starts << index + 1 if byte == '\n'.ord }
  origins = {} of Int32 => Int32
  starts.each_with_index do |(position, origin), index|
    first = (line_starts.bsearch_index { |start| start > position } || line_starts.size)
    last = if following = starts[index + 1]?
             (line_starts.bsearch_index { |start| start > following[0] } || line_starts.size) - 1
           else
             line_starts.size
           end
    (first..last).each { |line| origins[line] = origin + line - first }
  end
  origins
end

record LineOriginsAnswer, mapped : Hash(Int32, Int32)?, error : String?

# What a call answers: its hash, or the class of the exception it raised.
def line_origins_outcome(& : -> Hash(Int32, Int32)?) : LineOriginsAnswer
  LineOriginsAnswer.new(yield, nil)
rescue ex : Exception
  LineOriginsAnswer.new(nil, ex.class.name)
end

def line_origin_pragma(line : Int32) : Iyi::Lexer::LocPragma
  Iyi::Lexer::LocOriginPragma.new(line)
end

def line_pop_pragma : Iyi::Lexer::LocPragma
  Iyi::Lexer::LocPopPragma.new
end

def line_pragma_map(*entries : {Int32, Array(Iyi::Lexer::LocPragma)}) : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  hash = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  entries.each { |position, list| hash[position] = Array(Iyi::Lexer::LocPragma).new(list.size) { |index| list[index] } }
  hash
end

# The same pragmas, inserted in the reverse order.
def line_reversed_insertion(pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma))) : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  reversed = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  pragmas.to_a.reverse_each { |(position, list)| reversed[position] = list }
  reversed
end

# The same pragmas, inserted in a random order drawn from *random*.
def line_shuffled_insertion(pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma)), random : Random) : Hash(Int32, Array(Iyi::Lexer::LocPragma))
  shuffled = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  pragmas.to_a.shuffle(random).each { |(position, list)| shuffled[position] = list }
  shuffled
end

# The port's answer must equal the frozen original's for the same arguments,
# including the exception class when either one raises.
def line_expect_same_as_reference(source : String, pragmas : Hash(Int32, Array(Iyi::Lexer::LocPragma))?, file = __FILE__, line = __LINE__) : LineOriginsAnswer
  ported = line_origins_outcome { Iyi::MacroLineOrigins.of(source, pragmas) }
  frozen = line_origins_outcome { frozen_macro_line_origins(source, pragmas) }
  unless ported == frozen
    fail "port #{ported.inspect} differs from the frozen original #{frozen.inspect} for source #{source.inspect}, pragmas #{pragmas.inspect}", file, line
  end
  ported
end

LINE_RANDOM_ORIGINS = [0, 1, 2, 3, 7, 40, -3, Int32::MAX - 1, Int32::MAX] of Int32
LINE_RANDOM_BYTES   = [0x0a_u8, 0x61_u8, 0x62_u8, 0xc3_u8, 0xa9_u8, 0xff_u8, 0x00_u8, 0x80_u8, 0x0a_u8] of UInt8

# Arbitrary bytes (valid or not), positions from before the start to past the
# end, several origins at one position, and mixed non-origin pragmas.
def line_random_case(random : Random) : {String, Hash(Int32, Array(Iyi::Lexer::LocPragma))}
  size = random.rand(0..40)
  source = String.new(Bytes.new(size) { |_| LINE_RANDOM_BYTES.sample(random) })
  pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
  random.rand(0..4).times do
    list = [] of Iyi::Lexer::LocPragma
    random.rand(0..3).times do
      list << (random.rand(4) == 0 ? line_pop_pragma : line_origin_pragma(LINE_RANDOM_ORIGINS.sample(random)))
    end
    pragmas[random.rand(-2..size + 2)] = list
  end
  {source, pragmas}
end

describe "Iyi::MacroLineOrigins" do
  describe "against the frozen original Program#line_origins_of" do
    it "answers nil for nil pragmas and for pragmas without an origin" do
      line_expect_same_as_reference("a\nb\n", nil).mapped.should be_nil
      line_expect_same_as_reference("a\nb\n", {} of Int32 => Array(Iyi::Lexer::LocPragma)).mapped.should be_nil
      line_expect_same_as_reference("a\nb\n", line_pragma_map({0, [line_pop_pragma]})).mapped.should be_nil
    end

    it "maps a single origin from the start, and across a block of lines" do
      ported = line_expect_same_as_reference("a\nb\n", line_pragma_map({0, [line_origin_pragma(10)]}))
      ported.mapped.should eq({1 => 10, 2 => 11, 3 => 12})
    end

    it "ends one origin's range at the line that holds the next origin" do
      ported = line_expect_same_as_reference("x\ny\nz\n", line_pragma_map({0, [line_origin_pragma(5)]}, {2, [line_origin_pragma(40)]}))
      ported.mapped.should eq({1 => 5, 2 => 40, 3 => 41, 4 => 42})
    end

    it "maps production-shaped text with a generated line and a block after it" do
      source = "puts 1\n  raise \"x\"\nputs 3\n"
      ported = line_expect_same_as_reference(source, line_pragma_map({0, [line_origin_pragma(10)]}, {7, [line_origin_pragma(40)]}))
      ported.mapped.should eq({1 => 10, 2 => 40, 3 => 41, 4 => 42})
    end

    it "gives a same-line pair the origin of the later position" do
      ported = line_expect_same_as_reference("abc\nd", line_pragma_map({0, [line_origin_pragma(3)]}, {2, [line_origin_pragma(9)]}))
      ported.mapped.should eq({1 => 9, 2 => 10})
    end

    it "takes the later record in the list for several origins at one position" do
      ported = line_expect_same_as_reference("a\n", line_pragma_map({0, [line_origin_pragma(3), line_origin_pragma(9)]}))
      ported.mapped.should eq({1 => 9, 2 => 10})
    end

    it "gives equal-position records in the same list the same treatment as the original" do
      ported = line_expect_same_as_reference("a\nb", line_pragma_map({0, [line_origin_pragma(9), line_origin_pragma(3)]}))
      ported.mapped.should eq({1 => 3, 2 => 4})
    end

    it "gives blank lines the numbering of the range they sit in" do
      ported = line_expect_same_as_reference("a\n\n\nb", line_pragma_map({0, [line_origin_pragma(1)]}, {4, [line_origin_pragma(20)]}))
      ported.mapped.should eq({1 => 1, 2 => 2, 3 => 3, 4 => 20})
    end

    it "counts line starts in bytes across multi-byte characters" do
      ported = line_expect_same_as_reference("é\nü", line_pragma_map({0, [line_origin_pragma(1)]}, {3, [line_origin_pragma(4)]}))
      ported.mapped.should eq({1 => 1, 2 => 4})
    end

    it "maps a position inside a character exactly as the original does" do
      ported = line_expect_same_as_reference("é\n", line_pragma_map({1, [line_origin_pragma(5)]}))
      ported.mapped.should eq({1 => 5, 2 => 6})
    end

    it "maps invalid UTF-8 bytes exactly as the original does" do
      source = String.new(Bytes[0xff, 0x0a, 0xc3])
      ported = line_expect_same_as_reference(source, line_pragma_map({1, [line_origin_pragma(2)]}))
      ported.mapped.should eq({1 => 2, 2 => 3})
    end

    it "maps invalid UTF-8 bytes with origins inserted out of position order" do
      source = String.new(Bytes[0xff, 0x0a, 0xc3, 0x0a])
      ported = line_expect_same_as_reference(source, line_pragma_map({2, [line_origin_pragma(30)]}, {0, [line_origin_pragma(3)]}))
      ported.mapped.should eq({1 => 3, 2 => 4, 3 => 5})
    end

    it "maps line 0 exactly as the original does" do
      ported = line_expect_same_as_reference("a\nb", line_pragma_map({0, [line_origin_pragma(0)]}))
      ported.mapped.should eq({1 => 0, 2 => 1})
    end

    it "maps a negative position exactly as the original does" do
      ported = line_expect_same_as_reference("a\n", line_pragma_map({-1, [line_origin_pragma(5)]}))
      ported.mapped.should eq({0 => 5, 1 => 6, 2 => 7})
    end

    it "maps a position past the end exactly as the original does" do
      ported = line_expect_same_as_reference("a\n", line_pragma_map({5, [line_origin_pragma(1)]}))
      ported.mapped.should eq({2 => 1})
    end

    it "raises the same OverflowError as the original when a mapped line overflows" do
      ported = line_expect_same_as_reference("a\nb", line_pragma_map({0, [line_origin_pragma(Int32::MAX)]}))
      ported.error.should eq("OverflowError")
    end

    it "answers differently for reversed insertion order, and matches the original for each order" do
      source = "a\nb\nc\n"
      ascending = line_pragma_map({0, [line_origin_pragma(3)]}, {4, [line_origin_pragma(9)]})
      descending = line_reversed_insertion(ascending)

      ported_ascending = line_expect_same_as_reference(source, ascending)
      ported_descending = line_expect_same_as_reference(source, descending)

      ported_ascending.mapped.should eq({1 => 3, 2 => 4, 3 => 9, 4 => 10})
      ported_descending.mapped.should eq({1 => 3, 2 => 4, 3 => 5, 4 => 6})
      ported_ascending.should_not eq(ported_descending)
    end

    it "orders unsorted insertion by insertion, not by position" do
      source = "a\nb\nc\nd\n"
      unsorted = line_pragma_map({4, [line_origin_pragma(40)]}, {0, [line_origin_pragma(10)]}, {2, [line_origin_pragma(20)]})
      sorted = line_pragma_map({0, [line_origin_pragma(10)]}, {2, [line_origin_pragma(20)]}, {4, [line_origin_pragma(40)]})

      line_expect_same_as_reference(source, unsorted).mapped.should eq({1 => 10, 2 => 20, 3 => 21, 4 => 22, 5 => 23})
      line_expect_same_as_reference(source, sorted).mapped.should eq({1 => 10, 2 => 20, 3 => 40, 4 => 41, 5 => 42})
    end

    it "matches the frozen original over random arbitrary bytes, positions and insertion orders" do
      random = Random.new(20261110_u64)
      500.times do
        source, pragmas = line_random_case(random)
        line_expect_same_as_reference(source, pragmas)
        line_expect_same_as_reference(source, line_reversed_insertion(pragmas))
        line_expect_same_as_reference(source, line_shuffled_insertion(pragmas, random))
      end
    end
  end

  describe "determinism" do
    it "answers the same on repeated calls with the same input" do
      source = "a\nb\nc\n"
      pragmas = line_pragma_map({0, [line_origin_pragma(3)]}, {2, [line_origin_pragma(9)]})
      first = Iyi::MacroLineOrigins.of(source, pragmas)
      second = Iyi::MacroLineOrigins.of(source, pragmas)
      first.should eq(second)
      first.should eq({1 => 3, 2 => 9, 3 => 10, 4 => 11})
    end
  end

  describe "authority-only validate" do
    it "accepts a well-formed expansion" do
      Iyi::MacroLineOrigins.validate("a\nb\n", line_pragma_map({0, [line_origin_pragma(10)]}, {2, [line_origin_pragma(40)]}))
    end

    it "accepts nil pragmas and pragmas without an origin" do
      Iyi::MacroLineOrigins.validate("a\n", nil)
      Iyi::MacroLineOrigins.validate("a\n", line_pragma_map({0, [line_pop_pragma]}))
    end

    it "accepts reversed insertion order and several origins at one position" do
      Iyi::MacroLineOrigins.validate("a\nb\nc\n", line_pragma_map({4, [line_origin_pragma(9)]}, {0, [line_origin_pragma(3)]}))
      Iyi::MacroLineOrigins.validate("a\n", line_pragma_map({0, [line_origin_pragma(3), line_origin_pragma(9)]}))
    end

    it "refuses a negative position" do
      expect_raises(ArgumentError, /outside/) do
        Iyi::MacroLineOrigins.validate("a\n", line_pragma_map({-1, [line_origin_pragma(1)]}))
      end
    end

    it "refuses a position past the end of the text" do
      expect_raises(ArgumentError, /outside/) do
        Iyi::MacroLineOrigins.validate("a\n", line_pragma_map({3, [line_origin_pragma(1)]}))
      end
    end

    it "refuses a position inside a UTF-8 character" do
      expect_raises(ArgumentError, /inside a UTF-8 character/) do
        Iyi::MacroLineOrigins.validate("é\n", line_pragma_map({1, [line_origin_pragma(1)]}))
      end
    end

    it "refuses text that is not UTF-8" do
      expect_raises(ArgumentError, /not UTF-8/) do
        Iyi::MacroLineOrigins.validate(String.new(Bytes[0xff, 0x0a]), line_pragma_map({0, [line_origin_pragma(1)]}))
      end
    end

    it "refuses line 0" do
      expect_raises(ArgumentError, /lines start at 1/) do
        Iyi::MacroLineOrigins.validate("a\n", line_pragma_map({0, [line_origin_pragma(0)]}))
      end
    end

    it "is never run by of, which answers the same malformed input" do
      Iyi::MacroLineOrigins.of("a\n", line_pragma_map({0, [line_origin_pragma(0)]})).should eq({1 => 0, 2 => 1})
    end
  end
end
