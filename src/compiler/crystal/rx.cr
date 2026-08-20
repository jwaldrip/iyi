# iyi: the compiler's own regular expression engine.
#
# The compiler used to reach matching through Crystal's `Regex`, which links
# libpcre2-8. pcre2 sits on Crystal's required-libraries list and iyi means to
# need nothing on it, so matching is owned here. The semantics recorded in
# SPEC.md III.10 and Appendix B decision 17 are RE2's: linear time always, no
# construct whose cost can grow with the subject. That is Go's trade taken
# deliberately, backreferences and lookaround for a guarantee.
#
# Three parts, one file:
#   1. Parser, pattern source to AST.
#   2. Compiler, AST to a Thompson NFA program.
#   3. Pike VM, runs the program while tracking capture slots.
#
# Match extents and captures agree with the pcre2 the compiler used to link, and
# `spec/compiler/crystal/rx_spec.cr` holds that agreement by running both
# engines over the same corpus. Agreement is with pcre2 as the stdlib builds it,
# PCRE2_UTF | PCRE2_UCP, so `\w` reads é as a word character and é|b is not a
# word boundary, because that is what every pattern the compiler used to run saw.
#
# Three places state a reading rather than inherit one:
#
#   Case folding is ASCII. `(?i)` folds A-Z against a-z and nothing else, so
#   `(?i)é` does not match É where pcre2 under UCP would. That is the contract's
#   call, and the alternative, Unicode folding, means either case tables here or
#   leaning on a stdlib internal.
#
#   `\d` is any Unicode number, where pcre2 means \p{Nd} exactly. The stdlib
#   exposes numbers only as \p{Nd} plus \p{Nl} plus \p{No}, so ½ and Ⅴ count here
#   and do not in pcre2. Restricting to ASCII instead would have missed the
#   Arabic-Indic and mathematical digits pcre2 does match, which is the worse
#   miss for a class whose whole point is digits.
#
#   `\v` is the vertical tab character, the escape the contract lists it as,
#   where pcre2 and Perl read `\v` as the vertical whitespace class. Both agree
#   on a VT subject, which is why no spec case separates them. `\V`, the class's
#   complement, is not in the contract's set and is refused.
#
# Anything outside the supported subset raises `SyntaxError` when the pattern
# compiles; refusing loudly beats matching with quietly different semantics.
module Crystal::Rx
  # iyi: `{n,m}` is expanded by repetition at compile time, so the caps are what
  # stand between a pattern and an enormous program. 1000 is RE2's and Go's
  # repeat cap, chosen for the same reason: bounded work, loud refusal.
  MAX_REPEAT =    1000
  MAX_PROG   = 200_000

  class SyntaxError < Exception
    # Byte offset into the pattern source where the refusal happened.
    getter position : Int32

    def initialize(message : String, @position : Int32)
      super(message)
    end
  end

  # One successful match: byte offsets for group 0 and every capturing group.
  struct Match
    getter subject : String

    @slots : Array(Int32)
    @group_count : Int32

    def initialize(@subject : String, @slots : Array(Int32), @group_count : Int32)
    end

    # Capturing groups, excluding group 0.
    def group_count : Int32
      @group_count
    end

    # Byte offset where the group starts, -1 when the group did not participate.
    def begin(group : Int32 = 0) : Int32
      check_group group
      @slots[group * 2]
    end

    # Exclusive byte offset where the group ends, -1 when it did not participate.
    def end(group : Int32 = 0) : Int32
      check_group group
      @slots[group * 2 + 1]
    end

    # The group's text, nil when the group did not participate. A group that
    # matched empty returns "", which is how a caller tells the two apart.
    def [](group : Int32) : String?
      from = self.begin(group)
      to = self.end(group)
      return nil if from < 0 || to < 0
      Rx.byte_slice(@subject, from, to)
    end

    private def check_group(group : Int32) : Nil
      if group < 0 || group > @group_count
        raise IndexError.new("no capture group #{group} in this pattern (0..#{@group_count})")
      end
    end
  end

  # A compiled pattern: an NFA program plus its character class table. Immutable
  # after compilation, so one pattern is safe to match with repeatedly.
  class Pattern
    getter source : String

    @prog : Array(Inst)
    @classes : Array(ClassData)
    @group_count : Int32

    def initialize(@source : String, @prog : Array(Inst), @classes : Array(ClassData), @group_count : Int32)
    end

    def self.compile(source : String, ignore_case : Bool = false) : Pattern
      parser = Parser.new(source, ignore_case)
      root = parser.parse
      prog, classes = Compiler.new.compile(root)
      new(source, prog, classes, parser.group_count)
    end

    # Searches for the leftmost match at or after `start`, which is a byte
    # offset. `^` and `\A` still mean the start of the subject, never `start`,
    # so scanning a subject piece by piece cannot invent line starts.
    def match(subject : String, start : Int32 = 0) : Match?
      # A start past the end is no match, not an error: that is what the stdlib's
      # match_at_byte_index answers, and scanning loops lean on it.
      return nil unless 0 <= start <= subject.bytesize
      slots = VM.new(@prog, @classes, @group_count).run(subject, start)
      return nil unless slots
      Match.new(subject, slots, @group_count)
    end

    def matches?(subject : String, start : Int32 = 0) : Bool
      !match(subject, start).nil?
    end
  end

  def self.match(subject : String, pattern : Pattern) : Match?
    pattern.match(subject)
  end

  def self.matches?(subject : String, pattern : Pattern) : Bool
    pattern.matches?(subject)
  end

  def self.gsub(subject : String, pattern : Pattern, replacement : String) : String
    gsub_impl(subject, pattern) { |m| expand_replacement(m, replacement) }
  end

  def self.gsub(subject : String, pattern : Pattern, &block : Match -> String) : String
    gsub_impl(subject, pattern) { |m| block.call(m) }
  end

  def self.sub(subject : String, pattern : Pattern, replacement : String) : String
    sub_impl(subject, pattern) { |m| expand_replacement(m, replacement) }
  end

  def self.sub(subject : String, pattern : Pattern, &block : Match -> String) : String
    sub_impl(subject, pattern) { |m| block.call(m) }
  end

  def self.scan(subject : String, pattern : Pattern) : Array(Match)
    bytes = subject.to_slice
    size = bytes.size
    found = [] of Match
    pos = 0
    while pos <= size
      m = pattern.match(subject, pos)
      break unless m
      found << m
      from = m.begin(0)
      to = m.end(0)
      if to > from
        pos = to
      elsif from < size
        # An empty match cannot advance the scan by itself, so step one whole
        # character past it. Stepping one byte would split a UTF-8 sequence.
        _, width = decode(bytes, from, size)
        pos = from + width
      else
        break
      end
    end
    found
  end

  # Fields between matches. Two rules keep this identical to the pcre2-backed
  # `String#split(Regex)` this replaces, and both come from what an empty match
  # means: an empty match sitting exactly where the current field starts yields
  # no field at all, which is why a leading empty match and one landing right
  # after a match are both swallowed, and an empty match always advances one
  # whole character so the scan cannot loop. Trailing empty fields are kept.
  # A capturing pattern interleaves its groups after the field they closed, the
  # way the stdlib does, and a group that did not participate contributes
  # nothing rather than an empty field.
  def self.split(subject : String, pattern : Pattern) : Array(String)
    bytes = subject.to_slice
    size = bytes.size
    parts = [] of String
    field = 0
    pos = 0
    while pos < size
      m = pattern.match(subject, pos)
      break unless m
      from = m.begin(0)
      to = m.end(0)
      if to == field
        pos = to + char_width(bytes, to, size)
        next
      end
      parts << byte_slice(subject, field, from)
      field = to
      1.upto(m.group_count) do |group|
        text = m[group]
        parts << text if text
      end
      pos = to
      pos = to + char_width(bytes, to, size) if to == from
    end
    parts << byte_slice(subject, field, size)
    parts
  end

  private def self.gsub_impl(subject : String, pattern : Pattern, &append : Match -> String) : String
    bytes = subject.to_slice
    size = bytes.size
    buf = String::Builder.new
    pos = 0
    while pos <= size
      m = pattern.match(subject, pos)
      break unless m
      from = m.begin(0)
      to = m.end(0)
      buf << byte_slice(subject, pos, from)
      buf << append.call(m)
      if to > from
        pos = to
      elsif from < size
        # Empty match: keep the character sitting here and step past it.
        # Without this, gsub of /b*/ over "abc" would replace forever.
        _, width = decode(bytes, from, size)
        buf << byte_slice(subject, from, from + width)
        pos = from + width
      else
        break
      end
    end
    buf << byte_slice(subject, pos, size)
    buf.to_s
  end

  private def self.sub_impl(subject : String, pattern : Pattern, &append : Match -> String) : String
    m = pattern.match(subject, 0)
    return subject unless m
    buf = String::Builder.new
    buf << byte_slice(subject, 0, m.begin(0))
    buf << append.call(m)
    buf << byte_slice(subject, m.end(0), subject.bytesize)
    buf.to_s
  end

  # `\0` to `\9` name groups and an absent group contributes nothing. `\\` is a
  # literal backslash; any other escaped pair passes through as written, so a
  # replacement carrying Windows paths survives.
  private def self.expand_replacement(m : Match, replacement : String) : String
    return replacement unless replacement.includes?('\\')
    buf = String::Builder.new
    bytes = replacement.to_slice
    size = bytes.size
    i = 0
    while i < size
      b = bytes[i]
      if b == 0x5C && i + 1 < size
        n = bytes[i + 1]
        if 0x30 <= n <= 0x39
          group = (n - 0x30).to_i32
          if group <= m.group_count
            text = m[group]
            buf << text if text
          end
          i += 2
          next
        elsif n == 0x5C
          buf.write_byte 0x5C_u8
          i += 2
          next
        end
      end
      buf.write_byte b
      i += 1
    end
    buf.to_s
  end

  protected def self.byte_slice(subject : String, from : Int32, to : Int32) : String
    return "" if to <= from
    String.new(subject.to_slice[from, to - from])
  end

  # One definition of a word character, shared by `\w` and by the word sense of
  # `\b`. pcre2 compiled with PCRE2_UCP, which is how the stdlib compiles it and
  # therefore how every pattern the compiler used to run behaved, reads a word
  # character as \p{L}, \p{N} or underscore. `Char#alphanumeric?` is exactly
  # \p{L} plus \p{N}, so this needs no tables of its own.
  protected def self.word_char?(c : Char) : Bool
    c.alphanumeric? || c == '_'
  end

  # pcre2's `\s` under UCP is \p{Xps}: the ASCII spaces, NEL, and \p{Z}.
  # `Char#whitespace?` covers all of that except NEL, which is added here.
  protected def self.space_char?(c : Char) : Bool
    c.whitespace? || c == '\u{0085}'
  end

  # pcre2's `\h`, horizontal whitespace, which is what `\h` means in pcre2 and
  # Perl. It is not a hex digit; that reading is Ruby's, and taking it here would
  # have made `\h+` match "1F" where the engine this replaces matches nothing.
  protected def self.horizontal_space_char?(c : Char) : Bool
    case c
    when '\t', ' ', '\u{00A0}', '\u{1680}', '\u{202F}', '\u{205F}', '\u{3000}'
      true
    else
      '\u{2000}' <= c <= '\u{200A}'
    end
  end

  # Bytes in the character at `pos`, or 1 at or past the end so a caller
  # stepping past an empty match at the very end walks off the loop instead of
  # reading out of bounds.
  private def self.char_width(bytes : Bytes, pos : Int32, size : Int32) : Int32
    return 1 if pos >= size
    _, width = decode(bytes, pos, size)
    width
  end

  # Decodes one UTF-8 character. Offsets stay byte offsets while matching is per
  # character, which is what lets `.` and classes mean a character and
  # `Match#begin` mean a byte. A malformed or truncated sequence yields its lead
  # byte and a width of one, so damaged input cannot wedge the loop.
  protected def self.decode(bytes : Bytes, pos : Int32, size : Int32) : {Char, Int32}
    b0 = bytes[pos]
    return {b0.unsafe_chr, 1} if b0 < 0x80
    if b0 >= 0xF0
      width = 4
      mask = 0x07_u8
    elsif b0 >= 0xE0
      width = 3
      mask = 0x0F_u8
    elsif b0 >= 0xC0
      width = 2
      mask = 0x1F_u8
    else
      return {b0.unsafe_chr, 1}
    end
    return {b0.unsafe_chr, 1} if pos + width > size
    codepoint = (b0 & mask).to_i32
    1.upto(width - 1) do |k|
      b = bytes[pos + k]
      return {b0.unsafe_chr, 1} if (b & 0xC0) != 0x80
      codepoint = (codepoint << 6) | (b & 0x3F).to_i32
    end
    {codepoint.unsafe_chr, width}
  end

  # ---------------------------------------------------------------------------
  # Part 1: the parser, pattern source to AST.
  #
  # Recursive descent over bytes, decoding whole characters only where a literal
  # can appear. Positions in errors are byte offsets into the pattern.
  # ---------------------------------------------------------------------------

  private enum Anchor
    LineStart     # ^, and with no multiline mode this is \A
    LineEnd       # $, the end or just before one final newline
    TextStart     # \A
    TextEnd       # \z
    TextEndNl     # \Z
    WordBorder    # \b
    NotWordBorder # \B
  end

  # The built-in sets, read the way pcre2 under PCRE2_UCP reads them, because
  # that is how every pattern the compiler used to run behaved: `\w` is \p{L},
  # \p{N} or underscore, `\s` is \p{Xps}, `\h` is horizontal whitespace, and `\d`
  # is a decimal digit. `\D \W \S \H` are their complements, and the class level
  # negation in `[^...]` composes with them.
  private enum Builtin
    Digit      # \d
    Word       # \w
    Space      # \s
    Horizontal # \h
  end

  private abstract class Node
  end

  # Matches the empty string. Also what a bare `(?i)` leaves behind: a flag
  # change is not an atom, which is why a quantifier after one is refused.
  private class EmptyNode < Node
  end

  private class CharNode < Node
    getter char : Char
    getter? fold : Bool

    def initialize(@char : Char, @fold : Bool)
    end
  end

  # `.`, any character except a newline.
  private class AnyNode < Node
  end

  private class ClassNode < Node
    getter members : Array(ClassData::Member)
    getter? negated : Bool
    getter? fold : Bool

    def initialize(@members : Array(ClassData::Member), @negated : Bool, @fold : Bool)
    end
  end

  private class AssertNode < Node
    getter anchor : Anchor

    def initialize(@anchor : Anchor)
    end
  end

  private class CatNode < Node
    getter items : Array(Node)

    def initialize(@items : Array(Node))
    end
  end

  private class AltNode < Node
    getter alts : Array(Node)

    def initialize(@alts : Array(Node))
    end
  end

  private class GroupNode < Node
    getter body : Node
    getter index : Int32? # nil for a non-capturing group

    def initialize(@body : Node, @index : Int32?)
    end
  end

  private class RepeatNode < Node
    getter body : Node
    getter min : Int32
    getter max : Int32? # nil means unbounded
    getter? lazy : Bool
    getter pos : Int32 # the quantifier's offset, for the expansion cap error

    def initialize(@body : Node, @min : Int32, @max : Int32?, @lazy : Bool, @pos : Int32)
    end
  end

  private class Parser
    getter group_count : Int32

    def initialize(source : String, ignore_case : Bool)
      @bytes = source.to_slice
      @size = source.bytesize
      @pos = 0
      @group_count = 0
      @ignore_case = ignore_case
    end

    def parse : Node
      root = parse_alternation
      # Alternation only stops early at ')', so anything left is unbalanced.
      error "unbalanced parenthesis" if @pos < @size
      root
    end

    private def parse_alternation : Node
      alts = [parse_concat]
      while peek_byte == '|'.ord
        @pos += 1
        alts << parse_concat
      end
      alts.size == 1 ? alts.first : AltNode.new(alts)
    end

    private def parse_concat : Node
      items = [] of Node
      while @pos < @size
        b = @bytes[@pos]
        break if b == '|'.ord || b == ')'.ord
        items << parse_quantified
      end
      items.size == 1 ? items.first : CatNode.new(items)
    end

    private def parse_quantified : Node
      atom = parse_atom
      quant_pos = @pos
      min = 0
      max : Int32? = nil
      case peek_byte
      when '*'.ord
        @pos += 1
        min = 0
        max = nil
      when '+'.ord
        @pos += 1
        min = 1
        max = nil
      when '?'.ord
        @pos += 1
        min = 0
        max = 1
      when '{'.ord
        if pair = try_braces
          min, max = pair
        end
      end
      # try_braces rewinds when the braces are not a quantifier, so an
      # unmoved position means no quantifier followed this atom.
      return atom if @pos == quant_pos

      if atom.is_a?(EmptyNode)
        error "quantifier does not follow a repeatable atom", quant_pos
      end

      lazy = false
      case peek_byte
      when '?'.ord
        @pos += 1
        lazy = true
      when '+'.ord
        # A possessive quantifier is a backtracking control. There is nothing to
        # control here and honouring it would be a lie, so it is refused.
        error "possessive quantifiers are not supported", @pos
      when '*'.ord
        error "quantifier does not follow a repeatable atom", @pos
      end
      RepeatNode.new(atom, min, max, lazy, quant_pos)
    end

    private def parse_atom : Node
      case peek_byte
      when '('.ord
        @pos += 1
        parse_group
      when '['.ord
        parse_class
      when '.'.ord
        @pos += 1
        AnyNode.new
      when '^'.ord
        @pos += 1
        AssertNode.new(Anchor::LineStart)
      when '$'.ord
        @pos += 1
        AssertNode.new(Anchor::LineEnd)
      when '\\'.ord
        parse_escape
      when '*'.ord, '+'.ord, '?'.ord
        error "quantifier does not follow a repeatable atom"
      when '{'.ord
        # A brace that cannot form a quantifier is a literal brace, as in RE2.
        # One that could is a quantifier with nothing to repeat.
        error "quantifier does not follow a repeatable atom" if quantifier_ahead?
        @pos += 1
        CharNode.new('{', @ignore_case)
      else
        c, width = Rx.decode(@bytes, @pos, @size)
        @pos += width
        CharNode.new(c, @ignore_case)
      end
    end

    # '(' is already consumed. Everything past `(?` that is not `:` or an `i`
    # flag is a construct this engine refuses by design.
    private def parse_group : Node
      if peek_byte == '?'.ord
        @pos += 1
        case peek_byte
        when ':'.ord
          @pos += 1
          parse_group_body
        when 'i'.ord
          parse_inline_fold
        when '='.ord, '!'.ord
          error "lookahead is not supported"
        when '<'.ord
          nxt = peek_byte_at(1)
          error "lookbehind is not supported" if nxt == '='.ord || nxt == '!'.ord
          error "named groups are not supported"
        when '\''.ord, 'P'.ord
          error "named groups are not supported"
        when '>'.ord
          error "atomic groups are not supported"
        when '('.ord
          error "conditionals are not supported"
        when 'R'.ord, '&'.ord, '+'.ord
          error "recursion is not supported"
        when 'C'.ord
          error "callouts are not supported"
        else
          b = peek_byte
          error "recursion is not supported" if 0x30 <= b <= 0x39
          error "unsupported group construct after (?"
        end
      else
        @group_count += 1
        index = @group_count
        GroupNode.new(parse_group_body, index)
      end
    end

    # A flag set inside a group ends at that group's closing parenthesis, which
    # is pcre2's rule, so every group body saves and restores the fold flag.
    private def parse_group_body : Node
      saved = @ignore_case
      body = parse_alternation
      error "missing closing parenthesis" unless peek_byte == ')'.ord
      @pos += 1
      @ignore_case = saved
      body
    end

    private def parse_inline_fold : Node
      while peek_byte == 'i'.ord
        @pos += 1
      end
      terminator = peek_byte
      unless terminator == ')'.ord || terminator == ':'.ord
        # Only `i` exists here. `(?m)`, `(?s)`, `(?-i)` and friends would change
        # what anchors and `.` mean, and none of that is in the supported set.
        error "unsupported inline flag"
      end
      @pos += 1
      if terminator == ')'.ord
        @ignore_case = true
        EmptyNode.new
      else
        saved = @ignore_case
        @ignore_case = true
        body = parse_alternation
        error "missing closing parenthesis" unless peek_byte == ')'.ord
        @pos += 1
        @ignore_case = saved
        body
      end
    end

    private def parse_class : Node
      @pos += 1 # '['
      negated = false
      if peek_byte == '^'.ord
        negated = true
        @pos += 1
      end
      members = [] of ClassData::Member
      first = true
      while true
        b = peek_byte
        error "unterminated character class" if b < 0
        if b == ']'.ord && !first
          @pos += 1
          break
        end
        first = false
        item = parse_class_item
        if item.is_a?(ClassData::Member)
          members << item
          if peek_byte == '-'.ord && (nxt = peek_byte_at(1)) >= 0 && nxt != ']'.ord
            error "invalid range in character class"
          end
        else
          lo = item
          if peek_byte == '-'.ord && (nxt = peek_byte_at(1)) >= 0 && nxt != ']'.ord
            @pos += 1
            rhs = parse_class_item
            error "invalid range in character class" unless rhs.is_a?(Char)
            error "range out of order in character class" if lo > rhs
            members << ClassData::Member.range(lo, rhs)
          else
            members << ClassData::Member.range(lo, lo)
          end
        end
      end
      ClassNode.new(members, negated, @ignore_case)
    end

    # A class member is either a built-in set or a single character; a character
    # may then become the low end of a range.
    private def parse_class_item : ClassData::Member | Char
      if peek_byte == '\\'.ord
        @pos += 1
        b = peek_byte
        error "trailing backslash in character class" if b < 0
        case b
        when 'n'.ord then @pos += 1; '\n'
        when 't'.ord then @pos += 1; '\t'
        when 'r'.ord then @pos += 1; '\r'
        when 'f'.ord then @pos += 1; '\f'
        when 'v'.ord then @pos += 1; '\v'
        when '0'.ord
          @pos += 1
          octal_escape
        when 'x'.ord
          @pos += 1
          hex_escape
        when 'b'.ord
          # Inside a class `\b` is a backspace, as in pcre2. The word boundary
          # sense has no meaning where a single character is expected.
          @pos += 1
          8.unsafe_chr
        when 'd'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Digit, false)
        when 'D'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Digit, true)
        when 'w'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Word, false)
        when 'W'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Word, true)
        when 's'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Space, false)
        when 'S'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Space, true)
        when 'h'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Horizontal, false)
        when 'H'.ord then @pos += 1; ClassData::Member.builtin(Builtin::Horizontal, true)
        when 'p'.ord, 'P'.ord
          error "unicode property classes are not supported"
        else
          c, width = Rx.decode(@bytes, @pos, @size)
          error "unsupported escape \\#{c} in character class" if c.ascii_alphanumeric?
          @pos += width
          c
        end
      else
        c, width = Rx.decode(@bytes, @pos, @size)
        @pos += width
        c
      end
    end

    private def parse_escape : Node
      @pos += 1 # backslash
      b = peek_byte
      error "trailing backslash" if b < 0
      case b
      when 'n'.ord then @pos += 1; CharNode.new('\n', @ignore_case)
      when 't'.ord then @pos += 1; CharNode.new('\t', @ignore_case)
      when 'r'.ord then @pos += 1; CharNode.new('\r', @ignore_case)
      when 'f'.ord then @pos += 1; CharNode.new('\f', @ignore_case)
      when 'v'.ord then @pos += 1; CharNode.new('\v', @ignore_case)
      when '0'.ord
        @pos += 1
        CharNode.new(octal_escape, @ignore_case)
      when 'x'.ord
        @pos += 1
        CharNode.new(hex_escape, @ignore_case)
      when 'b'.ord then @pos += 1; AssertNode.new(Anchor::WordBorder)
      when 'B'.ord then @pos += 1; AssertNode.new(Anchor::NotWordBorder)
      when 'A'.ord then @pos += 1; AssertNode.new(Anchor::TextStart)
      when 'z'.ord then @pos += 1; AssertNode.new(Anchor::TextEnd)
      when 'Z'.ord then @pos += 1; AssertNode.new(Anchor::TextEndNl)
      when 'd'.ord then @pos += 1; builtin_class Builtin::Digit, false
      when 'D'.ord then @pos += 1; builtin_class Builtin::Digit, true
      when 'w'.ord then @pos += 1; builtin_class Builtin::Word, false
      when 'W'.ord then @pos += 1; builtin_class Builtin::Word, true
      when 's'.ord then @pos += 1; builtin_class Builtin::Space, false
      when 'S'.ord then @pos += 1; builtin_class Builtin::Space, true
      when 'h'.ord then @pos += 1; builtin_class Builtin::Horizontal, false
      when 'H'.ord then @pos += 1; builtin_class Builtin::Horizontal, true
      when 0x31..0x39
        # A backreference is the one construct that makes matching superlinear.
        # SPEC.md III.10 trades it away; saying so is better than approximating.
        error "backreferences are not supported"
      when 'p'.ord, 'P'.ord
        error "unicode property classes are not supported"
      when 'G'.ord
        error "\\G is not supported"
      when 'K'.ord
        error "\\K is not supported"
      else
        c, width = Rx.decode(@bytes, @pos, @size)
        error "unsupported escape \\#{c}" if c.ascii_alphanumeric?
        @pos += width
        CharNode.new(c, @ignore_case)
      end
    end

    private def builtin_class(kind : Builtin, negated : Bool) : Node
      ClassNode.new([ClassData::Member.builtin(kind, negated)], false, @ignore_case)
    end

    # `\0` takes up to two further octal digits, matching pcre2.
    private def octal_escape : Char
      value = 0
      2.times do
        b = peek_byte
        break if b < 0x30 || b > 0x37
        value = value * 8 + (b - 0x30)
        @pos += 1
      end
      value.unsafe_chr
    end

    private def hex_escape : Char
      value = 0
      count = 0
      while count < 2
        digit = hex_value(peek_byte)
        break if digit < 0
        value = value * 16 + digit
        @pos += 1
        count += 1
      end
      # `\x{...}` lands here with no digits. It is pcre2 syntax outside the
      # supported set, so it is refused rather than half honoured.
      error "malformed \\x escape, only \\xHH is supported" if count == 0
      value.unsafe_chr
    end

    private def hex_value(b : Int32) : Int32
      case b
      when 0x30..0x39 then b - 0x30
      when 0x41..0x46 then b - 0x37
      when 0x61..0x66 then b - 0x57
      else                 -1
      end
    end

    # Reads `{n}`, `{n,}`, `{n,m}` or `{,m}` and rewinds when the braces are
    # something else, which leaves the '{' to be parsed as a literal. pcre2 reads
    # `{,m}` as `{0,m}` and `{,}` as literal text, so this follows it there
    # rather than taking RE2's stricter reading and refusing a pattern pcre2
    # compiles.
    private def try_braces : {Int32, Int32?}?
      saved = @pos
      @pos += 1
      lower = parse_digits
      if peek_byte == ','.ord
        @pos += 1
        upper = parse_digits
        if peek_byte == '}'.ord && (lower >= 0 || upper >= 0)
          @pos += 1
          min = lower < 0 ? 0 : lower
          max = upper < 0 ? nil : upper
          error "numbers out of order in {} quantifier" if max && max < min
          check_repeat_cap min
          check_repeat_cap max if max
          return {min, max}
        end
      elsif lower >= 0 && peek_byte == '}'.ord
        @pos += 1
        check_repeat_cap lower
        return {lower, lower}
      end
      @pos = saved
      nil
    end

    private def quantifier_ahead? : Bool
      i = skip_digits(@pos + 1)
      saw_lower = i > @pos + 1
      saw_upper = false
      if i < @size && @bytes[i] == ','.ord
        j = skip_digits(i + 1)
        saw_upper = j > i + 1
        i = j
      end
      (saw_lower || saw_upper) && i < @size && @bytes[i] == '}'.ord
    end

    private def skip_digits(i : Int32) : Int32
      while i < @size && 0x30 <= @bytes[i] <= 0x39
        i += 1
      end
      i
    end

    private def parse_digits : Int32
      value = 0
      count = 0
      while 0x30 <= (b = peek_byte) <= 0x39
        value = value * 10 + (b - 0x30)
        return 1_000_000 if value >= 1_000_000
        count += 1
        @pos += 1
      end
      count == 0 ? -1 : value
    end

    private def check_repeat_cap(count : Int32) : Nil
      if count > MAX_REPEAT
        error "repeat count #{count} exceeds the #{MAX_REPEAT} limit"
      end
    end

    private def peek_byte : Int32
      @pos < @size ? @bytes[@pos].to_i32 : -1
    end

    private def peek_byte_at(offset : Int32) : Int32
      i = @pos + offset
      i < @size ? @bytes[i].to_i32 : -1
    end

    private def error(message : String, pos : Int32 = @pos) : NoReturn
      raise SyntaxError.new(message, pos)
    end
  end

  # ---------------------------------------------------------------------------
  # Part 2: the compiler, AST to a Thompson NFA program.
  #
  # Straight-line code with Split for choice and Save for capture slots. Split's
  # `a` target is the preferred branch: leftmost-first alternation and greed both
  # come out of which target is explored first, never from scores on states.
  # ---------------------------------------------------------------------------

  private struct Inst
    enum Kind
      Char     # consume one character equal to a's codepoint
      Class    # consume one character inside classes[a]
      Any      # consume one character that is not a newline
      Split    # fork: a preferred, b deferred
      Jmp      # continue at a
      Again    # a loop's back edge: a is the loop's split, b is the loop's exit
      Save     # slots[a] = current position
      Match    # accept
      Bol      # ^
      Eol      # $
      Bot      # \A
      Eot      # \z
      EotNl    # \Z
      WordB    # \b
      NotWordB # \B
    end

    getter kind : Kind
    property a : Int32
    property b : Int32
    getter? fold : Bool

    def initialize(@kind : Kind, @a : Int32 = 0, @b : Int32 = 0, @fold : Bool = false)
    end
  end

  # A character class: a union of members with one overall negation, so `[^\d_]`
  # is the negation of a two member union rather than a rewritten set.
  private struct ClassData
    struct Member
      getter lo : Char
      getter hi : Char
      getter builtin : Builtin?
      getter? negated : Bool

      def initialize(@lo : Char, @hi : Char, @builtin : Builtin?, @negated : Bool)
      end

      def self.range(lo : Char, hi : Char) : Member
        new(lo, hi, nil, false)
      end

      def self.builtin(kind : Builtin, negated : Bool) : Member
        new('\0', '\0', kind, negated)
      end
    end

    getter members : Array(Member)
    getter? negated : Bool
    getter? fold : Bool

    def initialize(@members : Array(Member), @negated : Bool, @fold : Bool)
    end

    def matches?(c : Char) : Bool
      hit = @members.any? { |m| hit?(m, c) }
      # iyi: fold by testing the subject character's other case, never by
      # expanding the class, so `[a-z]` under (?i) still costs one range test.
      # Non-ASCII folding is deliberately absent: Unicode case tables are a
      # dependency-sized liability and this engine exists to shed dependencies.
      if !hit && @fold && c.ascii_letter?
        other = c.ascii_uppercase? ? c + 32 : c - 32
        hit = @members.any? { |m| hit?(m, other) }
      end
      hit != @negated
    end

    private def hit?(m : Member, c : Char) : Bool
      if kind = m.builtin
        inside = case kind
                 when .digit? then c.number?
                 when .word?  then Rx.word_char?(c)
                 when .space? then Rx.space_char?(c)
                 else              Rx.horizontal_space_char?(c)
                 end
        inside != m.negated?
      else
        m.lo <= c <= m.hi
      end
    end
  end

  private class Compiler
    def initialize
      @prog = [] of Inst
      @classes = [] of ClassData
      @repeat_pos = 0
    end

    def compile(root : Node) : {Array(Inst), Array(ClassData)}
      emit Inst::Kind::Save, 0
      node root
      emit Inst::Kind::Save, 1
      emit Inst::Kind::Match
      {@prog, @classes}
    end

    private def node(n : Node)
      case n
      when CatNode
        n.items.each { |item| node item }
      when CharNode
        emit Inst::Kind::Char, n.char.ord, fold: n.fold?
      when AnyNode
        emit Inst::Kind::Any
      when ClassNode
        index = @classes.size
        @classes << ClassData.new(n.members, n.negated?, n.fold?)
        emit Inst::Kind::Class, index
      when AssertNode
        emit anchor_kind(n.anchor)
      when GroupNode
        # Two slots per group, and slots 0 and 1 belong to the whole match.
        if index = n.index
          emit Inst::Kind::Save, index * 2
          node n.body
          emit Inst::Kind::Save, index * 2 + 1
        else
          node n.body
        end
      when AltNode
        alternation(n.alts) { |branch| node branch }
      when RepeatNode
        repeat n
      else
        # EmptyNode: no instructions, it already matches.
      end
    end

    private def alternation(branches : Array(Node), &compile : Node ->)
      jumps = [] of Int32
      last = branches.size - 1
      branches.each_with_index do |branch, i|
        if i < last
          split = emit Inst::Kind::Split
          set_a split, @prog.size # preferred: this branch, in source order
          compile.call branch
          jumps << emit(Inst::Kind::Jmp)
          set_b split, @prog.size # deferred: the branches after it
        else
          compile.call branch
        end
      end
      jumps.each { |j| set_a j, @prog.size }
    end

    # Can this expression match the empty string? An unbounded loop over a body
    # that can decides whether the empty tail round below is compiled.
    private def nullable?(n : Node) : Bool
      case n
      when CharNode, AnyNode, ClassNode then false
      when CatNode                      then n.items.all? { |item| nullable?(item) }
      when AltNode                      then n.alts.any? { |branch| nullable?(branch) }
      when GroupNode                    then nullable?(n.body)
      when RepeatNode                   then n.min == 0 || nullable?(n.body)
      else                                   true # EmptyNode and the assertions
      end
    end

    # Emits only the paths through `n` that consume nothing, assertions included.
    # Never called on an expression that cannot match empty, which is why the
    # consuming nodes are unreachable here.
    private def epsilon(n : Node)
      case n
      when CatNode
        n.items.each { |item| epsilon item }
      when AltNode
        alternation(n.alts.select { |branch| nullable?(branch) }) { |branch| epsilon branch }
      when GroupNode
        if index = n.index
          emit Inst::Kind::Save, index * 2
          epsilon n.body
          emit Inst::Kind::Save, index * 2 + 1
        else
          epsilon n.body
        end
      when RepeatNode
        if n.min == 0
          epsilon n.body if nullable?(n.body)
        else
          n.min.times { epsilon n.body }
        end
      when AssertNode
        emit anchor_kind(n.anchor)
      else
        # EmptyNode: nothing to emit, which is the whole point of it.
      end
    end

    # pcre2 runs one more round of an unbounded loop whose body can match empty,
    # stops because that round consumed nothing, and reports that round's
    # captures: `(a*)*` over "aaa" gives group 1 "" at byte 3, not "aaa". The loop
    # cannot produce the round here, because the machine admits each program
    # counter once per position and the earlier round already holds the ones the
    # body needs. Compiling the body's empty path once more, after the loop, puts
    # the round back without a second thread at any counter, so captures agree
    # while the machine stays linear (SPEC.md III.10).
    private def empty_tail_round(n : RepeatNode)
      split = emit Inst::Kind::Split
      if n.lazy?
        set_b split, @prog.size
        epsilon n.body
        set_a split, @prog.size # lazy would rather not take the round
      else
        set_a split, @prog.size # greedy takes it, as pcre2 does
        epsilon n.body
        set_b split, @prog.size
      end
    end

    private def repeat(n : RepeatNode)
      saved_pos = @repeat_pos
      @repeat_pos = n.pos
      min = n.min
      max = n.max
      if max == min
        min.times { node n.body }
      elsif max.nil?
        if min == 1
          plus n
        else
          min.times { node n.body }
          star n
        end
        empty_tail_round n if nullable?(n.body)
      else
        min.times { node n.body }
        bounded n, max - min
      end
      @repeat_pos = saved_pos
    end

    private def star(n : RepeatNode)
      split = emit Inst::Kind::Split
      if n.lazy?
        set_b split, @prog.size
        node n.body
        back = emit Inst::Kind::Again, split
        set_a split, @prog.size # lazy prefers leaving the loop
      else
        set_a split, @prog.size # greedy prefers another turn through the body
        node n.body
        back = emit Inst::Kind::Again, split
        set_b split, @prog.size
      end
      # A turn that consumed nothing must not re-enter the body, and it must not
      # die either: it continues at the exit, which is the next instruction and
      # is where empty_tail_round lands when the body is nullable. That keeps the
      # empty turn at the priority pcre2 gives it, inside the turn's own subtree
      # rather than behind the loop's exit branch, which is what `(a*?)*` needs.
      set_b back, @prog.size
    end

    private def plus(n : RepeatNode)
      # One mandatory copy with the loop after it, rather than compiling `e e*`
      # and doubling the body.
      body = @prog.size
      node n.body
      split = emit Inst::Kind::Split
      if n.lazy?
        set_a split, @prog.size
        set_b split, body
      else
        set_a split, body
        set_b split, @prog.size
      end
    end

    private def bounded(n : RepeatNode, count : Int32)
      # `{n,m}` becomes n copies and then m-n nested optionals. Nested, not a
      # flat run of `e?`, so leaving early skips every remaining copy at once.
      return if count <= 0
      split = emit Inst::Kind::Split
      if n.lazy?
        set_b split, @prog.size
        node n.body
        bounded n, count - 1
        set_a split, @prog.size
      else
        set_a split, @prog.size
        node n.body
        bounded n, count - 1
        set_b split, @prog.size
      end
    end

    private def anchor_kind(anchor : Anchor) : Inst::Kind
      case anchor
      when .line_start?  then Inst::Kind::Bol
      when .line_end?    then Inst::Kind::Eol
      when .text_start?  then Inst::Kind::Bot
      when .text_end?    then Inst::Kind::Eot
      when .text_end_nl? then Inst::Kind::EotNl
      when .word_border? then Inst::Kind::WordB
      else                    Inst::Kind::NotWordB
      end
    end

    private def emit(kind : Inst::Kind, a : Int32 = 0, b : Int32 = 0, fold : Bool = false) : Int32
      # The cap turns expansion bombs like ((a{1000}){1000}) into a refusal at
      # the offending quantifier instead of a program nothing can hold.
      if @prog.size >= MAX_PROG
        raise SyntaxError.new("compiled pattern exceeds #{MAX_PROG} instructions", @repeat_pos)
      end
      @prog << Inst.new(kind, a, b, fold)
      @prog.size - 1
    end

    private def set_a(i : Int32, v : Int32) : Nil
      inst = @prog[i]
      inst.a = v
      @prog[i] = inst
    end

    private def set_b(i : Int32, v : Int32) : Nil
      inst = @prog[i]
      inst.b = v
      @prog[i] = inst
    end
  end

  # ---------------------------------------------------------------------------
  # Part 3: the Pike VM, running the program while tracking capture slots.
  #
  # One thread list per subject position, threads held in priority order. Two
  # rules produce pcre2's answers without pcre2's worst case:
  #   a Split adds its preferred branch first, so list order is the order a
  #   backtracking engine would explore, and
  #   a pc joins a position's list at most once, so work per position is bounded
  #   by the program and total work is linear in the subject.
  # ---------------------------------------------------------------------------

  private struct Thread
    getter pc : Int32
    getter slots : Array(Int32)

    def initialize(@pc : Int32, @slots : Array(Int32))
    end
  end

  private class VM
    def initialize(@prog : Array(Inst), @classes : Array(ClassData), @group_count : Int32)
      @marks = Array(Int32).new(@prog.size, 0)
      @stamp = 0
      @stack = Array({Int32, Array(Int32)}).new
    end

    # Returns the winning capture slots, or nil when nothing matched.
    def run(subject : String, start : Int32) : Array(Int32)?
      bytes = subject.to_slice
      size = bytes.size
      # Never mutated: Save copies before writing, so every restart can share it.
      initial = Array(Int32).new((@group_count + 1) * 2, -1)

      clist = Array(Thread).new
      nlist = Array(Thread).new
      best : Array(Int32)? = nil

      @stamp += 1
      pos = start
      while pos <= size
        # Unanchored search without a `.*?` prefix: seed one start thread per
        # position, appended behind every survivor so an earlier start always
        # outranks a later one. @stamp still names this position's list, so a
        # seed duplicating a survivor's pc is dropped by the same dedup. Nothing
        # is seeded once a match exists, since a later start could only lose.
        # Seeding at the top of the step rather than the end of the previous one
        # matters for a pattern that opens with an assertion: `\Bo` leaves the
        # list empty at position 0 and still has to be tried further along.
        add_thread(clist, 0, initial, pos, bytes, size) unless best
        break if clist.empty? && best

        if pos < size
          c, width = Rx.decode(bytes, pos, size)
        else
          c = nil
          width = 1
        end

        nlist.clear
        @stamp += 1
        cut = false
        i = 0
        while i < clist.size && !cut
          thread = clist[i]
          inst = @prog[thread.pc]
          case inst.kind
          when .char?
            if c && char_eq?(c, inst.a.unsafe_chr, inst.fold?)
              add_thread nlist, thread.pc + 1, thread.slots, pos + width, bytes, size
            end
          when .class?
            if c && @classes[inst.a].matches?(c)
              add_thread nlist, thread.pc + 1, thread.slots, pos + width, bytes, size
            end
          when .any?
            if c && c != '\n'
              add_thread nlist, thread.pc + 1, thread.slots, pos + width, bytes, size
            end
          else
            # Match. Record it and abandon the rest of this list: those threads
            # are lower priority, so no continuation of theirs can win. Threads
            # already carried forward are higher priority and may still improve
            # on this, which is how /a|ab/ keeps "a" while /ac|a/ takes "ac".
            best = thread.slots.dup
            cut = true
          end
          i += 1
        end

        clist, nlist = nlist, clist
        pos += width
      end
      best
    end

    # Follows control flow eagerly so the step loop only ever sees consumers and
    # Match. Iterative with an explicit stack rather than recursive: a program
    # near the instruction cap can be one long chain of splits, and recursion
    # there would overflow instead of matching.
    private def add_thread(list : Array(Thread), pc : Int32, slots : Array(Int32), pos : Int32, bytes : Bytes, size : Int32) : Nil
      stack = @stack
      stack.clear
      stack.push({pc, slots})
      while entry = stack.pop?
        pc, slots = entry
        next if @marks[pc] == @stamp
        @marks[pc] = @stamp
        inst = @prog[pc]
        case inst.kind
        when .jmp?
          stack.push({inst.a, slots})
        when .again?
          # A loop's back edge. When the loop's split was already expanded at this
          # position, this turn consumed nothing, so re-entering the body could
          # not terminate: continue at the exit instead of dropping the thread.
          # pcre2 ends a loop on a turn that consumed nothing in the same place,
          # which is why the priority comes out the same.
          stack.push({@marks[inst.a] == @stamp ? inst.b : inst.a, slots})
        when .split?
          # Push the deferred branch first so the preferred branch pops first
          # and reaches the list first. Stack order is the priority order.
          stack.push({inst.b, slots})
          stack.push({inst.a, slots})
        when .save?
          # iyi: copy at the point of mutation. The alternative, copying on every
          # Split as the classic Pike VM does, isolates the same writes but
          # allocates per branch instead of per capture and would force a fresh
          # slot array for every restart.
          slots = slots.dup
          slots[inst.a] = pos
          stack.push({pc + 1, slots})
        when .bol?, .bot?
          stack.push({pc + 1, slots}) if pos == 0
        when .eol?, .eot_nl?
          stack.push({pc + 1, slots}) if pos == size || (pos + 1 == size && bytes[pos] == 0x0A)
        when .eot?
          stack.push({pc + 1, slots}) if pos == size
        when .word_b?
          stack.push({pc + 1, slots}) if word_before?(bytes, pos) != word_at?(bytes, pos, size)
        when .not_word_b?
          stack.push({pc + 1, slots}) if word_before?(bytes, pos) == word_at?(bytes, pos, size)
        else
          list << Thread.new(pc, slots)
        end
      end
    end

    private def char_eq?(got : Char, want : Char, fold : Bool) : Bool
      return true if got == want
      # iyi: ASCII-only folding, at match time. Non-ASCII folding is deliberately
      # absent; see ClassData#matches? for why.
      return false unless fold
      if want.ascii_uppercase?
        got == want + 32
      elsif want.ascii_lowercase?
        got == want - 32
      else
        false
      end
    end

    # `\b` compares the word-ness of the characters either side of the position,
    # and the ends of the subject count as non-word, so `\bdog\b` matches "dog"
    # standing alone.
    private def word_at?(bytes : Bytes, pos : Int32, size : Int32) : Bool
      return false unless pos < size
      c, _ = Rx.decode(bytes, pos, size)
      word_char? c
    end

    private def word_before?(bytes : Bytes, pos : Int32) : Bool
      return false unless pos > 0
      i = pos - 1
      # Walk back over UTF-8 continuation bytes to the character's first byte.
      while i > 0 && (bytes[i] & 0xC0) == 0x80
        i -= 1
      end
      c, _ = Rx.decode(bytes, i, pos)
      word_char? c
    end

    private def word_char?(c : Char) : Bool
      Rx.word_char?(c)
    end
  end
end
