require "./parser"

module Iyi
  # One path of bound text. Offsets are byte offsets into the text.
  #
  # `before` and `after` are the bytes either side of the whole path. `after_first`
  # is the byte after its first segment.
  record BoundPathOccurrence, start : Int32, finish : Int32, names : Array(String),
    before : UInt8?, after_first : UInt8?, after : UInt8?

  # Which paths a bound rewrite touches. `DiagnosticBoundRecipe` asks here for its
  # token rewrites and `tool bind` asks here for its text rewrites, so a build with
  # diagnostic capture and one without rewrite the same paths.
  module BoundPathRules
    # `Root::X` for the root `Root`. A path that is the root itself is not rooted
    # at it, and neither is a global `::Root::X` or an interior `Other::Root::X`.
    def self.rooted_at?(path : BoundPathOccurrence, segments : Array(String)) : Bool
      path.names.size > segments.size && path.names[0, segments.size] == segments && !continued_before?(path)
    end

    # A path whose first segment is the bound name *name*.
    def self.headed_by?(path : BoundPathOccurrence, name : String) : Bool
      path.names[0] == name && !continued_before?(path) && !identifier_byte_at?(path.after_first)
    end

    # The single-segment path *name*, with no `::` neighbour.
    def self.alias_of?(path : BoundPathOccurrence, name : String) : Bool
      path.names.size == 1 && path.names[0] == name && !continued_before?(path) && !scope_or_identifier_at?(path.after)
    end

    # The whole path *segments*, with no `::` neighbour.
    def self.exactly?(path : BoundPathOccurrence, segments : Array(String)) : Bool
      path.names == segments && !continued_before?(path) && !scope_or_identifier_at?(path.after)
    end

    # A name does not start right after `:` or an identifier byte.
    private def self.continued_before?(path : BoundPathOccurrence) : Bool
      byte = path.before
      return false unless byte
      byte == 0x3A_u8 || identifier_byte?(byte)
    end

    private def self.identifier_byte_at?(byte : UInt8?) : Bool
      byte ? identifier_byte?(byte) : false
    end

    private def self.scope_or_identifier_at?(byte : UInt8?) : Bool
      return false unless byte
      byte == 0x3A_u8 || identifier_byte?(byte)
    end

    private def self.identifier_byte?(byte : UInt8) : Bool
      byte == 0x5F_u8 ||
        (byte >= 0x30_u8 && byte <= 0x39_u8) ||
        (byte >= 0x41_u8 && byte <= 0x5A_u8) ||
        (byte >= 0x61_u8 && byte <= 0x7A_u8)
    end
  end

  # The paths in a piece of bound text, read by the parser.
  #
  # `tool bind` rewrites names in text it has already printed: a body, a restriction, a
  # parameter, a `fun` line. Searching that text for a name also finds the name inside a
  # string, a regex or a comment, and telling those apart needs the parser: only it knows
  # whether `/` divides or opens a regex, where an interpolation ends, and what a heredoc
  # holds. So the text is parsed, and the paths are the `Path` nodes the parser built,
  # at the byte offsets of the tokens it read them from.
  #
  # Text inside a macro literal is not parsed, so it holds no path. The recipe's token
  # rewrites do not reach it either.
  module BoundPathIndex
    # What the text is, which decides how it is parsed.
    enum Entry
      # A method body.
      Body
      # A value: a field's default, a class variable's or a constant's value.
      Expression
      # A type: a restriction, a return type, a superclass.
      Type
      # One parameter of a signature, a block parameter included.
      Parameter
      # One line of a `lib` body.
      FunLine
    end

    # The paths of *text*, in order. *entry* is tried first and the other entries after
    # it, because a caller holding text does not always know which of them it is. Text
    # that parses as none of them raises: rewriting it by search would be a guess.
    #
    # *parameters* are the parameters of the signature the text belongs to, the block
    # parameter last. A body is read inside a def that declares them, because the parser
    # reads `x = x.abs`, `n -= 1` and `->obj.call` only where `x`, `n` and `obj` are
    # variables. A parameter is read at *index* among them, because a default may name an
    # earlier parameter and a bare `*` must be followed by one.
    def self.paths(text : String, entry : Entry, iyi : Bool,
                   parameters : Array(String) = [] of String, index : Int32? = nil) : Array(BoundPathOccurrence)
      failure = nil
      ([entry] + Entry.values.reject { |other| other == entry }).each do |candidate|
        begin
          before, after = wrapper(candidate, parameters, index)
          return read(text, candidate, iyi, before, after)
        rescue error : CodeError | ArgumentError | InvalidByteSequenceError
          failure ||= error
        end
      end
      raise ArgumentError.new("bound text cannot be read as source: #{failure.try(&.message)}: #{text.inspect}")
    end

    # The source *text* is parsed inside: what stands before it and what stands after it.
    private def self.wrapper(entry : Entry, parameters : Array(String), index : Int32?) : {String, String}
      case entry
      in .body?
        {"def __iyi_bound__(#{parameters.join(", ")})\n", "\nend"}
      in .expression?, .type?
        {"", ""}
      in .parameter?
        earlier = index ? parameters[0, index] : [] of String
        later = index ? parameters[index + 1..] : [] of String
        {"def __iyi_bound__(#{earlier.map { |parameter| "#{parameter}, " }.join}",
         "#{later.map { |parameter| ", #{parameter}" }.join})\nend"}
      in .fun_line?
        {"lib LibIyiBound\n", "\nend"}
      end
    end

    private def self.read(text : String, entry : Entry, iyi : Bool, before : String, after : String) : Array(BoundPathOccurrence)
      parser = Parser.new("#{before}#{text}#{after}")
      parser.iyi = iyi
      parser.enable_diagnostic_name_observations
      if entry.type?
        parser.next_token
        parser.parse_bare_proc_type
        parser.check :EOF
      else
        parser.parse
      end
      occurrences(text, before.bytesize, parser.diagnostic_name_observations)
    end

    # Groups the parser's path-segment observations by the `Path` they belong to.
    private def self.occurrences(text : String, base : Int32,
                                 observations : Array(DiagnosticParsedName)) : Array(BoundPathOccurrence)
      groups = {} of UInt64 => Array(DiagnosticParsedName)
      observations.each do |observation|
        next unless observation.context == "path_segment"
        (groups[observation.owner.object_id] ||= [] of DiagnosticParsedName) << observation
      end

      found = [] of BoundPathOccurrence
      groups.each_value do |segments|
        segments.sort_by!(&.slot.index)
        segments.each_with_index do |segment, index|
          raise ArgumentError.new("parsed path segments are not contiguous") unless segment.slot.index == index
        end
        start = segments.first.input_start - base
        finish = segments.last.input_end - base
        # A name of the wrapper, not of the text.
        next if finish <= 0 || start >= text.bytesize
        raise ArgumentError.new("parsed path crosses the bound text") if start < 0 || finish > text.bytesize
        names = segments.map(&.token_text)
        unless text.byte_slice(start, finish - start) == names.join("::")
          raise ArgumentError.new("parsed path is not written as its segments")
        end
        bytes = text.to_unsafe
        first_end = start + names[0].bytesize
        occurrence = BoundPathOccurrence.new(start, finish, names,
          start > 0 ? bytes[start - 1] : nil,
          first_end < text.bytesize ? bytes[first_end] : nil,
          finish < text.bytesize ? bytes[finish] : nil)
        found << occurrence unless found.includes?(occurrence)
      end

      found.sort_by!(&.start)
      found.each_cons_pair do |earlier, later|
        raise ArgumentError.new("parsed paths overlap") if later.start < earlier.finish
      end
      found
    end
  end
end
