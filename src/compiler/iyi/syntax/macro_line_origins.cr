require "./lexer"

module Iyi
  # The source line each line of an inline macro's expansion was written on.
  #
  # `MacroLineOrigins.of` is a verbatim port of `Program#line_origins_of`
  # (macros/macros.cr). It must give the same result for every input that
  # method accepts, including the inputs a valid expansion never produces:
  # positions out of range, positions inside a UTF-8 character, line 0,
  # invalid bytes, several origins at one position, and pragmas handed over in
  # any insertion order. The replay contract requires that equality, so `of`
  # does no sorting, no validation and no arithmetic of its own. Its
  # `Int32` operations raise exactly where the original's do.
  #
  # Refusing malformed input is not this function's job. `validate` states the
  # refusals for a caller that has the authority to make them, and it is never
  # called from `of`.
  module MacroLineOrigins
    # The expansion line of each origin, as `Program#line_origins_of` computes
    # it. Origins are read in the hash's insertion order, and a later range
    # overwrites an earlier one, exactly as the original does.
    def self.of(source : String, pragmas : Hash(Int32, Array(Lexer::LocPragma))?) : Hash(Int32, Int32)?
      return nil unless pragmas
      starts = [] of {Int32, Int32}
      pragmas.each do |position, list|
        list.each do |pragma|
          starts << {position, pragma.line_number} if pragma.is_a?(Lexer::LocOriginPragma)
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

    # Authority-only refusal of malformed expansions. A caller that owns the
    # refusal runs this before `of`. Nothing in the parser or the interpreter
    # calls it, and `of` does not. It raises `ArgumentError` for:
    #
    # - text that is not UTF-8;
    # - a pragma position outside `0..source.bytesize`;
    # - a pragma position inside a UTF-8 character;
    # - an origin line number below 1.
    #
    # It accepts reversed insertion order and several origins at one position,
    # because `of` defines their result and a valid expansion can carry them.
    def self.validate(source : String, pragmas : Hash(Int32, Array(Lexer::LocPragma))?) : Nil
      return unless pragmas
      unless source.valid_encoding?
        raise ArgumentError.new("macro expansion is not UTF-8 text, so its line origins cannot be checked")
      end

      bytes = source.to_slice
      pragmas.each do |position, list|
        unless 0 <= position <= bytes.size
          raise ArgumentError.new("pragma at byte #{position} is outside the #{bytes.size}-byte expansion")
        end
        if position < bytes.size && (bytes[position] & 0xC0) == 0x80
          raise ArgumentError.new("pragma at byte #{position} falls inside a UTF-8 character")
        end
        list.each do |pragma|
          if pragma.is_a?(Lexer::LocOriginPragma) && pragma.line_number < 1
            raise ArgumentError.new("line origin at byte #{position} is line #{pragma.line_number}: lines start at 1")
          end
        end
      end
      nil
    end
  end
end
