module Iyi
  # The heredoc indentation rule over constituents the parser has already read.
  #
  # This is a pure function. It takes no parser, lexer, or AST, so a replay can
  # apply the same rule to the same pieces, and the result is decided by the
  # arguments alone.
  #
  # A piece is one constituent of a heredoc body in source order. Its value is a
  # STRING token's decoded value, or an interpolated node held as an opaque
  # marker of type `M`. Its line is the token's line as the lexer reports it,
  # which decides where a line ends. Output is the same sequence with the
  # indentation removed: adjacent strings are merged, and markers are returned
  # as the same objects, in order. The input is never mutated.
  #
  # The algorithm is a transcription of `Parser#remove_heredoc_indent`,
  # `Parser#remove_heredoc_from_line`, and the heredoc line check in
  # `Parser#remove_heredoc_indent`. Any change to one must change the other, and
  # a change to the parser's rule must be reflected here before a replay relies
  # on it.
  module HeredocIndent
    # A line that does not begin with `indent` whitespace characters. The message
    # and line match what the parser raises for the same body.
    class Error < Exception
      getter line : Int32
      getter column : Int32

      def initialize(message : String, @line : Int32, @column : Int32 = 1)
        super(message)
      end
    end

    # One constituent of a heredoc body. The value is a string or a marker.
    struct Piece(M)
      getter value : String | M
      getter line : Int32

      def initialize(@value : String | M, @line : Int32)
      end
    end

    # Removes `indent` characters of leading whitespace from each line of the
    # body. Raises `Error` when a line that has a value to strip does not begin
    # with `indent` whitespace characters. Raises `ArgumentError` when `indent`
    # is negative, because the parser never removes indentation in that case.
    def self.remove(pieces : Indexable(Piece(M)), indent : Int32) : Array(String | M) forall M
      raise ArgumentError.new("heredoc indent must not be negative: #{indent}") if indent < 0

      current_line = IO::Memory.new
      remove_indent = true
      result = [] of String | M
      previous_line_number = 0

      pieces.each_with_index do |piece, i|
        value = piece.value
        line_number = piece.line

        this_piece_is_in_new_line = line_number != previous_line_number
        next_piece_is_in_new_line = i == pieces.size - 1 || pieces[i + 1].line != line_number

        if value.is_a?(String)
          if value.in?("\n", "\r\n")
            current_line << value
            if this_piece_is_in_new_line || next_piece_is_in_new_line
              text = current_line.to_s
              text = strip_line(text, indent, line_number - 1) if remove_indent
              append_string result, text
              current_line.clear
              remove_indent = true
            end
          elsif (slash_n = value.starts_with?('\n')) || value.starts_with?("\r\n")
            # The token opens with a newline, so the line before it ends here and
            # the rest of the token starts the next line.
            current_line << (slash_n ? '\n' : "\r\n")
            text = current_line.to_s
            text = strip_line(text, indent, line_number - 1) if remove_indent
            append_string result, text
            current_line.clear
            remove_indent = true
            current_line << value.byte_slice(slash_n ? 1 : 2)
          else
            current_line << value
          end
        else
          if remove_indent
            text = current_line.to_s
            if text.size < indent || !text.each_char.first(indent).all?(&.ascii_whitespace?)
              raise Error.new("heredoc line must have an indent greater than or equal to #{indent}", line_number, 1)
            end
            text = text[indent..-1]
            append_string result, text unless text.empty?
            result << value
            remove_indent = false
            current_line.clear
          else
            unless current_line.empty?
              append_string result, current_line.to_s
              current_line.clear
            end
            result << value
          end
        end

        previous_line_number = line_number
      end

      unless current_line.empty?
        text = current_line.to_s
        text = strip_line(text, indent, pieces.last.line) if remove_indent
        append_string result, text
      end

      result
    end

    # Strips `indent` whitespace characters from a newline-terminated line. A
    # line shorter than `indent` that is only whitespace and its newline becomes
    # a bare newline.
    private def self.strip_line(line : String, indent : Int32, line_number : Int32) : String
      unless line.each_char.first(indent).all?(&.ascii_whitespace?)
        raise Error.new("heredoc line must have an indent greater than or equal to #{indent}", line_number, 1)
      end
      line.size - 1 < indent ? "\n" : line[indent..-1]
    end

    # Appends a string, merging it into the previous string so no two strings
    # are adjacent in the output.
    private def self.append_string(result : Array(T), text : String) : Nil forall T
      last = result.last?
      if last.is_a?(String)
        result[-1] = last + text
      else
        result << text
      end
    end
  end
end
