# Compatibility: Crystal's standard library highlighter does
# `require "compiler/crystal/syntax"` and then names `Lexer` and `Token`
# unqualified inside `Crystal::SyntaxHighlighter`. The compiler's syntax
# bits live at `compiler/iyi/syntax` now, so without this file that
# require cannot find them, and without the aliases the highlighter
# cannot see them.
#
# Parser and SyntaxException are the other two names Crystal programs
# historically used after requiring this path (`Crystal::Parser.parse`).
require "compiler/iyi/syntax"

module Crystal
  alias Lexer = Iyi::Lexer
  alias Token = Iyi::Token
  alias Parser = Iyi::Parser
  alias SyntaxException = Iyi::SyntaxException
  alias Keyword = Iyi::Keyword
end
