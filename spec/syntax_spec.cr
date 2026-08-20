# This is a spec entry point to run all specs related to syntax (parsing, formatting, tools).

require "./compiler/lexer/**"
require "./compiler/parser/**"
require "./compiler/formatter/**"

require "./compiler/iyi/tools/doc_spec.cr"
require "./compiler/iyi/tools/doc/**"
require "./compiler/iyi/tools/flags_spec.cr"
require "./compiler/iyi/tools/format_spec.cr"

require "./std/crystal/syntax_highlighter/**"
