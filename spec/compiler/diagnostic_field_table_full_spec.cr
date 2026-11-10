require "../spec_helper"
require "./diagnostic_field_table_spec"

# Full-compiler context. The full census is only meaningful when the compiler's
# reopened AST classes are loaded, so this file refuses to compile without them.
# Silently running the syntax context here would hide a missing full scope.
{% unless Iyi::Block.has_method?(:binder) %}
  {% raise "diagnostic_field_table_full_spec requires the full compiler types (Block#binder); load them through ../spec_helper" %}
{% end %}
