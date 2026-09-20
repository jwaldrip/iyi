# What a `.cr` file gets on top of iyi's prelude, and nothing an `.iyi` file
# can see.
#
# A program written in Crystal expects a handful of names to be there without
# asking: `ENV`, `not_nil!`, the two bang-named accessor macros. iyi's library
# either already has them under its own name or cannot spell them at all, so
# neither the prelude nor a `require` can supply them: the prelude is iyi and
# is parsed by iyi's rules, and `ENV` is never required by anyone.
#
# This file is Crystal, compiled after the prelude whenever the program being
# built is a `.cr` file on iyi's library. That is the whole seam: the language
# keeps its rules, and the compatibility surface lives on the other side of
# the file extension, where Crystal's rules apply.
import std/env

# iyi's `std/env` already exports a struct called `ENV` with the surface
# Crystal's has: `[]`, `[]?`, `[]=`, `fetch`, `has_key?`, `delete`, `each`.
# The `import` above is all it takes: a `.cr` file sees an imported module's
# exports by name without a `using`, so `ENV["HOME"]` here is iyi's own, and
# writing an alias for it is refused because the name is already bound.
# Measured both ways: with the import a `.cr` program answers
# `ENV.has_key?("PATH")`, and without it the same program cannot find `ENV`.

# Crystal's arguments are a top-level constant; iyi's are `Program.args`,
# which is the same array asked for by name rather than found lying around.
ARGV = Program.args

class Object
  # `!` is not part of a name in iyi (SPEC.md III.1.7a): postfix `!` there
  # propagates an error. So `not_nil!` cannot be written in the prelude no
  # matter how much Crystal code calls it, and Crystal's own library and spec
  # framework call it throughout.
  def not_nil!(message = nil) : self
    self
  end

  # `getter! foo : T` declares a nilable field, answers `foo?` with what is
  # there and `foo` with the value or a failure. Used 20 times in the Crystal
  # library in this tree, and `property!` 52 times; both unsayable in iyi for
  # the same reason as `not_nil!`.
  macro getter!(*names)
    {% for name in names %}
      {% if name.is_a?(TypeDeclaration) %}
        @{{ name.var.id }} : {{ name.type }}?

        def {{ name.var.id }}? : {{ name.type }}?
          @{{ name.var.id }}
        end

        def {{ name.var.id }} : {{ name.type }}
          @{{ name.var.id }}.not_nil!("{{ name.var.id }} cannot be nil")
        end
      {% else %}
        def {{ name.id }}?
          @{{ name.id }}
        end

        def {{ name.id }}
          @{{ name.id }}.not_nil!("{{ name.id }} cannot be nil")
        end
      {% end %}
    {% end %}
  end

  macro property!(*names)
    {% for name in names %}
      getter! {{ name }}

      {% if name.is_a?(TypeDeclaration) %}
        def {{ name.var.id }}=(value : {{ name.type }}?)
          @{{ name.var.id }} = value
        end
      {% else %}
        def {{ name.id }}=(value)
          @{{ name.id }} = value
        end
      {% end %}
    {% end %}
  end
end

class Object
  # `value.try { |v| ... }`: run the block on a value that is there, and
  # answer nil for one that is not. iyi does not carry this because its
  # nil-safety is flow typing: you test the variable and the compiler narrows
  # it. Crystal code reaches for `try` instead, constantly, so it lives on
  # the Crystal side rather than in the prelude.
  def try(&block)
    yield self
  end
end

struct Nil
  def not_nil!(message = nil)
    raise message || "nil assertion failed"
  end

  def try(&block)
    nil
  end
end
