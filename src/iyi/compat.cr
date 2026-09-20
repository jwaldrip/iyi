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
import std/text

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

# `str[1..]`, `str[0...3]`: Crystal code slices a string with a range, and
# iyi's `String#[]` takes an index or a start and a count. One operation,
# spelling missing, so it is written here in terms of the one that exists.
# iyi spells the open end `exclusive?` where Crystal spells it
# `excludes_end?`; the name a Crystal program writes is given below.
struct Range(B, E)
  def excludes_end? : Bool
    exclusive?
  end
end

class String
  def [](range : Range(Int32, Int32)) : String
    start = range.begin
    start = start + size if start < 0
    finish = range.end
    finish = finish + size if finish < 0
    finish = finish - 1 if range.exclusive?
    finish = size - 1 if finish > size - 1
    return "" if start > finish
    self[start, finish - start + 1]
  end

  def [](range : Range(Int32, Nil)) : String
    start = range.begin
    start = start + size if start < 0
    return "" if start >= size
    self[start, size - start]
  end

  def [](range : Range(Nil, Int32)) : String
    finish = range.end
    finish = finish + size if finish < 0
    finish = finish - 1 if range.exclusive?
    finish = size - 1 if finish > size - 1
    return "" if finish < 0
    self[0, finish + 1]
  end
end

# Integer walks Crystal writes and iyi does not have. `times` is in the
# prelude because iyi programs write it; these two are here because Crystal
# programs do and iyi's answer is a range.
struct Int32
  def upto(last : Int32, &block) : Nil
    value = self
    while value <= last
      yield value
      value = value + 1
    end
  end

  def downto(last : Int32, &block) : Nil
    value = self
    while value >= last
      yield value
      value = value - 1
    end
  end
end

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

  # `build.tap { |b| ... }`: hand the value to a block and answer the value.
  # Crystal code uses it to configure something in the expression that makes
  # it; iyi writes the two statements.
  def tap(&block)
    yield self
    self
  end

  def itself
    self
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

# Exceptions.
#
# The compiler predefines the name `Exception` for every program (it needs a
# type for a landing pad to produce), but on iyi's library nothing had ever
# given it a body, a message or a subclass: `raise "x"` called iyi's `raise`,
# which panics, and a `rescue` compiled to a handler nothing could ever reach.
#
# This is the Crystal half of the seam. iyi's error model is unchanged and
# SPEC.md III.1.4 still holds for iyi: an error is a value, a panic unwinds by
# registry, and an `.iyi` file cannot write a `rescue` at all. A `.cr` file is
# Crystal, and in Crystal `raise` throws.
class Exception
  getter message : String?
  getter cause : Exception?

  def initialize(@message : String? = nil, @cause : Exception? = nil)
  end

  def to_s : String
    @message || {{ @type.name.stringify }}
  end

  def inspect : String
    "#{{{ @type.name.stringify }}}: #{@message}"
  end
end

# The subclasses Crystal's own library raises by name. Each is here because
# something in `src/` names it, not for completeness: the hierarchy grows when
# a program needs a name, the same rule the rest of this file follows.
#
# `TypeCastError` is deliberately absent: the prelude already declares one,
# carrying a message for the panic a failed `.as` in a `select` expansion
# produces, and it is not an `Exception`. Redeclaring it here as one is a
# superclass mismatch, and the compiler says so.
class ArgumentError < Exception
end

class IndexError < Exception
end

class KeyError < Exception
end

class NilAssertionError < Exception
end

class OverflowError < Exception
end

class DivisionByZeroError < Exception
end

class InvalidByteSequenceError < Exception
end

class RuntimeError < Exception
end

class NotImplementedError < Exception
end

class IO
  class Error < Exception
  end
end

# `raise` in a `.cr` file throws; iyi's `raise`, which panics, is the one an
# `.iyi` file gets. Same spelling, two languages, decided by the extension.
def raise(exception : Exception) : NoReturn
  unwind_ex = Pointer(LibUnwind::Exception).malloc(1_u64)
  unwind_ex.value.exception_class = 0_u64
  unwind_ex.value.exception_cleanup = 0_u64
  unwind_ex.value.exception_object = exception.as(Void*)
  unwind_ex.value.exception_type_id = exception.crystal_type_id
  __iyi_raise(unwind_ex)
end

def raise(message : String) : NoReturn
  raise Exception.new(message)
end
