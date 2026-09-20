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
import std/slice
import std/time
import std/random
import std/path
import std/dir

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
  # `"7".to_u64?`: iyi answers `to_i?` and `std/text` answers `to_i64`, and
  # a seed is the reason Crystal code asks for the unsigned one.
  def to_u64? : UInt64?
    value = to_i?
    return nil if value.nil?
    return nil if value < 0
    value.to_u64
  end

  def to_u64 : UInt64
    to_u64? || raise ArgumentError.new("Invalid UInt64: #{self}")
  end

  # `String.build { |io| io << part }`: Crystal's way of assembling a string
  # without naming the intermediate. The block is handed something that
  # takes the same writes an `IO` does, and the pieces are joined once at
  # the end rather than copied per `<<`.
  class Builder
    def initialize
      @parts = [] of String
    end

    def <<(value) : Builder
      @parts << value.to_s
      self
    end

    def print(value) : Nil
      @parts << value.to_s
    end

    def puts(value) : Nil
      @parts << value.to_s
      @parts << "\n"
    end

    def puts : Nil
      @parts << "\n"
    end

    def write_string(bytes : ::Std::Slice::Slice(UInt8)) : Nil
      @parts << String.new(bytes)
    end

    def to_s : String
      @parts.join("")
    end
  end

  def self.build(&block) : String
    builder = Builder.new
    yield builder
    builder.to_s
  end

  # `lchop?`: the prefix removed, or nil when it was not there, which is how
  # Crystal code asks "is this one of mine" and takes the rest in one step.
  # iyi has `lchop(Char)` and `starts_with?`, so this is the pair written as
  # the question they are usually asked as.
  def lchop?(prefix : String) : String?
    return nil unless starts_with?(prefix)
    self[prefix.size, size - prefix.size]
  end

  def lchop?(char : Char) : String?
    return nil unless starts_with?(char)
    self[1, size - 1]
  end

  def lchop(prefix : String) : String
    lchop?(prefix) || self
  end

  def rchop?(suffix : String) : String?
    return nil unless ends_with?(suffix)
    self[0, size - suffix.size]
  end

  def rchop(suffix : String) : String
    rchop?(suffix) || self
  end

  def rchop : String
    size > 0 ? self[0, size - 1] : self
  end

  # `String.new(slice)`: a string from bytes. iyi's `String.new` takes a size
  # and a block that fills the buffer, which is the primitive; this is the
  # Crystal's spelling written on top of it.
  def self.new(slice : ::Std::Slice::Slice(UInt8)) : String
    String.new(slice.size) do |buffer|
      index = 0
      while index < slice.size
        buffer[index] = slice[index]
        index = index + 1
      end
    end
  end

  # The bytes behind the string, without copying them. Crystal code reaches
  # for this when it wants to scan ASCII without paying for character
  # indexing; iyi's `Slice` is the same thing under another module.
  def to_slice : ::Std::Slice::Slice(UInt8)
    ::Std::Slice::Slice(UInt8).new(to_unsafe, bytesize, read_only: true)
  end

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

# `Time`, and `Random`, which Crystal's prelude makes ambient rather than
# requirable: `src/spec/dsl.cr` names `Time::Instant` and `src/spec/cli.cr`
# names `Random::PCG32` and `Random::Secure` without requiring either, so a
# `require` could not have supplied them.
#
# The clock and the span are iyi's, forwarded. `Instant` is new here because
# iyi's library has no opaque monotonic reading, only the clock behind it.
class Time
  alias Span = ::Std::Time::Span

  struct Instant
    def initialize(@nanoseconds : UInt64)
    end

    def elapsed : ::Std::Time::Span
      now = ::Std::Time::Time.monotonic_nanoseconds
      ::Std::Time::Span.nanoseconds((now - @nanoseconds).to_i64)
    end
  end

  def self.instant : Instant
    Instant.new(::Std::Time::Time.monotonic_nanoseconds)
  end

  def self.utc : ::Std::Time::Time
    ::Std::Time::Time.utc
  end

  def self.monotonic : ::Std::Time::Span
    ::Std::Time::Span.nanoseconds(::Std::Time::Time.monotonic_nanoseconds.to_i64)
  end
end

# Crystal names its generators; iyi has one `Random` and does not. The names
# are what a program writes, and both answer from iyi's generator rather
# than a second implementation, with one exception: `PCG32` is written out,
# because a seeded run is the whole point of the flag that asks for one and
# quietly substituting a different generator would make `--seed` a lie.
class Random
  # PCG-XSH-RR 32. Written in `UInt64` throughout because `UInt32` has no
  # conversions and no shifts in this prelude: the arithmetic is the
  # algorithm's, masked back to 32 bits at each step rather than relying on
  # a narrower type to do it.
  class PCG32
    MULTIPLIER = 6364136223846793005_u64
    INCREMENT  = 1442695040888963407_u64
    MASK32     = 0xffffffff_u64

    def initialize(seed : UInt64 = 0_u64)
      @state = 0_u64
      next_u
      @state = @state &+ seed
      next_u
    end

    def next_u : UInt64
      old = @state
      @state = old &* MULTIPLIER &+ INCREMENT
      shifted = ((old.unsafe_shr(18_u64) ^ old).unsafe_shr(27_u64)) & MASK32
      rotation = old.unsafe_shr(59_u64)
      right = shifted.unsafe_shr(rotation)
      left = shifted.unsafe_shl((32_u64 - rotation) & 31_u64)
      (right | left) & MASK32
    end

    def rand(n : Int32) : Int32
      return 0 if n <= 0
      (next_u % n.to_u64).to_i64.to_i32
    end

    def rand : Float64
      next_u.to_f64 / 4294967296.0
    end
  end

  # The seed source. iyi's `Random.new` already takes its entropy from the
  # platform, which is what `Secure` names.
  module Secure
    def self.rand(n : Int32) : Int32
      ::Std::Random::Random.new.rand(n)
    end

    # `rand(0..max)`: Crystal code asks for a number in a range, and a seed is
    # the usual reason.
    def self.rand(range : Range(Int32, Int32)) : Int32
      first = range.begin
      last = range.end
      last = last - 1 if range.exclusive?
      return first if last <= first
      first + ::Std::Random::Random.new.rand(last - first + 1)
    end

    def self.next_u : UInt32
      ::Std::Random::Random.new.next_u32
    end
  end
end

# `clone` on an array of immutable elements is `dup`, which the prelude has.
# Deliberately not defined on `Object`: Crystal's `clone` is a deep copy, and
# a shallow one wearing that name would be a quiet wrong answer for anything
# holding mutable state.
class Array(T)
  def clone : Array(T)
    dup
  end

  # Written with `each` rather than `select`, because `select` is iyi's
  # concurrency keyword and the parser reads it as one even here: a
  # receiverless `select { ... }` is a parse error in a `.cr` file too.
  def select!(&block : T -> Bool) : Array(T)
    kept = [] of T
    each { |value| kept << value if yield value }
    clear
    concat(kept)
    self
  end

  def reject!(&block : T -> Bool) : Array(T)
    select! { |value| !(yield value) }
  end

  # Range slicing, the same operation `String#[]` needed and for the same
  # reason: iyi takes a start and a count.
  def [](range : Range(Int32, Int32)) : Array(T)
    start = range.begin
    start = start + size if start < 0
    finish = range.end
    finish = finish + size if finish < 0
    finish = finish - 1 if range.exclusive?
    finish = size - 1 if finish > size - 1
    result = [] of T
    index = start
    while index <= finish
      result << self[index]
      index = index + 1
    end
    result
  end

  def [](range : Range(Int32, Nil)) : Array(T)
    self[Range.new(range.begin, size - 1, false)]
  end

  def [](range : Range(Nil, Int32)) : Array(T)
    self[Range.new(0, range.end, range.exclusive?)]
  end

  def reverse! : Array(T)
    left = 0
    right = size - 1
    while left < right
      held = self[left]
      self[left] = self[right]
      self[right] = held
      left = left + 1
      right = right - 1
    end
    self
  end
end

# The mutating forms, which iyi names after the participle and Crystal names
# with a `!`. Both spellings exist in the program now, each in the language
# that can say it: these are only reachable from a `.cr` file.
class Hash(K, V)
  def select!(&block : K, V -> Bool) : Hash(K, V)
    doomed = [] of K
    each { |key, value| doomed << key unless yield key, value }
    doomed.each { |key| delete(key) }
    self
  end

  def reject!(&block : K, V -> Bool) : Hash(K, V)
    select! { |key, value| !(yield key, value) }
  end

  def dup : Hash(K, V)
    copy = Hash(K, V).new
    each { |key, value| copy[key] = value }
    copy
  end

  def clone : Hash(K, V)
    dup
  end
end

# The prelude's `Set` says `add`, which answers whether the value was new.
# Crystal writes `<<` when it does not care and chains instead.
class Set(T)
  def <<(value : T) : Set(T)
    add(value)
    self
  end

  def concat(values) : Set(T)
    values.each { |value| add(value) }
    self
  end
end

# `Process.on_terminate`, the one thing `src/spec.cr` asks of `Process`: run
# this when the user interrupts, so a suite killed with Ctrl-C still prints
# what it had. Nothing in iyi binds `signal`, so the binding is here.
#
# The handler runs the block directly, which is what the caller wants and is
# not async-signal-safe in general; it is written this way because the only
# caller prints a summary and exits, and a version that set a flag nobody
# polls would be a handler that silently never runs.
lib LibCompatSignal
  fun signal(signum : Int32, handler : Int32 -> Nil) : Void*
end

module Process
  SIGINT  =  2
  SIGTERM = 15

  @@on_terminate : Proc(Nil)? = nil

  def self.on_terminate(&block) : Nil
    @@on_terminate = block
    LibCompatSignal.signal(SIGINT, ->Process.handle_terminate(Int32))
    LibCompatSignal.signal(SIGTERM, ->Process.handle_terminate(Int32))
  end

  # :nodoc:
  def self.handle_terminate(signum : Int32) : Nil
    if handler = @@on_terminate
      handler.call
    end
  end
end

# `io << value << "\n"`: Crystal code chains writes, iyi says `print`. One call
# underneath, and chaining is why the return is the stream.
class IyiIO
  def <<(value) : IyiIO
    print(value)
    self
  end

  # `write_string(bytes)`: the byte-level write Crystal's escaping code uses
  # to avoid building a `String` per fragment. iyi's `write` takes the
  # pointer and the count, which is the same call.
  def write_string(bytes : ::Std::Slice::Slice(UInt8)) : Nil
    write(bytes.to_unsafe, bytes.size)
  end
end

# `System.hostname`, which the JUnit formatter writes into its report.
# Nothing in iyi binds `gethostname`, so the binding is here, sized to the
# POSIX limit and answering the empty string rather than raising: a report
# that cannot name the machine is still a report.
lib LibCompatHost
  fun gethostname(name : Pointer(UInt8), len : UInt64) : Int32
end

module System
  def self.hostname : String
    buffer = Pointer(UInt8).malloc(256_u64)
    return "" unless LibCompatHost.gethostname(buffer, 256_u64) == 0
    length = 0
    while length < 256 && buffer[length] != 0_u8
      length = length + 1
    end
    String.new(length) do |target|
      index = 0
      while index < length
        target[index] = buffer[index]
        index = index + 1
      end
    end
  end
end

# `exit`, which iyi does not have on purpose: a program there ends when its
# last line runs and a failure is a panic (SPEC.md III.1.4). A Crystal
# program ends where it says so, and the prelude's own `__iyi_exit` is the
# same call underneath.
def exit(status : Int32 = 0) : NoReturn
  __iyi_exit(status)
end

# `hash.put_if_absent(key) { value }`: read the key, and only build the
# value when it is missing. Crystal code uses it to avoid constructing a
# default on every lookup, and iyi's `Hash` has `[]?` and `[]=` to write it
# with.
class Hash(K, V)
  def put_if_absent(key : K, &block : K -> V) : V
    existing = self[key]?
    return existing unless existing.nil?
    value = yield key
    self[key] = value
    value
  end

  def put_if_absent(key : K, value : V) : V
    put_if_absent(key) { value }
  end
end

# `File.expand_path`, written here rather than forwarded, and the reason is
# worth keeping: `import std/file` in this file rebinds the name `File` to
# the module `Std::File` for *every* module in the program, so `std/random`
# calling `File.open("/dev/urandom")` stopped resolving. An import in the
# compatibility layer is program-wide, and a module whose name collides with
# a prelude type cannot be imported here at all.
class File
  SEPARATOR = '/'

  # `File.new(path, "w")`: Crystal code constructs a file and gets something it
  # can write to. The prelude spells the same thing `File.open`, which hands
  # back the `IyiIO` this returns, so the name is the only difference.
  def self.new(path : String | Path, mode : String = "r") : IyiIO
    open(path.to_s, mode)
  end

  def self.expand_path(path : String, base : String? = nil) : String
    return path if path.starts_with?('/')

    home = ENV["HOME"]?
    if home && path.starts_with?('~')
      rest = path.size > 1 ? path[1, path.size - 1] : ""
      return rest.empty? ? home : home + rest
    end

    root = base || Dir.current
    root = root[0, root.size - 1] if root.size > 1 && root.ends_with?('/')
    path.empty? ? root : root + "/" + path
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

# `Path` is iyi's, under its own module. An `import` alone does not put the
# name in a `.cr` program's reach (measured: `Path.posix` is an undefined
# constant with the import in place, `Std::Path::Path.posix` works), and a
# top-level alias is a global constant, so this is the bridge.
alias Path = ::Std::Path::Path
alias Dir = ::Std::Dir::Dir
alias Bytes = ::Std::Slice::Slice(UInt8)

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
