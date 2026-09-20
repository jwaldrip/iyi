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

  # `split(char) { |piece| ... }`: the block form, which hands each piece
  # over instead of building the array. iyi has the array-returning one.
  def split(separator : Char, &block : String -> Nil) : Nil
    split(separator).each { |piece| yield piece }
  end

  # `inspect_unquoted(io)`: the escaped form without the quotes around it,
  # which is how a value gets written into an XML attribute or a message
  # without a control character going through raw. iyi's own `inspect` only
  # wraps the string in quotes, so the escaping is written here.
  def inspect_unquoted(io) : Nil
    each_char do |character|
      if character == '\n'
        io << "\\n"
      elsif character == '\t'
        io << "\\t"
      elsif character == '\r'
        io << "\\r"
      elsif character == '"'
        io << "\\\""
      elsif character == '\\'
        io << "\\\\"
      elsif character.control?
        io << "\\u{" << character.ord.to_s(16) << "}"
      else
        io << character
      end
    end
  end

  def inspect_unquoted : String
    String.build { |io| inspect_unquoted(io) }
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
  # `a + b`: a new array of both. iyi has `concat`, which changes the
  # receiver; Crystal code adds two lists and keeps them.
  def +(other : Array(T)) : Array(T)
    result = dup
    result.concat(other)
    result
  end

  def clone : Array(T)
    dup
  end

  # A Fisher-Yates shuffle driven by the caller's generator, because the
  # point of passing one is that `--seed` reproduces the order.
  def shuffle!(generator) : Array(T)
    index = size - 1
    while index > 0
      target = generator.rand(index + 1)
      held = self[index]
      self[index] = self[target]
      self[target] = held
      index = index - 1
    end
    self
  end

  # iyi names the copy after the participle: `sorted`, `sorted_by`. Crystal
  # spells the same thing `sort` and `sort_by`, and the mutating pair with a
  # bang. Both names, each doing what its own language means by it.
  # `block.call` rather than `yield`: `sorted` and `sorted_by` take captured
  # blocks, and a `yield` inside one is refused.
  def sort(&block : T, T -> Int32) : Array(T)
    sorted { |left, right| block.call(left, right) }
  end

  def sort_by(&block : T -> U) : Array(T) forall U
    sorted_by { |value| block.call(value) }
  end

  def sort!(&block : T, T -> Int32) : Array(T)
    ordered = sorted { |left, right| block.call(left, right) }
    clear
    concat(ordered)
    self
  end

  # `join(io, separator)`: write the pieces straight into a stream instead
  # of building the joined string first.
  def join(io, separator : Char) : Nil
    join(io, separator.to_s)
  end

  def join(io, separator : String) : Nil
    index = 0
    while index < size
      io << separator if index > 0
      io << self[index]
      index = index + 1
    end
  end

  def max_of(&block : T -> U) : U forall U
    best = nil
    each do |value|
      candidate = block.call(value)
      best = candidate if best.nil? || candidate > best
    end
    best.not_nil!
  end

  def sort_by!(&block : T -> U) : Array(T) forall U
    ordered = sorted_by { |value| block.call(value) }
    clear
    concat(ordered)
    self
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
  # `Hash(K, V).new(0)`: a default for a key that is not there, which is how
  # Crystal code counts things without testing first. iyi's `Hash` answers
  # nil and leaves the decision to the caller, so the default is held here
  # and `[]` consults it.
  @compat_default : V? = nil

  def self.new(default : V) : Hash(K, V)
    table = Hash(K, V).new
    table.compat_default = default
    table
  end

  protected def compat_default=(value : V) : V
    @compat_default = value
  end

  def [](key : K) : V
    value = self[key]?
    return value unless value.nil?
    fallback = @compat_default
    return fallback unless fallback.nil?
    raise KeyError.new("Missing hash key: #{key}")
  end

  # `to_a`: the pairs, so they can be sorted. iyi's `Hash` walks with
  # `each` and answers `keys` and `values`; the pair list is what a program
  # that wants them in an order asks for.
  def to_a : Array(Tuple(K, V))
    pairs = [] of Tuple(K, V)
    each { |key, value| pairs << {key, value} }
    pairs
  end

  def max_of(&block : K, V -> U) : U forall U
    best = nil
    each do |key, value|
      candidate = block.call(key, value)
      best = candidate if best.nil? || candidate > best
    end
    best.not_nil!
  end

  # `update(key) { |old| new }`: read, change, write, in one step. The
  # counter next to it is why: `counts.update(tag) { |n| n + 1 }`.
  def update(key : K, &block : V -> V) : V
    current = self[key]
    replacement = block.call(current)
    self[key] = replacement
    replacement
  end

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

# Ordering a tuple, element by element, which is how Crystal code sorts by
# more than one key: `sort_by { |k, v| {-v, k} }` is a count descending and
# then a name. The prelude's `Tuple` indexes and sizes itself and stops
# there, so the comparison is written from the members' own `<`.
struct Tuple
  def <(other : Tuple) : Bool
    {% for index in 0...T.size %}
      return true if self[{{ index }}] < other[{{ index }}]
      return false if other[{{ index }}] < self[{{ index }}]
    {% end %}
    false
  end

  def >(other : Tuple) : Bool
    other < self
  end

  def <=(other : Tuple) : Bool
    !(other < self)
  end

  def >=(other : Tuple) : Bool
    !(self < other)
  end
end

# The prelude's `Set` says `add`, which answers whether the value was new.
# Crystal writes `<<` when it does not care and chains instead.
class Set(T)
  def <<(value : T) : Set(T)
    add(value)
    self
  end

  # `tally(into)`: count into a table the caller already has, so counts from
  # several sets add up instead of each answering its own map.
  def tally(into : Hash(T, Int32)) : Hash(T, Int32)
    each do |value|
      current = into[value]?
      into[value] = current.nil? ? 1 : current + 1
    end
    into
  end

  # Whether the two sets share anything, which is how a tag filter asks
  # "does this example carry one of the tags I was given".
  def intersects?(other : Set(T)) : Bool
    found = false
    each { |value| found = true if other.includes?(value) }
    found
  end

  # `a + b`: a new set of both, leaving each alone. `concat` below is the
  # one that changes the receiver.
  def +(other : Set(T)) : Set(T)
    result = Set(T).new
    each { |value| result.add(value) }
    other.each { |value| result.add(value) }
    result
  end

  def dup : Set(T)
    self + Set(T).new
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
  # `value.to_s(self)`, not `print(value)`. A type that writes itself into a
  # stream overrides `to_s(io)` and leaves the no-argument `to_s` alone, and
  # iyi's default for that one is the type's own name: going through `print`
  # made a colorized string print as `Colorize::Object(String)`.
  def <<(value) : IyiIO
    value.to_s(self)
    self
  end

  # `print` and `puts` go the same way, and for the same reason: the spec
  # summary printed `Colorize::Object(String)` because `puts value` reached
  # the no-argument `to_s`, which on a type that only writes itself into a
  # stream is iyi's default, the type's own name.
  def print(value) : Nil
    value.to_s(self)
  end

  def puts(value) : Nil
    value.to_s(self)
    puts
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

# A cursor over a string's characters, and the two predicates the callers
# of one reach for. iyi's `String` walks with `each_char` and has no cursor,
# because nothing in iyi wanted to stop halfway; the XML escaper in the spec
# framework does, so the characters are collected once and indexed.
struct Char
  # `value.to_s(io)`: Crystal writes into a stream rather than building a
  # string to throw away. iyi's `to_s` answers the string, which is the
  # whole reason its `Object` is small (SPEC.md, object.iyi), so the
  # stream-taking form belongs on this side of the seam.
  def to_s(io) : Nil
    io << to_s
  end

  def control? : Bool
    ord < 32 || ord == 127
  end

  def ascii_control? : Bool
    control?
  end

  class Reader
    def initialize(string : String)
      @chars = [] of Char
      string.each_char { |character| @chars << character }
      @pos = 0
    end

    def has_next? : Bool
      @pos < @chars.size
    end

    def current_char : Char
      @chars[@pos]
    end

    def pos : Int32
      @pos
    end

    def next_char : Char
      @pos = @pos + 1
      has_next? ? @chars[@pos] : '\0'
    end
  end
end

# `at_exit { ... }`: run this when the program ends. iyi has no such hook
# and does not want one (a program there ends when its last line runs), but
# a Crystal program registers its whole spec run inside one, so the hooks
# are kept and drained by `exit` and by libc's `atexit` for the ordinary
# end of `main`.
lib LibCompatExit
  fun atexit(handler : -> Nil) : Int32
end

module AtExitHandlers
  # The handler takes the exit status, because Crystal's does and the spec
  # framework reads it: a run that is already failing does not start.
  @@handlers = [] of Proc(Int32, Nil)
  @@status = 0
  @@armed = false
  @@draining = false

  def self.register(handler : Proc(Int32, Nil)) : Nil
    unless @@armed
      LibCompatExit.atexit(->AtExitHandlers.drain)
      @@armed = true
    end
    @@handlers << handler
  end

  # Last registered first, which is the order Crystal runs them in, and
  # once: `exit` drains and then libc calls this again.
  def self.status=(status : Int32) : Int32
    @@status = status
  end

  def self.drain : Nil
    return if @@draining
    @@draining = true
    index = @@handlers.size - 1
    while index >= 0
      @@handlers[index].call(@@status)
      index = index - 1
    end
    @@handlers.clear
    @@draining = false
  end
end

def at_exit(&block : Int32 -> Nil) : Nil
  AtExitHandlers.register(block)
end

# `exit`, which iyi does not have on purpose: a program there ends when its
# last line runs and a failure is a panic (SPEC.md III.1.4). A Crystal
# program ends where it says so, and the prelude's own `__iyi_exit` is the
# same call underneath.
def exit(status : Int32 = 0) : NoReturn
  AtExitHandlers.status = status
  AtExitHandlers.drain
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

# Asking whether a path is a directory by opening it as one. The first
# version read `st_mode` out of a `stat` buffer at an offset worked out from
# the struct layout, and the offset was wrong: measured against a real file
# and a real directory, the mode sits at `UInt16` index 2, while the guessed
# index 4 happened to match for the file and read zero for the directory. A
# wrong answer about every directory would have shipped. `opendir` asks the
# question directly and carries no layout at all.
lib LibCompatDir
  fun opendir(path : UInt8*) : Void*
  fun closedir(dir : Void*) : Int32
end

# `File.expand_path`, written here rather than forwarded, and the reason is
# worth keeping: `import std/file` in this file rebinds the name `File` to
# the module `Std::File` for *every* module in the program, so `std/random`
# calling `File.open("/dev/urandom")` stopped resolving. An import in the
# compatibility layer is program-wide, and a module whose name collides with
# a prelude type cannot be imported here at all.
class File
  SEPARATOR = '/'

  # `file?` and `directory?`: which kind of thing is at the path. The
  # prelude answers `exists?` only, and `std/file` has both, but importing
  # that module here rebinds the name `File` program-wide (see below), so
  # the kernel is asked directly.
  def self.directory?(path : String | Path) : Bool
    handle = LibCompatDir.opendir(path.to_s)
    return false if handle.address == 0_u64
    LibCompatDir.closedir(handle)
    true
  end

  def self.file?(path : String | Path) : Bool
    name = path.to_s
    exists?(name) && !directory?(name)
  end

  # The file's lines, without their terminators. `read` is the prelude's.
  def self.read_lines(path : String | Path) : Array(String)
    read(path.to_s).split('\n')
  end

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

# Two things a summary line asks of a number: round it to a couple of
# decimals, and print it without an exponent. Neither is in iyi's prelude,
# and `std/float` carries the `Float32` versions only.
struct Float64
  def round(digits : Int32 = 0) : Float64
    scale = 1.0
    count = 0
    while count < digits
      scale = scale * 10.0
      count = count + 1
    end
    shifted = self * scale
    whole = shifted.to_i64
    fraction = shifted - whole.to_f64
    whole = whole + 1_i64 if fraction >= 0.5
    whole = whole - 1_i64 if fraction <= -0.5
    whole.to_f64 / scale
  end

  # `humanize` in Crystal abbreviates with an SI suffix. The only caller
  # here prints a count of seconds, so this rounds rather than inventing a
  # suffix table nothing in this program would exercise.
  def humanize : String
    round(3).to_s
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

# `Fiber` is iyi's own, under the name its runtime uses. Crystal code asks
# `Fiber.has_constant?(:ExecutionContext)` at macro time to find out whether
# this runtime schedules across threads, and the honest answer here is no:
# iyi's scheduler is a group, not an execution context (SPEC.md III.4). The
# alias exists so the question can be asked rather than failing to compile.
alias Fiber = IyiFiber


# `Fiber.yield`: hand the processor to whatever else is ready. iyi spells it
# `IyiScheduler.reschedule`, and the name is on the fiber because that is
# where Crystal code looks for it. The spec framework calls it between
# examples so a Ctrl-C is noticed promptly.
class IyiFiber
  # A yield with nothing else to run is a no-op, not a wait. iyi's
  # `reschedule` parks the caller and looks for another fiber, and panics
  # with "every fiber is blocked" when there is none: correct for a fiber
  # that is waiting on something, wrong for one that is only being polite.
  # The spec framework calls this between examples on the main fiber.
  def self.yield : Nil
    IyiScheduler.reschedule unless IyiScheduler.state.run_head.is_a?(Nil)
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

# A type that declares its own `to_s` hides `Object`'s stream-taking one:
# iyi resolves by name before arity, so `String#to_s` alone means
# `"x".to_s(io)` is a wrong-arity error rather than a fall-through. Every
# core type that writes itself needs the pair written out.
class ::String
  def to_s(io) : Nil
    io.print(self)
  end
end

{% for type in %w(Char Bool Symbol Int32 Int64 UInt8 UInt64 Float64) %}
  struct ::{{ type.id }}
    def to_s(io) : Nil
      io.print(to_s)
    end
  end
{% end %}

# An enum's number. The compiler gives an enum `value`; Crystal code asks
# for `to_i`, and both mean the integer the member was declared with.
struct Enum
  def to_i : Int32
    value
  end

  def to_s(io) : Nil
    io.print(to_s)
  end
end

class Object
  # `pretty_inspect`: Crystal's pretty printer wraps a long value across
  # lines. Nothing here has one, and a failure message that reads the value
  # on a single line is the same message, only wider.
  def pretty_inspect : String
    inspect
  end

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
  # Also on `Exception` itself, not only on `Object`: the call site holds an
  # `Exception+`, the virtual type over every subclass, and the lookup does
  # not reach `Object`'s from there.
  def self.name : String
    {{ @type.name.stringify }}
  end

  getter message : String?
  getter cause : Exception?

  def initialize(@message : String? = nil, @cause : Exception? = nil)
  end

  def to_s : String
    @message || {{ @type.name.stringify }}
  end

  # No backtrace. Crystal's comes from `Exception::CallStack`, which walks
  # the unwinder's frames and reads DWARF to name them; iyi has neither, and
  # a made-up frame list would be worse than an honest absence. Callers that
  # ask get nil and print the message instead, which is what they do for a
  # backtrace-less exception in Crystal too.
  def backtrace? : Array(String)?
    nil
  end

  def backtrace : Array(String)
    [] of String
  end

  def inspect_with_backtrace : String
    inspect
  end

  def inspect_with_backtrace(io) : Nil
    io << inspect
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
