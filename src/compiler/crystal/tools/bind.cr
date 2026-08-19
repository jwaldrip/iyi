# iyi: what it would take to put a Crystal shard behind an iyi boundary.
#
#   crystal tool bind -e Kemal shard_entry.cr
#
# R-2 asks every exported signature to write its types down, and Crystal infers
# instead of writing. Most of a shard's surface can be written down without a
# human: a method whose parameters carry types can be instantiated on purpose,
# and what it returns falls out of that. This says how much of a given shard is
# in that position, which is the number that decides whether a boundary is
# worth generating at all.
#
# It reads and counts; it writes no `.iyi` yet. Measuring first is the same
# order every other part of this project was built in.
#
# **It lives in the compiler rather than beside it**, and the reason is worth
# keeping: reading a shard means analysing the standard library it is written
# against, and the standard library asks `size_of`, which is answered from a
# data layout. A front end that links no LLVM has none, so a tool built that
# way cannot read a single real shard.
module Crystal
  # What a method is, for a boundary.
  enum BindVerdict
    # Every parameter and the return type are written. R-2 already.
    Ready
    # The parameters are written and the return type is not: a machine can
    # instantiate this and read the answer.
    NeedsReturn
    # A parameter carries no type. Nothing can guess it, so a human writes it.
    NeedsHuman
  end

  record BindMethod,
    owner : String,
    name : String,
    verdict : BindVerdict,
    block : Bool,
    untyped : Array(String),
    location : String,
    params : Array({String, String}),
    returns : String?,
    # What the return type turned out to be, once the method was instantiated
    # on purpose, or the reason it could not be.
    inferred : String?,
    refused : String? do
    # Every type this signature names, so the emitter can ask whether they can
    # all be named on the other side.
    def signature_types : Array(String)
      types = params.map { |(_, restriction)| restriction }
      answer = returns || inferred
      types << answer if answer
      types
    end

    # The `pub def` an iyi module would carry. Written from what the source
    # said where it said it, and from what instantiation answered where it did
    # not, which is the only difference between the two halves of this file.
    def declaration : String
      args = params.map { |(name, restriction)| "#{name} : #{restriction}" }.join(", ")
      answer = returns || inferred || "Nil"
      signature = args.empty? ? name : "#{name}(#{args})"
      "pub def #{signature} : #{answer}"
    end
  end

  # The types an iyi program already has, so a signature naming one of them
  # needs nothing from this boundary. Everything else is somebody's to declare,
  # and saying which is most of what a boundary costs.
  BIND_PRELUDE = %w(String Int32 Int64 UInt8 UInt32 UInt64 Float64 Bool Nil Char Symbol Array Hash Range Pointer Void)

  def self.print_bind(program : Program, root : String?, io : IO) : Nil
    unless root
      io.puts "tool bind needs the shard's own namespace: -e Kemal"
      return
    end

    methods = [] of BindMethod
    collect_bind program.types?, root, methods

    ready = methods.count(&.verdict.ready?)
    inferable = methods.count(&.verdict.needs_return?)
    human = methods.count(&.verdict.needs_human?)

    io.puts "#{root}: #{methods.size} public methods on its own types"
    io.puts
    io.puts "  R-2 as written            #{ready}"
    io.puts "  a machine can write       #{inferable}"
    io.puts "  a human has to write      #{human}"
    io.puts
    io.puts "  of those, take a block    #{methods.count(&.block)}"

    machine = methods.select(&.verdict.needs_return?)
    unless machine.empty?
      answered = machine.count { |m| m.inferred }
      io.puts
      io.puts "instantiated on purpose, to read what they return:"
      io.puts "  answered                  #{answered}"
      io.puts "  refused                   #{machine.size - answered}"
      machine.select(&.refused).group_by { |m| m.refused.not_nil! }
        .to_a.sort_by { |(_, v)| -v.size }.first(8).each do |(reason, list)|
        io.puts "    %-38s %d" % [reason[0, 38], list.size]
      end
    end

    return if methods.empty?
    mechanical = ready + inferable
    io.puts
    io.puts "  #{(mechanical * 100.0 / methods.size).round(1)}% of the surface needs no human."

    emit_module methods, root, io

    return if human.zero?

    # Named, because the count is the estimate and this is the work. Each line
    # is one signature somebody has to decide, and the parameter it is about.
    io.puts
    io.puts "what a human has to write:"
    methods.select(&.verdict.needs_human?).sort_by { |m| {m.owner, m.name} }.each do |method|
      io.puts "  #{method.owner}##{method.name}(#{method.untyped.join(", ")})"
      io.puts "    #{method.location}"
    end
  end

  # The draft boundary: what a consumer would import.
  #
  # A signature goes in when every type in it is one an iyi program can name —
  # the shard's own, or the prelude's. What is left out is left out by name,
  # because those are the types somebody has to decide about, and deciding is
  # the work this tool exists to size.
  private def self.emit_module(methods : Array(BindMethod), root : String, io : IO) : Nil
    known = methods.select { |m| m.verdict.ready? || m.inferred }
    lines = [] of String
    outside = Hash(String, Int32).new(0)

    known.each do |method|
      types = method.signature_types
      foreign = types.reject { |t| nameable?(t, root) }
      if foreign.empty?
        lines << method.declaration
      else
        # Named by the part that is missing rather than by the whole
        # signature, because the part is what somebody has to declare and one
        # decision unblocks every signature that mentions it.
        foreign.each do |type|
          type.scan(/[A-Za-z_][A-Za-z0-9_:]*/).each do |match|
            part = match[0]
            next if part == "class"
            outside[part] += 1 unless nameable_name?(part, root)
          end
        end
      end
    end

    io.puts
    io.puts "a boundary this tool can already write:"
    io.puts "  signatures                #{lines.size}"
    io.puts "  waiting on a type nobody has declared  #{known.size - lines.size}"

    unless outside.empty?
      io.puts
      io.puts "the types that boundary is waiting on:"
      outside.to_a.sort_by { |(_, c)| -c }.first(10).each do |(name, count)|
        io.puts "  %-44s %d" % [name, count]
      end
    end

    unlocked = blocked_by(known, root)
    unless unlocked.empty?
      io.puts
      io.puts "declaring one type at a time, and what each one unlocks:"
      declared = Set(String).new
      total = 0
      unlocked.first(8).each do |name|
        declared << name
        opened = known.count do |method|
          foreign_names(method, root).all? { |t| declared.includes?(t) } &&
            !foreign_names(method, root).empty?
        end
        io.puts "  %-40s %+d  (%d in all)" % [name, opened - total, opened]
        total = opened
      end
    end

    return if lines.empty?

    io.puts
    io.puts "# --- draft ---"
    io.puts "# Flat, and a real boundary is not: these methods belong to the"
    io.puts "# types that declare them, and grouping them there is the next"
    io.puts "# thing this tool has to learn. What is settled here is the part"
    io.puts "# that was in doubt, which is whether the signatures can be known."
    io.puts "module #{root.downcase}"
    io.puts
    lines.sort.each { |line| io.puts line }
    io.puts "# --- end ---"
  end

  # The foreign types one signature waits on.
  private def self.foreign_names(method : BindMethod, root : String) : Set(String)
    names = Set(String).new
    method.signature_types.each do |type|
      type.scan(/[A-Za-z_][A-Za-z0-9_:]*/).each do |match|
        part = match[0]
        next if part == "class"
        names << part unless nameable_name?(part, root)
      end
    end
    names
  end

  # The order to declare them in: the one that unblocks the most first.
  #
  # Greedy rather than optimal, and the difference does not matter — what this
  # answers is "where does the work start", and the head of the list is the
  # same either way.
  private def self.blocked_by(known : Array(BindMethod), root : String) : Array(String)
    counts = Hash(String, Int32).new(0)
    known.each do |method|
      foreign_names(method, root).each { |name| counts[name] += 1 }
    end
    counts.to_a.sort_by { |(name, count)| {-count, name} }.map { |(name, _)| name }
  end

  # A type an iyi program can name: the shard's own, or one of the prelude's.
  #
  # Every name inside it, not just the one in front. `Hash(Exception.class,
  # Proc(HTTP::Server::Context, Exception, String))` begins with a type the
  # prelude has and is made almost entirely of types it does not, and reading
  # only the head counted it as writable — the measurement flattering itself.
  private def self.nameable?(name : String, root : String) : Bool
    name.scan(/[A-Za-z_][A-Za-z0-9_:]*/).all? do |match|
      part = match[0]
      next true if part == "class" # `Exception.class` is read as its own name
      nameable_name?(part, root)
    end
  end

  private def self.nameable_name?(name : String, root : String) : Bool
    return true if name == root || name.starts_with?("#{root}::")
    BIND_PRELUDE.includes?(name.lchop("::"))
  end

  # Only the types the shard declares. A type it merely reopened belongs to
  # somebody else, and R-3 is what refuses to carry it here.
  private def self.collect_bind(types : Hash(String, Type)?, root : String,
                                methods : Array(BindMethod)) : Nil
    return unless types

    types.each_value do |type|
      next unless type.is_a?(NamedType)
      name = type.to_s
      next unless name == root || name.starts_with?("#{root}::")

      each_bind_def(type) { |a_def| methods << classify_bind(type, a_def) }
      each_bind_def(type.metaclass) { |a_def| methods << classify_bind(type.metaclass, a_def) }

      collect_bind type.types?, root, methods
    end
  end

  private def self.each_bind_def(type : Type, & : Def ->) : Nil
    defs = type.as?(ModuleType).try &.defs
    return unless defs

    defs.each_value do |list|
      list.each do |item|
        a_def = item.def
        next unless a_def.visibility.public?
        # A method with no location is the compiler's own — `allocate` exists
        # on every type and nobody wrote it. A boundary carries what a shard's
        # author wrote, and `new` comes back through `initialize`.
        next unless a_def.location
        yield a_def
      end
    end
  end

  private def self.classify_bind(owner : Type, a_def : Def) : BindMethod
    verdict =
      if a_def.args.any? { |arg| arg.restriction.nil? }
        BindVerdict::NeedsHuman
      elsif a_def.return_type
        BindVerdict::Ready
      else
        BindVerdict::NeedsReturn
      end

    inferred = nil
    refused = nil
    if verdict.needs_return?
      inferred, refused = infer_return(owner, a_def)
    end

    BindMethod.new(
      owner: owner.to_s,
      name: a_def.name,
      verdict: verdict,
      block: !a_def.block_arg.nil? || !a_def.block_arity.nil?,
      untyped: a_def.args.select(&.restriction.nil?).map(&.name),
      location: a_def.location.try(&.to_s) || "?",
      inferred: inferred,
      refused: refused,
      params: a_def.args.map { |arg| {arg.name, arg.restriction.try(&.to_s) || "?"} },
      returns: a_def.return_type.try(&.to_s),
    )
  end

  # Instantiate a method nobody called, and read what it returns.
  #
  # This is the whole trick, and it is why a shard's untyped surface is not the
  # wall it looks like. Crystal types a method when something calls it, so a
  # library's own methods have no types until a program uses them — but a
  # method whose parameters are written down can be *called on purpose*, with
  # one synthesised argument per parameter, and the answer is the same answer a
  # real call would have produced.
  #
  # What it cannot do is written down beside what it can. A block is the honest
  # one: its type depends on what the caller passes, so there is no single
  # answer to read.
  private def self.infer_return(owner : Type, a_def : Def) : {String?, String?}
    return {nil, "takes a block"} if a_def.block_arg || a_def.block_arity
    return {nil, "splat"} if a_def.splat_index || a_def.double_splat
    return {nil, "generic type"} if owner.instance_type.is_a?(GenericType)
    return {nil, "abstract"} if a_def.abstract?

    args = [] of ASTNode
    a_def.args.each do |arg|
      restriction = arg.restriction
      return {nil, "no restriction"} unless restriction

      type = owner.lookup_type?(restriction)
      return {nil, "cannot resolve #{restriction}"} unless type
      return {nil, "generic parameter"} if type.is_a?(TypeParameter)

      args << Var.new(arg.name).tap(&.set_type(type.virtual_type))
    end

    receiver = Var.new("self").tap(&.set_type(owner))
    call = Call.new(receiver, a_def.name, args)
    call.scope = owner
    call.recalculate

    type = call.type?
    return {nil, "no type"} unless type

    {type.to_s, nil}
  rescue ex : Crystal::CodeError
    {nil, ex.message.to_s.lines.first?.to_s}
  rescue ex
    {nil, ex.message.to_s.lines.first?.to_s}
  end
end
