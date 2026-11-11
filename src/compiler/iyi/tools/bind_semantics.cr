# iyi: the semantic questions `tool bind` asks of a shard, as functions of their
# explicit inputs. Nothing here reads or writes the bind tool's own state.
module Iyi
  module BindSemantics
  # `Log` written `::Log`, where leaving it bare would find something else.
  #
  # An artifact's declarations are rendered *inside* the module they belong to,
  # so a bare name is looked up there first. `Kemal::Log` is a constant and
  # `::Log` is Crystal's class, and an accessor declared to return `Log` inside
  # `module Kemal` finds the constant: *`Kemal::Log` is not a type, it's a
  # constant*. Only a top-level name can be shadowed this way, and only a name
  # of Crystal's — the shard's own are reached through the root on purpose.
  #
  # The *head* of a path, not only a bare name, and that took `db` to find. It
  # writes `def self.arg_to_log(arg) : ::Log::Metadata::Value` — with the `::`,
  # because a shard's author meets this too — and a declaration resolving that
  # to `Log::Metadata::Value` put the same shadowing one segment along:
  # `undefined constant Log::Metadata::Value`, read inside a module that has a
  # `Log` of its own. What can be shadowed is the first name in the path, so
  # that is the one asked about.
  def self.global_name(name : String, root : String, crystal_types : Set(String)) : String
    return name if name.starts_with?("::")

    head = name.partition("::")[0]
    return name if head == root || head.empty?
    return name unless crystal_types.includes?(head)
    "::#{name}"
  end

  def self.crystal_library_types(program : Program) : {Set(String), Set(String)}
    names = Set(String).new
    private_names = Set(String).new
    library = program.requires.find(&.ends_with?("prelude.cr"))
    return {names, private_names} unless library
    root = File.dirname(library)

    collect_crystal_types program.types?, "", root, names, private_names
    {names, private_names}
  end

  private def self.collect_crystal_types(types : Hash(String, Type)?, prefix : String,
                                         root : String, names : Set(String),
                                         private_names : Set(String),
                                         hidden : Bool = false) : Nil
    return unless types

    types.each do |name, type|
      next unless type.is_a?(NamedType)
      written_here = type.locations.try(&.any? { |location| location.read_from.to_s.starts_with?(root) })
      next unless written_here || type.types?

      # A `private` type of the library is not a name a consumer can write.
      # `Log::ProcFormatter` is one, and `EMail`'s
      # `def self.client_log_formatter : ::Log::ProcFormatter` was carried as
      # surface because this table said the name was available: the fill build
      # then stopped on `private constant Log::ProcFormatter referenced`, and
      # the whole shard did not bind over one def nobody outside could have
      # called anyway.
      #
      # It goes in the other table instead, because a *value* of it can cross
      # even where the name cannot: `Log::Formatter.new { }` answers one, and
      # `EMail::Client::LOG_FORMATTER` is that call. See `nameable_value?`.
      inside = hidden || type.private?
      if written_here
        (inside ? private_names : names) << "#{prefix}#{name}"
      end
      collect_crystal_types type.types?, "#{prefix}#{name}::", root, names, private_names, inside
    end
  end

  # The abstract `def` this one answers, in a module the type includes or a
  # class it inherits from.
  #
  # An abstract def is a written signature, which is the one thing a shard's
  # own implementation is allowed to leave out: `HTTP::Handler` writes
  # `abstract def call(context : HTTP::Server::Context)` and kemal's handlers
  # write `def call(context) : Nil`. R-2 says this already for iyi's own impls
  # — "the trait already wrote the types down, and a consumer types the call
  # from the trait rather than from here" — and the same sentence is true of a
  # Crystal module's abstract method.
  #
  # Matched on name and arity only. Anything finer would be overload resolution
  # against a signature that by construction has no overloads to resolve
  # against: an abstract def is the one shape the ancestor demands.
  def self.abstract_ancestor_def(owner : Type, a_def : Def) : Def?
    ancestors = owner.responds_to?(:ancestors) ? owner.ancestors : nil
    return nil unless ancestors

    ancestors.each do |ancestor|
      defs = ancestor.as?(ModuleType).try &.defs
      next unless defs
      defs[a_def.name]?.try &.each do |item|
        other = item.def
        next unless other.abstract?
        next unless other.args.size == a_def.args.size
        next if other.args.any? { |arg| arg.restriction.nil? }
        return other
      end
    end
    nil
  end

  # This def, with the types its ancestor wrote where the shard wrote none.
  #
  # A copy, because the tree belongs to the program being read and the rest of
  # this tool has to keep seeing what the shard actually wrote.
  def self.with_ancestor_types(owner : Type, a_def : Def) : Def
    missing = a_def.args.any? { |arg| arg.restriction.nil? } || a_def.return_type.nil?
    return a_def unless missing
    other = abstract_ancestor_def(owner, a_def)
    return a_def unless other

    copy = a_def.clone
    copy.location = a_def.location
    copy.args.each_with_index do |arg, index|
      arg.restriction = other.args[index].restriction.try(&.clone) if arg.restriction.nil?
    end

    # And the return, for the reason the parameters take: the requirement
    # already wrote the type down, and an override is held to it.
    # `db` writes `abstract def build_unprepared_statement(query) : Stmt` and
    # `sqlite3` writes `def build_unprepared_statement(query)`, so a
    # declaration without the return said less than the language requires:
    # `this method overrides … which has an explicit return type of Stmt.
    # Please add an explicit return type to this method as well`.
    copy.return_type = other.return_type.try(&.clone) if copy.return_type.nil?
    copy
  end

  # Resolve once before constructing any diagnostic producer. Semantic lookup
  # failure retains the original source spelling, as the ordinary path does.
  def self.resolve_restriction_decision(owner : Type, node : ASTNode?, qualify : Bool,
                                        root : String, crystal_types : Set(String)) : {String?, String?, String?, Bool}
    return {nil, nil, nil, false} unless node
    written = node.to_s
    return {written, written, written, false} if written == "_"
    if node.is_a?(Self)
      resolved = owner.instance_type.devirtualize.to_s
      return {written, resolved, resolved, false}
    end

    if node.is_a?(Metaclass)
      inner = resolve_restriction_decision(owner, node.name, qualify, root, crystal_types)[1]
      resolved = inner ? "#{inner}.class" : written
      return {written, resolved, resolved, false}
    end

    type = owner.lookup_type?(node)
    return {written, written, written, false} unless type
    return {written, written, written, false} if type.is_a?(TypeParameter) || type.is_a?(GenericType)

    resolved = type.devirtualize.to_s
    target = qualify ? global_name(resolved, root, crystal_types) : resolved
    {written, target, resolved, target != resolved}
  rescue
    written = node.try(&.to_s)
    {written, written, written, false}
  end

  # A block of the annotated shape, for a call nobody wrote.
  #
  # The arguments carry no types: a block literal takes them from the method
  # being called, which is the thing being instantiated. The body has to be of
  # the annotated output type, and `uninitialized` is how you name a value of a
  # type without building one — the same answer the keep file's text gives.
  private def self.synthesize_block(owner : Type, restriction : ASTNode,
                                    root : String, crystal_types : Set(String)) : Block?
    return nil unless restriction.is_a?(ProcNotation)

    inputs = restriction.inputs || [] of ASTNode
    args = inputs.map_with_index { |_, index| Var.new("__bind_b#{index}") }

    output = restriction.output
    body =
      if output.nil? || output.to_s == "Nil"
        NilLiteral.new
      else
        # Resolved against the owner, because the call this block goes into is
        # typed by a visitor whose scope is the *program*. `db` writes
        # `&factory : -> Connection` inside `DB`, and `uninitialized Connection`
        # visited at the top level is `undefined constant Connection` — which
        # this tool read as "the method does not compile" and dropped
        # `Database#initialize`, the one thing a consumer builds a `Database`
        # with.
        # Unqualified, because `global: true` is what makes this absolute and
        # the two together are one `::` too many: `::Int32` split on `::`
        # leaves an empty first segment, and the path printed `::::Int32`.
        written = resolve_restriction_decision(owner, output, false, root, crystal_types)[1] || output.to_s
        UninitializedVar.new(Var.new("__bind_block_result"), Path.new(written.split("::"), global: true))
      end

    Block.new(args, body)
  end

  # Instantiate a method nobody called, and hand back the call.
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
  # The third value says the refusal was the *compiler's* — the method does not
  # compile — as against this tool declining to ask. A method that cannot be
  # checked because its block is unannotated is fine and travels; one whose body
  # does not typecheck is not, and declaring it puts the failure in the keep
  # file, where it takes the whole artifact down with it.
  def self.instantiate(owner : Type, a_def : Def, root : String,
                       crystal_types : Set(String)) : {Call?, String?, Bool}
    # A block whose own type is written is not the problem; one whose output is
    # `_`, or which was never annotated, is. What such a method returns depends
    # on what the caller passes, and there is no single answer to read.
    block = nil
    if block_arg = a_def.block_arg
      restriction = block_arg.restriction
      return {nil, "block is not annotated", false} unless restriction
      return {nil, "block returns `_`", false} if restriction.to_s.includes?("_")

      # And then hand the call one, which this did not do.
      #
      # A method that takes a block is called *with* a block or it is not
      # called: `JSON::Builder#string` has an overload taking a value and one
      # taking a block, so a synthesised call with neither matched the first
      # and answered `wrong number of arguments (given 0, expected 1)`. The
      # method's own return type was then the one thing on the boundary
      # standing on the shard's word, which is the whole of what rule 1 is
      # about, over a block the annotation had already described.
      #
      # The keep file has written exactly this block as text since blocks
      # first crossed — `{ |b0| nil }`, or an `uninitialized` of the output
      # where the output is not `Nil`. This is the same block as a node.
      block = synthesize_block owner, restriction, root, crystal_types
      return {nil, "block shape not understood", false} unless block
    end
    return {nil, "yields without a block parameter", false} if a_def.block_arity && !a_def.block_arg
    return {nil, "splat", false} if a_def.splat_index || a_def.double_splat
    return {nil, "generic type", false} if owner.instance_type.is_a?(GenericType)
    return {nil, "abstract", false} if a_def.abstract?

    args = [] of ASTNode
    a_def.args.each do |arg|
      restriction = arg.restriction
      return {nil, "no restriction", false} unless restriction

      type = owner.lookup_type?(restriction)
      return {nil, "cannot resolve #{restriction}", false} unless type
      return {nil, "generic parameter", false} if type.is_a?(TypeParameter)

      # `Class` is every metaclass there is, and there is no end to them:
      # `Foo.class`, `Foo.class.class`, and so on for as long as anybody asks.
      # A real caller writes `Log.for(MyThing)` and names one; a call
      # synthesised here would hand the compiler the whole family and ask it to
      # enumerate them, which is `Log.for(type : Class)` recursing through
      # `Call#recalculate` until the stack ends. The `Program#iyi_instantiation_limit`
      # this tool sets is what turns that into a diagnosis rather than a crash;
      # this is what keeps it from being asked.
      return {nil, "unbounded receiver", false} if type == owner.program.class_type

      args << Var.new(arg.name).tap(&.set_type(type.virtual_type))
    end

    receiver = Var.new("self").tap(&.set_type(owner))
    call = Call.new(receiver, a_def.name, args, block)
    call.scope = owner
    # A block's body is code, and code is visited. A blockless call never
    # needed one and so this was never set; with a block attached the compiler
    # says so plainly — `Iyi::Call#parent_visitor cannot be nil`.
    call.parent_visitor = MainVisitor.new(owner.program)
    call.recalculate
    {call, nil, false}
  rescue ex : Iyi::CodeError
    {nil, ex.message.to_s.lines.first?.to_s, true}
  rescue ex
    {nil, ex.message.to_s.lines.first?.to_s, true}
  ensure
    # Whatever happened, this tool's next question starts from the top. An
    # instantiation that stopped part way — refused, or found not to terminate
    # — leaves the counter where it stopped, and the depth is per *question*.
    owner.program.iyi_instantiation_depth = 0
  end

  # The name a boundary's type answers to once a consumer imports it: `prefix` is
  # the module path, camelcased, and a class root has none.
  def self.bound_name(prefix : String, name : String) : String
    prefix.empty? ? name : "#{prefix}::#{name}"
  end

  # Whether a name a boundary declares can be recorded bare. Not when Crystal's
  # library or the builtins already own that spelling, not when it is the root
  # itself, and not when the shard declares it under the root: `yield` answers that.
  def self.bare_bound_name?(name : String, root : String, crystal_types : Set(String),
                            builtin : Set(String), & : String -> Bool) : Bool
    return false if crystal_types.includes?(name) || builtin.includes?(name)
    return false if name == root
    !yield name
  end
  end
end
