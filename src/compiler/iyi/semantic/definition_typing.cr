# iyi: definition-site typing — the language rule the `check` probe grew
# up into.
#
# Lazy typing (inherited from Crystal) types a def when somebody calls
# it, so a build said "clean" about a body it never visited. For one
# release that hole was patched in a verb: `iyi check` appended a text
# probe and compiled twice. This file is the same idea made a *rule of
# the language*: every fully declared def in user code is typed at its
# definition, in the same compile as everything else — build, `check`,
# artifact emit, and every LSP keystroke agree about what "clean" means.
#
# The probes are synthesized *after* the top-level pass, from resolved
# types, and that placement is load-bearing — a parse-time draft failed
# twice in ways worth keeping on record:
#
# - `def describe(e : Enumerable)` is fully written and still not
#   probeable: a trait restriction makes the def generic (the body types
#   per call, Crystal's own semantics), and no parser can know which
#   names are traits. Here the restriction is *resolved* first, and
#   trait, abstract, module and uninstantiated-generic parameters put
#   the def honestly out of reach.
# - Probes visible to the top-level visitor met the macro expander
#   without a scope and crashed on the kemal port. Appended here, only
#   the main pass ever sees them.
#
# Mechanism: for each eligible def, a snippet at *global* scope — the
# resolved type names are absolute, so it types anywhere — calling it
# once with `uninitialized` values of the declared types, under
# `if false` so nothing can ever run. Instance methods get an
# `uninitialized Owner` receiver; module functions are called on the
# module itself. Every node is stamped with the def's own location, so
# a probe-found error anchors at the def it belongs to. R-2 is what
# makes all of this possible: a written signature is exactly enough to
# type a body without a caller, and Crystal cannot offer the rule
# precisely because Crystal does not require the writing.
#
# Scope: user files only — the entry and everything it imports. `.cr`
# sources keep Crystal's lazy rule (that language did not promise
# otherwise), and the prelude is not re-probed on every build it never
# changes in.
require "../syntax/ast"

module Iyi::DefinitionTyping
  def self.append_probes(program : Program, node : ASTNode) : Nil
    return unless node.is_a?(Expressions)

    files = user_files(program)
    return if files.empty?

    serial = 0
    probes = [] of ASTNode

    each_owner(program) do |owner|
      defs = owner.defs
      next unless defs
      defs.each_value do |overloads|
        overloads.each do |with_metadata|
          a_def = with_metadata.def
          filename = a_def.location.try(&.filename).as?(String)
          next unless filename && filename.ends_with?(".iyi") && files.includes?(filename)
          serial += 1
          if probe = synthesize(program, owner, a_def, serial)
            probes << probe
          end
        end
      end
    end

    return if probes.empty?
    node.expressions.concat(probes)
  end

  # The entry file plus everything it imported: exactly the code this
  # build is responsible for. The prelude and `--crystal` sources never
  # appear here.
  private def self.user_files(program : Program) : Set(String)
    files = Set(String).new
    if entry = program.filename
      files << entry
    end
    program.iyi_module_imports.each do |file, imports|
      files << file
      imports.each { |imported| files << imported }
    end
    files
  end

  # Every type that can own a probeable def: the program itself (a
  # script's top-level defs), non-generic modules that are not traits,
  # and concrete classes and structs. Generic and abstract types keep
  # caller-typed bodies — there is no one receiver to make.
  private def self.each_owner(program : Program, & : Type ->) : Nil
    yield program
    walk_types(program) do |type|
      case type
      when NonGenericModuleType
        yield type unless type.trait?
      when NonGenericClassType
        yield type unless type.abstract?
      else
        # Not an owner the probe can stand a receiver up for.
      end
    end
  end

  private def self.walk_types(container : Type, & : Type ->) : Nil
    queue = [] of Type
    if types = container.types?
      types.each_value { |type| queue << type }
    end
    while type = queue.pop?
      yield type
      if types = type.types?
        types.each_value { |inner| queue << inner }
      end
    end
  end

  # One def's probe, or nil when the declaration does not say enough:
  # a snippet parsed alone, every node stamped with the def's location.
  private def self.synthesize(program : Program, owner : Type, a_def : Def, serial : Int32) : ASTNode?
    return nil unless probable?(a_def)
    location = a_def.location
    return nil unless location

    # The probe calls from *outside*, so it can only honestly reach what
    # outside reaches. An impl-carried def is out entirely: R-3 keeps it
    # inside its trait context, and a direct call on the target type
    # would type the body without the impl's own siblings in scope — the
    # collections sample's `<=>` found that the hard way. A non-`pub`
    # module function is behind R-2's wall; a `private` method behind
    # Crystal's. Those bodies stay caller-typed, which is the truth of
    # their reachability, said rather than worked around.
    return nil if a_def.iyi_from_impl?
    case owner
    when NonGenericModuleType
      return nil unless a_def.exported?
    else
      return nil unless a_def.visibility.public?
    end

    # Every type the snippet prints must be *nameable from global
    # scope*: the probe lives at the program's top level, and R-2's wall
    # blocks naming a non-`pub` type of a unit from outside — a spec
    # with a private `struct User` taught that the wall applies to
    # probes exactly as it applies to people.
    return nil unless nameable?(owner)

    argument_types = [] of Type
    a_def.args.each do |arg|
      restriction = arg.restriction
      return nil unless restriction
      resolved = resolve(owner, restriction)
      return nil unless resolved && instantiable?(resolved) && nameable?(resolved)
      argument_types << resolved
    end

    lines = [] of String
    names = argument_types.map_with_index do |argument_type, index|
      name = "__iyi_dt_#{serial}_#{index}"
      lines << "#{name} = uninitialized #{argument_type}"
      name
    end

    call =
      case owner
      when Program
        "#{a_def.name}(#{names.join(", ")})"
      when NonGenericModuleType
        "#{owner}.#{a_def.name}(#{names.join(", ")})"
      else
        receiver = "__iyi_dt_#{serial}_r"
        lines << "#{receiver} = uninitialized #{owner}"
        "#{receiver}.#{a_def.name}(#{names.join(", ")})"
      end

    # The return is verified when the declared type can be a variable;
    # a def honestly declared to return a trait still gets its body
    # typed, just not the assignment check.
    returned = a_def.return_type.try { |written| resolve(owner, written) }
    if returned && instantiable?(returned) && nameable?(returned) && !returned.nil_type?
      lines << "__iyi_dt_#{serial}_v : #{returned} = #{call}"
    else
      lines << call
    end

    parser = Parser.new("if false\n#{lines.join('\n')}\nend\n")
    parser.filename = location.filename
    parsed = parser.parse
    parsed.accept(Stamper.new(location))
    parsed
  rescue Iyi::CodeError
    # A type whose printed name does not re-parse (rare, and its own
    # bug elsewhere): the def stays caller-typed rather than the build
    # failing over a probe.
    nil
  end

  private def self.resolve(owner : Type, written : ASTNode) : Type?
    owner.lookup_type?(written)
  rescue Iyi::CodeError
    nil
  end

  # A type an `uninitialized` variable can hold: concrete, this-world,
  # every union member included. Virtual types devirtualize first so an
  # abstract root answers as itself.
  private def self.instantiable?(type : Type) : Bool
    type = type.devirtualize
    if type.is_a?(UnionType)
      return type.union_types.all? { |member| instantiable?(member) }
    end
    return false if type.is_a?(GenericType)
    return false if type.module?
    return false if type.abstract?
    return false if type.is_a?(NoReturnType) || type.is_a?(VoidType)
    return false if type.metaclass?
    true
  end

  # Whether the type's printed name resolves from the program's top
  # level. The climb mirrors the R-2 check itself: crossing into an iyi
  # unit requires the unit to export the name; everything else (nested
  # types of pub types, prelude types, unions, generic instances) is a
  # matter of walking the pieces.
  private def self.nameable?(type : Type) : Bool
    type = type.devirtualize
    if type.is_a?(UnionType)
      return type.union_types.all? { |member| nameable?(member) }
    end
    if type.is_a?(GenericClassInstanceType)
      return false unless nameable?(type.generic_type)
      return type.type_vars.each_value.all? do |var|
        !var.is_a?(Type) || nameable?(var)
      end
    end
    current = type
    while current.is_a?(NamedType)
      namespace = current.namespace
      # `Program` is its own namespace (constructed `super(self, self,
      # "main")`); walking past it loops forever — call.cr's using walk
      # carries the same warning.
      break if namespace == current
      if namespace.iyi_unit? && !namespace.exported_name?(current.name)
        return false
      end
      break unless namespace.is_a?(NamedType)
      current = namespace
    end
    true
  end

  # A def the probe can honestly call: every parameter carries a written
  # type, the return is written, and there is no shape the probe cannot
  # synthesise — no block, no splats, no free vars, no defaults, no
  # receiver (`self.` defs need no receiver made, and macros made them),
  # a plainly callable name.
  private def self.probable?(a_def : Def) : Bool
    return false if a_def.block_arity || a_def.block_arg
    return false if a_def.splat_index || a_def.double_splat
    return false if (free_vars = a_def.free_vars) && !free_vars.empty?
    return false unless a_def.return_type
    return false if a_def.abstract?
    return false if a_def.receiver
    return false if a_def.name == "initialize"
    return false unless a_def.name.each_char.all? { |ch| ch.alphanumeric? || ch == '_' || ch.in?('?', '!') }
    return false unless a_def.name[0].lowercase? || a_def.name[0] == '_'
    a_def.args.all? do |arg|
      arg.restriction && !arg.default_value && arg.external_name == arg.name
    end
  end

  # Sets every node's location to the def the probe belongs to, so the
  # error a probe finds points at the definition rather than at a
  # synthetic line no file contains — and marks every call as the
  # compiler's own, so reference answers never count it.
  private class Stamper < Visitor
    def initialize(@location : Location)
    end

    def visit(node : ASTNode) : Bool
      node.at(@location)
      node.iyi_synthetic = true if node.is_a?(Call)
      true
    end
  end
end
