# iyi: BindReplayAuthority, the closed-set replay of a bound projection
# (BoundProvenancePlan §3.3, slice S5r).
#
# A producer is admitted only when every field it carries is recomputed here
# from the live Program and the two inputs the caller approved: the bind root
# and the directory of `--use-iyimod` artifacts. Nothing is read from
# `BindMethod`, from bind's `@@` state, or from a field the producer reports
# about its own semantics. A producer whose origin is not registered in the
# live program is refused, because there is nothing for it to be checked
# against.
#
# This is in-memory validation only. It grants no external trust. An artifact
# keeps its own holds (H1 to H7) whatever this authority admits.
module Iyi
  class BindReplayAuthority < DiagnosticProjectionAuthority
    getter program : Program
    getter root : String
    getter artifact_dir : String?

    def initialize(@program : Program, @root : String, @artifact_dir : String? = nil)
      super()
    end

    # Returns when the producer is admitted. Raises `bound projection replay refused`
    # with the producer's kind otherwise, including when recomputation itself fails.
    def replay!(producer : DiagnosticBoundProducer, source_text : String) : Nil
      admitted = begin
        recompute(producer, source_text)
      rescue
        false
      end
      raise DiagnosticProjectionAuthority.refused(producer) unless admitted
    end

    private def recompute(producer : DiagnosticBoundProducer, source : String) : Bool
      case producer
      when DiagnosticBoundProducer::StripRoot
        strip_root_admitted?(producer, source)
      when DiagnosticBoundProducer::ForeignType
        foreign_type_admitted?(producer, source)
      when DiagnosticBoundProducer::AliasType
        alias_admitted?(producer, source)
      when DiagnosticBoundProducer::SelfReturn
        self_return_admitted?(producer, source)
      when DiagnosticBoundProducer::SemanticSignatureType
        semantic_signature_admitted?(producer, source)
      when DiagnosticBoundProducer::UninitializedClassVar
        uninitialized_class_var_admitted?(producer, source)
      when DiagnosticBoundProducer::ConstantAccessor
        constant_accessor_admitted?(producer, source)
      when DiagnosticBoundProducer::ResolvedRestriction
        resolved_restriction_admitted?(producer, source)
      when DiagnosticBoundProducer::SynthesizedConstructor
        synthesized_constructor_admitted?(producer, source)
      when DiagnosticBoundProducer::ConstantTarget
        constant_target_admitted?(producer, source)
      else
        false
      end
    end

    # The bind root itself, or a declaration path under it that the program
    # really declares. The source must begin with the stripped prefix.
    private def strip_root_admitted?(producer : DiagnosticBoundProducer::StripRoot, source : String) : Bool
      return false if @root.empty?
      root = producer.root
      return false unless source.starts_with?("#{root}::")
      return true if root == @root
      root.starts_with?("#{@root}::") && declared_path?(root)
    end

    # The alias of a foreign boundary. Recomputed from the artifacts the caller
    # approved, with the same bare-name rule bind applies, minus names the shard
    # declares itself. The name must be a top-level declaration that the
    # artifact actually carries, and its qualified form must differ from it.
    private def foreign_type_admitted?(producer : DiagnosticBoundProducer::ForeignType, source : String) : Bool
      old = producer.source_name
      return false if old.empty? || producer.module_name.empty? || producer.qualified_name == old
      return false unless source == old || source.starts_with?("#{old}::")
      bound = foreign_bindings[old]? || return false
      bound[0] == producer.module_name && bound[1] == producer.qualified_name
    end

    # The alias must be written in the shard, not in Crystal's library, and its
    # devirtualised target must be the answer the producer reports.
    private def alias_admitted?(producer : DiagnosticBoundProducer::AliasType, source : String) : Bool
      name = producer.name
      return false if name.empty? || source != name
      owner = lookup_owner(producer.owner) || return false
      target = owner.types?.try(&.[]?(name))
      return false unless target.is_a?(AliasType)
      return false if library_type?(target)
      aliased = target.aliased_type? || return false
      aliased.devirtualize.to_s == producer.resolved_type
    end

    # A metaclass `new` answering `self`. Bind only writes it when the class
    # declares a constant of its own name, so that is what is recomputed.
    private def self_return_admitted?(producer : DiagnosticBoundProducer::SelfReturn, source : String) : Bool
      owner_text = producer.owner_type
      return false unless source == owner_text && producer.method_name == "new" && producer.receiver == "self"
      owner = lookup_owner(owner_text) || return false
      own_name = owner_text.split("::").last
      owner.types?.try(&.[]?(own_name)).is_a?(Const)
    end

    # Recomputed from the one def the origin names. The answer is the written
    # restriction or return type, resolved the way bind resolves a restriction.
    # A return with no written type has no answer this replay can recompute,
    # so it is refused.
    private def semantic_signature_admitted?(producer : DiagnosticBoundProducer::SemanticSignatureType, source : String) : Bool
      return false unless source.empty? && producer.definition_origin.valid_for_anchor?("Def", "keyword")
      matches = defs_with_origin(producer.definition_origin)
      return false unless matches.size == 1
      owner, a_def = matches[0]
      case producer.field
      when "parameter_restriction"
        index = producer.parameter_index || return false
        return false unless index >= 0 && index < a_def.args.size
        restriction = a_def.args[index].restriction || return false
        decision_target(owner, restriction) == producer.semantic_type
      when "return_type"
        return false unless producer.parameter_index.nil?
        restriction = a_def.return_type || return false
        decision_target(owner, restriction) == producer.semantic_type
      else
        false
      end
    end

    # The class variable is the owner's own, has no initializer, and its type is
    # not nilable.
    private def uninitialized_class_var_admitted?(producer : DiagnosticBoundProducer::UninitializedClassVar, source : String) : Bool
      return false unless source.empty? && !producer.semantic_type.empty?
      owner = lookup_owner(producer.owner_type) || return false
      class_vars = owner.responds_to?(:class_vars) ? owner.class_vars : nil
      return false unless class_vars
      variable = class_vars[producer.variable_name]? || return false
      return false unless variable.initializer.nil?
      type = variable.type
      return false if nilable?(type)
      type.devirtualize.to_s == producer.semantic_type
    end

    # An accessor for a constant is the constant's own getter. The constant is
    # found through the origin its declaration carries, and the accessor's prefix
    # and name are recomputed from the constant's place under the root.
    private def constant_accessor_admitted?(producer : DiagnosticBoundProducer::ConstantAccessor, source : String) : Bool
      return false unless source.empty? && !producer.constant_name.empty?
      origin = producer.definition_origin
      return false unless origin.is_a?(DiagnosticOrigin::Synthetic)
      return false unless origin.synthesis_kind == "constant_accessor" && origin.structural_slot == "getter"
      return false unless origin.valid_for_anchor?("Def", "keyword")
      return false unless ["Name", "Receiver"].includes?(producer.part)
      declared = constants_with_origin(origin.parent_origin)
      return false unless declared.size == 1
      namespace, name, _ = declared[0]
      return false unless name == producer.constant_name
      relative = relative_namespace(namespace) || return false
      prefix = relative.empty? ? "" : "#{relative.gsub("::", "_")}_"
      prefix == producer.prefix
    end

    # A nested type's written restriction, resolved and qualified the way bind
    # resolves it. Every field must match what the decision gives.
    private def resolved_restriction_admitted?(producer : DiagnosticBoundProducer::ResolvedRestriction, source : String) : Bool
      written_text = producer.written_type
      return false unless source == written_text && producer.root == @root
      owner = lookup_owner(producer.owner_type) || return false
      node = parse_type(written_text) || return false
      written, target, resolved, add_global = BindSemantics.resolve_restriction_decision(owner, node, true, @root, crystal_types)
      return false unless written == written_text && target && resolved
      return false if written == target
      resolved == producer.resolved_type && add_global == producer.add_global
    end

    # A metaclass `new` synthesised from an `initialize`. Both must carry the one origin.
    private def synthesized_constructor_admitted?(producer : DiagnosticBoundProducer::SynthesizedConstructor, source : String) : Bool
      return false unless source.empty? && ["definition_name", "local_reference"].includes?(producer.part)
      origin = producer.definition_origin
      return false unless origin.valid_for_anchor?("Def", "keyword")
      owners = named_types.select { |type| origin_defs(type.metaclass, "new", origin).size == 1 }
      return false unless owners.size == 1
      origin_defs(owners[0], "initialize", origin).size == 1
    end

    # A constant's own declaration. Its path is its owner chain relative to the
    # root, plus its name.
    private def constant_target_admitted?(producer : DiagnosticBoundProducer::ConstantTarget, source : String) : Bool
      return false unless source.empty? && producer.declaration_origin.valid_for_anchor?("Assign", "constant")
      declared = constants_with_origin(producer.declaration_origin)
      return false unless declared.size == 1
      namespace, name, _ = declared[0]
      relative = relative_namespace(namespace) || return false
      expected = relative.empty? ? name : "#{relative}::#{name}"
      producer.path == expected
    end

    # Bind's rule for the qualified name a restriction answers to, applied to
    # one node. Proc notation has no single answer this replay recomputes.
    private def decision_target(owner : Type, node : ASTNode) : String?
      return nil if node.is_a?(ProcNotation)
      written, target, _, _ = BindSemantics.resolve_restriction_decision(owner, node, true, @root, crystal_types)
      written ? target : nil
    end

    # The bare names each `--use-iyimod` artifact in the approved directory
    # contributes, with the module and qualified name they map to. Recomputed
    # per call, from the artifacts, with the rule bind applies: a name the
    # program declares, bare or under the module prefix, that is not a Crystal
    # or builtin name, and that the shard does not declare under its root.
    # Later artifacts win, as they do in bind.
    private def foreign_bindings : Hash(String, {String, String})
      bindings = {} of String => {String, String}
      dir = @artifact_dir
      return bindings unless dir

      crystal = crystal_types
      builtin = @program.builtin_type_names
      Dir.glob(Iyi.glob_root(dir).join("*.iyimod")).sort.each do |path|
        artifact = begin
          IyiMod.read(path)
        rescue
          next
        end

        found = Set(String).new
        artifact.exports.types.each { |declaration| collect_known_names(declaration, "", found) }
        prefix = artifact.class_root ? "" : artifact.module_name.split('/').map(&.camelcase).join("::")
        bare = found.select do |name|
          qualified = BindSemantics.bound_name(prefix, name)
          (declared_path?(name) || declared_path?(qualified)) &&
            BindSemantics.bare_bound_name?(name, @root, crystal, builtin) { |candidate| declared_path?("#{@root}::#{candidate}") }
        end

        artifact.exports.types.each do |declaration|
          next unless bare.includes?(declaration.name)
          bindings[declaration.name] = {artifact.module_name, BindSemantics.bound_name(prefix, declaration.name)}
        end
      end
      bindings
    end

    private def collect_known_names(declaration : IyiMod::TypeDecl, prefix : String, known : Set(String)) : Nil
      known << "#{prefix}#{declaration.name}"
      declaration.types.each do |nested|
        collect_known_names(nested, "#{prefix}#{declaration.name}::", known)
      end
    end

    # A type the program declares under this qualified path. Every segment must
    # be a named type.
    private def declared_path?(qualified : String) : Bool
      table = @program.types?
      qualified.split("::").each do |part|
        return false unless table
        type = table[part]?
        return false unless type.is_a?(NamedType)
        table = type.types?
      end
      true
    end

    # The named type this path writes, and only when its text is exactly the path.
    private def lookup_owner(path : String) : NamedType?
      return nil if path.empty?
      table = @program.types?
      owner : NamedType? = nil
      path.split("::").each do |segment|
        return nil unless table
        found = table[segment]?
        return nil unless found.is_a?(NamedType)
        owner = found
        table = found.types?
      end
      return nil unless owner && owner.to_s == path
      owner
    end

    # The namespace of a constant, written relative to the root. The root itself is
    # the empty string. Nil when the namespace lies outside the root.
    private def relative_namespace(namespace : String) : String?
      return "" if namespace == @root
      return nil if @root.empty?
      return namespace.lchop("#{@root}::") if namespace.starts_with?("#{@root}::")
      nil
    end

    # Every named type in the program, nested ones included.
    private def named_types : Array(NamedType)
      found = [] of NamedType
      collect_named_types(@program.types?, found)
      found
    end

    private def collect_named_types(table : Hash(String, Type)?, found : Array(NamedType)) : Nil
      return unless table
      table.each_value do |type|
        next unless type.is_a?(NamedType)
        found << type
        collect_named_types(type.types?, found)
      end
    end

    # Every constant the program declares, as its namespace, its name and the
    # constant itself.
    private def constants_under(table : Hash(String, Type)?, namespace : String, found : Array({String, String, Const})) : Nil
      return unless table
      table.each do |name, type|
        if type.is_a?(Const)
          found << {namespace, name, type}
        elsif type.is_a?(NamedType)
          constants_under(type.types?, namespace.empty? ? name : "#{namespace}::#{name}", found)
        end
      end
    end

    # The constants whose declaration origin is this one. The origin is set only
    # under diagnostic capture, so an unregistered origin matches nothing.
    private def constants_with_origin(origin : DiagnosticOrigin) : Array({String, String, Const})
      found = [] of {String, String, Const}
      constants_under(@program.types?, "", found)
      found.select { |(_, _, constant)| constant.iyi_declaration_origin == origin }
    end

    # The defs whose origin is this one, with the container each sits in.
    private def defs_with_origin(origin : DiagnosticOrigin) : Array({Type, Def})
      found = [] of {Type, Def}
      named_types.each do |type|
        containers = [] of Type
        containers << type
        containers << type.metaclass
        containers.each do |container|
          module_type = container.as?(ModuleType)
          next unless module_type
          defs = module_type.defs
          next unless defs
          defs.each_value do |items|
            items.each do |item|
              a_def = item.def
              found << {container, a_def} if a_def.diagnostic_origin == origin
            end
          end
        end
      end
      found
    end

    # The defs the container names `name`, whose origin is this one.
    private def origin_defs(container : Type?, name : String, origin : DiagnosticOrigin) : Array(Def)
      module_type = container.as?(ModuleType)
      return [] of Def unless module_type
      defs = module_type.defs
      return [] of Def unless defs
      listed = defs[name]?
      return [] of Def unless listed
      listed.map { |item| item.def }.select { |a_def| a_def.diagnostic_origin == origin }
    end

    # Bind's rule for the type a written restriction answers to, applied to a
    # type this replay parses itself, with the root and crystal set it
    # computes. Parses canonical text only, so a printed form that does not
    # round-trip is refused.
    private def parse_type(text : String) : ASTNode?
      return nil if text.empty?
      parser = Parser.new(text)
      parser.filename = "bind-replay.iyi"
      parser.next_token
      node = parser.parse_bare_proc_type
      node.to_s == text ? node : nil
    rescue
      nil
    end

    # Names Crystal's library declares, computed from the program alone.
    private def crystal_types : Set(String)
      BindSemantics.crystal_library_types(@program)[0]
    end

    # True for the nil type and for a union that holds it.
    private def nilable?(type : Type) : Bool
      nil_type = type.program.nil_type
      return true if type == nil_type
      type.is_a?(UnionType) && type.union_types.includes?(nil_type)
    end

    # A type written in Crystal's library is not the shard's. Its locations
    # decide, against the directory of the prelude the program required.
    private def library_type?(type : Type) : Bool
      library = @program.requires.find(&.ends_with?("prelude.cr"))
      return false unless library
      root = File.dirname(library)
      locations = type.responds_to?(:locations) ? type.locations : nil
      return false unless locations && !locations.empty?
      locations.all? do |location|
        filename = location.read_from
        filename.is_a?(String) && filename.starts_with?(root)
      end
    end
  end
end
