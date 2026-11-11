# iyi: BindReplayAuthority, the live recomputation of a bound projection
# (ProjectionNoRegressionPlan slice S5r, against S1's `recompute`).
#
# The ledger hands `recompute` one request: the site the projection is rendered
# at, the claimed producer, and the source text it covers. This authority answers
# the same question from the live Program and the inputs the caller approved: the
# bind root, the artifact's module name, and the directory of `--use-iyimod`
# artifacts. A claim's fields are never read as answers. A claim names a key (an
# origin, an owner path, a name) that the live program must find, and every
# answered field comes from the program. A live answer that differs from the claim
# is returned as is; the ledger refuses the difference (R4). A program that cannot
# answer, or a live tie that does not hold, raises R2.
#
# Site ties (§3.6 of the revised plan) are checked here as well as at render. At
# render, S1 checks the site kind and declaration tie first (A1), so a broken
# declaration tie is reported as A1 through the ledger, not as R2.
#
# In-process validation only. Compiled-in code can construct any authority it
# likes, so this grants no authentication. An artifact keeps its own holds (H1 to
# H7) whatever this authority admits.
#
# Known limit: bind strips a nested declared path as well as the root
# (`strip_root(text, "Root::Name")`), so the root is not fixed by the source text
# alone. This authority checks that the claimed root is the bind root or a declared
# path under it, that the source begins with it, and, for a nested root, that the
# site lies inside it.
module Iyi
  class BindReplayAuthority < DiagnosticProjectionAuthority
    getter program : Program
    getter root : String
    getter module_name : String
    getter artifact_dir : String?

    def initialize(@program : Program, @root : String, @module_name : String, @artifact_dir : String? = nil)
      super()
    end

    # The live answer for the projection `request` covers, as a fresh producer of
    # the claim's exact class, built from live answers and live origin objects.
    # Any failure raises R2 with the claim's kind.
    def recompute(request : DiagnosticProjectionRequest) : DiagnosticBoundProducer
      claim = request.producer
      live = begin
        answer(request)
      rescue
        nil
      end
      raise DiagnosticProjectionAuthority.refused(claim) unless live
      live
    end

    private def answer(request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      case claim = request.producer
      when DiagnosticBoundProducer::StripRoot
        strip_root_answer(claim, request)
      when DiagnosticBoundProducer::ForeignType
        foreign_type_answer(claim, request)
      when DiagnosticBoundProducer::AliasType
        alias_answer(claim, request)
      when DiagnosticBoundProducer::SelfReturn
        self_return_answer(claim, request)
      when DiagnosticBoundProducer::SemanticSignatureType
        semantic_signature_answer(claim, request)
      when DiagnosticBoundProducer::UninitializedClassVar
        uninitialized_class_var_answer(claim, request)
      when DiagnosticBoundProducer::ConstantAccessor
        constant_accessor_answer(claim, request)
      when DiagnosticBoundProducer::ResolvedRestriction
        resolved_restriction_answer(claim, request)
      when DiagnosticBoundProducer::SynthesizedConstructor
        synthesized_constructor_answer(claim, request)
      when DiagnosticBoundProducer::ConstantTarget
        constant_target_answer(claim, request)
      else
        nil
      end
    end

    # Site ties (§3.6). The site's declaration origin must be the claimed origin.
    # Origins compare structurally, which is the comparison R4 uses.
    private def site_declares?(request : DiagnosticProjectionRequest, origin : DiagnosticOrigin) : Bool
      declared = request.site.declaration_origin
      !declared.nil? && declared == origin
    end

    # The site's kind, as S1 names it. A producer at a kind its rule does not list
    # is refused.
    private def site_kind?(request : DiagnosticProjectionRequest, kinds : Array(String)) : Bool
      kinds.includes?(request.site.kind)
    end

    # The owner the site's key container belongs to (§3.5). Nil for the top level.
    private def site_owner_text(request : DiagnosticProjectionRequest) : String?
      BindSemantics.site_owner(request.site.container, @root, @module_name)
    end

    # bind strips the root, or a declared path under it, from a path that begins
    # with it. The root must be the bind root or a declared path under it. A nested
    # root authorises only sites inside it: the site owner is that root or nested
    # in it. The bind root authorises any site.
    private def strip_root_answer(claim : DiagnosticBoundProducer::StripRoot,
                                  request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil if @root.empty?
      stripped = claim.root
      return nil unless request.source_text.starts_with?("#{stripped}::")
      return nil unless stripped == @root || (stripped.starts_with?("#{@root}::") && declared_path?(stripped))
      unless stripped == @root
        owner = site_owner_text(request) || return nil
        return nil unless owner == stripped || owner.starts_with?("#{stripped}::")
      end
      DiagnosticBoundProducer::StripRoot.new(stripped)
    end

    # The alias of a foreign boundary, recomputed from the artifacts the caller
    # approved, with bind's bare-name rule. The live module and qualified name
    # replace the claim's.
    private def foreign_type_answer(claim : DiagnosticBoundProducer::ForeignType,
                                    request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      old = claim.source_name
      return nil if old.empty?
      return nil unless request.source_text == old || request.source_text.starts_with?("#{old}::")
      bound = foreign_bindings[old]? || return nil
      return nil if bound[1] == old
      DiagnosticBoundProducer::ForeignType.new(bound[0], old, bound[1])
    end

    # The alias must be the owner's own, written in the shard, and its devirtualised
    # target is the live answer. The site must belong to the owner.
    private def alias_answer(claim : DiagnosticBoundProducer::AliasType,
                             request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      name = claim.name
      return nil if name.empty? || request.source_text != name
      return nil unless site_owner_text(request) == claim.owner
      owner = lookup_owner(claim.owner) || return nil
      target = owner.types?.try(&.[]?(name))
      return nil unless target.is_a?(AliasType)
      return nil if library_type?(target)
      aliased = target.aliased_type? || return nil
      DiagnosticBoundProducer::AliasType.new(owner.to_s, name, aliased.devirtualize.to_s)
    end

    # A metaclass `new` answering `self`. Bind writes it only when the class declares
    # a constant of its own name, so that is what is recomputed. A signature site of
    # the owner.
    private def self_return_answer(claim : DiagnosticBoundProducer::SelfReturn,
                                   request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless site_kind?(request, ["signature"])
      owner_text = claim.owner_type
      return nil unless request.source_text == owner_text
      return nil unless site_owner_text(request) == owner_text
      owner = lookup_owner(owner_text) || return nil
      own_name = owner_text.split("::").last
      return nil unless owner.types?.try(&.[]?(own_name)).is_a?(Const)
      DiagnosticBoundProducer::SelfReturn.new(owner_text, "new", "self")
    end

    # The semantic type of one slot of a signature: a parameter restriction or a
    # return. For a def, the answer is the restriction as bind resolves it, or the
    # instantiated return when none was written (K10). A return the program cannot
    # answer is refused, not guessed. For a constant accessor, the answer is the
    # constant's devirtualised value type, named as bind names it (K9).
    private def semantic_signature_answer(claim : DiagnosticBoundProducer::SemanticSignatureType,
                                          request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless request.source_text.empty?
      return nil unless site_kind?(request, ["signature"])
      origin = claim.definition_origin
      return nil unless site_declares?(request, origin)
      return nil unless origin.valid_for_anchor?("Def", "keyword")
      return nil unless {"parameter_restriction", "return_type"}.includes?(claim.field)

      if accessor = constant_accessor_declaration(origin)
        live_origin, constant = accessor
        return nil unless claim.field == "return_type" && claim.parameter_index.nil?
        value_type = constant.value.type?.try(&.devirtualize.to_s) || return nil
        named = BindSemantics.global_name(value_type, @root, crystal_types)
        return DiagnosticBoundProducer::SemanticSignatureType.new(live_origin, claim.field, nil, named)
      end

      matches = defs_with_origin(origin)
      return nil unless matches.size == 1
      owner, written = matches[0]
      live_origin = written.diagnostic_origin || return nil
      a_def = BindSemantics.with_ancestor_types(owner, written)
      semantic = semantic_type_of(owner, a_def, claim.field, claim.parameter_index) || return nil
      DiagnosticBoundProducer::SemanticSignatureType.new(live_origin, claim.field, claim.parameter_index, semantic)
    end

    private def semantic_type_of(owner : Type, a_def : Def, field : String, index : Int32?) : String?
      case field
      when "parameter_restriction"
        return nil unless index && index >= 0 && index < a_def.args.size
        restriction = a_def.args[index].restriction || return nil
        decision_target(owner, restriction)
      when "return_type"
        return nil unless index.nil?
        if written = a_def.return_type
          decision_target(owner, written)
        else
          inferred, _, _ = BindSemantics.infer_return(owner, a_def, @root, crystal_types)
          inferred
        end
      end
    end

    # The class variable is the owner's own, carries the declaration the claim names
    # (C4), has no initializer, and its type is not nilable. Its site is a class_var
    # site of the owner, named as the variable.
    private def uninitialized_class_var_answer(claim : DiagnosticBoundProducer::UninitializedClassVar,
                                               request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless request.source_text.empty?
      return nil unless site_kind?(request, ["class_var"])
      return nil unless site_declares?(request, claim.declaration_origin)
      return nil unless request.site.name == claim.variable_name
      return nil unless site_owner_text(request) == claim.owner_type
      owner = lookup_owner(claim.owner_type) || return nil
      class_vars = owner.responds_to?(:class_vars) ? owner.class_vars : nil
      return nil unless class_vars
      variable = class_vars[claim.variable_name]? || return nil
      live_origin = variable.iyi_class_var_declaration_origin
      return nil unless live_origin == claim.declaration_origin
      return nil unless variable.initializer.nil?
      type = variable.type
      return nil if nilable?(type)
      DiagnosticBoundProducer::UninitializedClassVar.new(live_origin, claim.owner_type,
        claim.variable_name, type.devirtualize.to_s)
    end

    # An accessor for a constant is the constant's own getter. Its origin is a
    # Synthetic one built from the constant's live declaration origin, so the claim's
    # origin must be exactly that.
    private def constant_accessor_answer(claim : DiagnosticBoundProducer::ConstantAccessor,
                                         request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless request.source_text.empty?
      return nil unless site_kind?(request, ["signature"])
      return nil unless site_declares?(request, claim.definition_origin)
      return nil unless {"Name", "Receiver"}.includes?(claim.part)
      accessor = constant_accessor_declaration(claim.definition_origin) || return nil
      live_origin, constant = accessor
      namespace, name = constant_location(constant) || return nil
      relative = relative_namespace(namespace) || return nil
      prefix = relative.empty? ? "" : "#{relative.gsub("::", "_")}_"
      DiagnosticBoundProducer::ConstantAccessor.new(live_origin, prefix, name, claim.part)
    end

    # A nested type's written restriction, resolved and qualified the way bind
    # resolves it. The written text must be the source, the decision must give a
    # different target than the written text, and the owner must be the site's owner
    # (for a metaclass, the owner text may carry `.class`).
    private def resolved_restriction_answer(claim : DiagnosticBoundProducer::ResolvedRestriction,
                                            request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless site_kind?(request, ["signature"])
      written_text = claim.written_type
      return nil unless request.source_text == written_text
      site_owner = site_owner_text(request) || return nil
      owner_text = claim.owner_type
      return nil unless owner_text == site_owner || owner_text == "#{site_owner}.class"
      metaclass = owner_text.ends_with?(".class")
      base = metaclass ? owner_text.rchop(".class") : owner_text
      named = lookup_owner(base) || return nil
      owner : Type = metaclass ? named.metaclass : named
      node = parse_type(written_text) || return nil
      written, target, resolved, add_global = BindSemantics.resolve_restriction_decision(owner, node, true, @root, crystal_types)
      return nil unless written == written_text && target && resolved
      return nil if written == target
      DiagnosticBoundProducer::ResolvedRestriction.new(owner_text, written_text, resolved, @root, add_global)
    end

    # A metaclass `new` synthesised from an `initialize`. Default-argument `new`
    # expansions share the initialize's origin (`semantic/new.cr`), so several `new`
    # defs may carry the one origin. They must all belong to one owner.
    private def synthesized_constructor_answer(claim : DiagnosticBoundProducer::SynthesizedConstructor,
                                               request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless request.source_text.empty?
      return nil unless site_kind?(request, ["signature"])
      return nil unless {"definition_name", "local_reference"}.includes?(claim.part)
      return nil unless site_declares?(request, claim.definition_origin)
      origin = claim.definition_origin
      return nil unless origin.valid_for_anchor?("Def", "keyword")
      owners = named_types.select { |type| !origin_defs(type.metaclass, "new", origin).empty? }
      return nil unless owners.size == 1
      initializers = origin_defs(owners[0], "initialize", origin)
      return nil if initializers.empty?
      live_origin = initializers[0].diagnostic_origin || return nil
      DiagnosticBoundProducer::SynthesizedConstructor.new(live_origin, claim.part)
    end

    # A constant's own declaration. Its path is its owner chain relative to the root,
    # plus its name, and the declaration must be the claimed one.
    private def constant_target_answer(claim : DiagnosticBoundProducer::ConstantTarget,
                                       request : DiagnosticProjectionRequest) : DiagnosticBoundProducer?
      return nil unless request.source_text.empty?
      return nil unless site_kind?(request, ["constant"])
      return nil unless site_declares?(request, claim.declaration_origin)
      return nil unless claim.declaration_origin.valid_for_anchor?("Assign", "constant")
      declared = constants_with_origin(claim.declaration_origin)
      return nil unless declared.size == 1
      namespace, name, constant = declared[0]
      live_origin = constant.iyi_declaration_origin || return nil
      relative = relative_namespace(namespace) || return nil
      path = relative.empty? ? name : "#{relative}::#{name}"
      DiagnosticBoundProducer::ConstantTarget.new(live_origin, path)
    end

    # The constant a Synthetic constant-accessor origin was made from, and the origin
    # built from that constant's live declaration. Nil for any other origin.
    private def constant_accessor_declaration(origin : DiagnosticOrigin) : {DiagnosticOrigin, Const}?
      return nil unless origin.is_a?(DiagnosticOrigin::Synthetic)
      return nil unless origin.synthesis_kind == "constant_accessor" && origin.structural_slot == "getter"
      declared = constants_with_origin(origin.parent_origin)
      return nil unless declared.size == 1
      constant = declared[0][2]
      parent = constant.iyi_declaration_origin || return nil
      live = DiagnosticOrigin::Synthetic.new(parent, "constant_accessor", "getter")
      return nil unless live == origin
      {live, constant}
    end

    private def constant_location(constant : Const) : {String, String}?
      parent = constant.iyi_declaration_origin || return nil
      declared = constants_with_origin(parent)
      return nil unless declared.size == 1
      namespace, name, _ = declared[0]
      {namespace, name}
    end

    # Bind's rule for the type a written restriction answers to, applied to one node.
    # A proc notation has no single answer this replay recomputes.
    private def decision_target(owner : Type, node : ASTNode) : String?
      return nil if node.is_a?(ProcNotation)
      written, target, _, _ = BindSemantics.resolve_restriction_decision(owner, node, true, @root, crystal_types)
      written ? target : nil
    end

    # The bare names each `--use-iyimod` artifact in the approved directory
    # contributes, with the module and qualified name they map to. Recomputed per call
    # from the artifacts, with bind's rule. Later artifacts win, as in bind.
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

    # A type the program declares under this qualified path. Every segment must be a
    # named type.
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

    # The defs whose origin is this one, with the container each sits in.
    private def defs_with_origin(origin : DiagnosticOrigin) : Array({Type, Def})
      found = [] of {Type, Def}
      named_types.each do |type|
        [type, type.metaclass].each do |container|
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

    # The constants whose declaration origin is this one. The origin is set only under
    # diagnostic capture, so an unregistered origin matches nothing.
    private def constants_with_origin(origin : DiagnosticOrigin) : Array({String, String, Const})
      found = [] of {String, String, Const}
      constants_under(@program.types?, "", found)
      found.select { |(_, _, constant)| constant.iyi_declaration_origin == origin }
    end

    # Every constant the program declares, as its namespace, its name and the constant.
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

    # The namespace of a constant, written relative to the root. The root itself is the
    # empty string. Nil when the namespace lies outside the root.
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

    # Parses canonical type text only, so a printed form that does not round-trip is
    # refused.
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

    # A type written in Crystal's library is not the shard's. Its locations decide,
    # against the directory of the prelude the program required.
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
