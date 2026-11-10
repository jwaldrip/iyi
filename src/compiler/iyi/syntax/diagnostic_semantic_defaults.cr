require "./diagnostic_field_table"

module Iyi
  # Raw-ivar default gate for semantic fields.
  #
  # Each declared semantic field gets one generated check at compile time. The
  # check reads the raw ivar (`node.@field`), never an accessor.
  #
  # Macro API facts this file relies on (Crystal 1.21, compiler/crystal/macros/methods.cr):
  #   MetaVar#name            is the ivar name without "@"; raw access is `node.@{{ name.id }}`
  #   MetaVar#default_value   is NilLiteral when there is no initializer, so a declared
  #                           `= nil` and a missing initializer cannot be told apart
  #   TypeNode#nilable?       reports the reflected type's nilability
  #   StringLiteral#split, ArrayLiteral#includes?, HashLiteral#keys and #[] exist.
  #   `lchop` is not a macro method and is not used.
  #
  # The checks, by reflected default form:
  #   true / false, number       raw value must equal the literal
  #   SmallNodeList.new          raw @first, @second and @tail must all be nil
  #   nil (NilLiteral)           allowed only as an inert nil state: the reflected type
  #                              must be nilable and the raw value must be nil. The
  #                              check never claims an initializer was present.
  #                              A non-nilable field with a nil default always refuses.
  #   no initializer, other      refused
  #
  # Refusals are the fail-closed outcome. Messages are built only on failure, so
  # the success path allocates nothing.
  module DiagnosticSemanticDefaults
    # Base semantic fields that every concrete node carries from ASTNode.
    BASE_SEMANTIC_FIELDS = %w(type dependencies observers enclosing_call dirty)

    # Generates, for every concrete node class:
    #   semantic_check_<Kind>_<field>(node)   one check per declared field
    #   verify!(node)                          dispatches to the checks of the node's class
    #   check_field!(node, field)              runs one named check
    #   declared_semantic_fields(kind)         the declared fields of a kind
    # `base` applies to every kind. `declared` adds fields to individual kinds.
    macro define_semantic_gate(base, declared)
      {% for sub in Iyi::ASTNode.all_subclasses %}
      {% unless sub.abstract? %}
      {% kind = sub.name.split("::").last %}
      {% for ivar in sub.instance_vars %}
      {% name = ivar.name.stringify %}
      {% if base.includes?(name) || (declared.keys.includes?(kind) && declared[kind].includes?(name)) %}
      def self.semantic_check_{{ kind.id }}_{{ name.id }}(node : {{ sub.name.id }}) : Nil
        {% dv = ivar.default_value %}
        {% if !dv %}
          raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: no initializer, so no recognized default")
        {% elsif dv.is_a?(NilLiteral) %}
          {% if ivar.type.nilable? %}
            raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: raw value is not nil, so it is not the inert nil state") unless node.@{{ ivar.name.id }}.nil?
          {% else %}
            raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: a non-nilable field may not carry a nil default")
          {% end %}
        {% elsif dv.is_a?(BoolLiteral) || dv.is_a?(NumberLiteral) %}
          raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: raw value differs from its declared default") unless node.@{{ ivar.name.id }} == {{ dv.stringify.id }}
        {% elsif dv.stringify == "SmallNodeList.new" %}
          list = node.@{{ ivar.name.id }}
          raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: raw list is not empty") unless list && list.@first.nil? && list.@second.nil? && list.@tail.nil?
        {% else %}
          raise ArgumentError.new("{{ kind.id }}.{{ name.id }}: unrecognized default form")
        {% end %}
        nil
      end
      {% end %}
      {% end %}
      {% end %}
      {% end %}

      def self.verify!(node : ASTNode) : Nil
        ensure_coverage!
        {% begin %}
        case node
        {% for sub in Iyi::ASTNode.all_subclasses %}
        {% unless sub.abstract? %}
        {% kind = sub.name.split("::").last %}
        when {{ sub.name.id }}
          {% for ivar in sub.instance_vars %}
          {% name = ivar.name.stringify %}
          {% if base.includes?(name) || (declared.keys.includes?(kind) && declared[kind].includes?(name)) %}
          semantic_check_{{ kind.id }}_{{ name.id }}(node)
          {% end %}
          {% end %}
          nil
        {% end %}
        {% end %}
        else
          raise ArgumentError.new("unclassified AST node #{node.class}")
        end
        {% end %}
      end

      def self.check_field!(node : ASTNode, field : String) : Nil
        {% begin %}
        case node
        {% for sub in Iyi::ASTNode.all_subclasses %}
        {% unless sub.abstract? %}
        {% kind = sub.name.split("::").last %}
        when {{ sub.name.id }}
          case field
          {% for ivar in sub.instance_vars %}
          {% name = ivar.name.stringify %}
          {% if base.includes?(name) || (declared.keys.includes?(kind) && declared[kind].includes?(name)) %}
          when {{ name }}
            semantic_check_{{ kind.id }}_{{ name.id }}(node)
          {% end %}
          {% end %}
          else
            raise ArgumentError.new("#{node.class}.#{field}: not a declared semantic field")
          end
        {% end %}
        {% end %}
        else
          raise ArgumentError.new("unclassified AST node #{node.class}")
        end
        {% end %}
      end

      def self.declared_semantic_fields(kind : String) : Array(String)
        {% begin %}
        case kind
        {% for sub in Iyi::ASTNode.all_subclasses %}
        {% unless sub.abstract? %}
        {% k = sub.name.split("::").last %}
        when {{ k }}
          [{% for f in base %}{{ f }}, {% end %}{% if declared.keys.includes?(k) %}{% for f in declared[k] %}{{ f }}, {% end %}{% end %}] of String
        {% end %}
        {% end %}
        else
          [] of String
        end
        {% end %}
      end
    end

    define_semantic_gate(
      %w(type dependencies observers enclosing_call dirty),
      {
        "Path" => %w(target_const target_type syntax_replacement),
        "Generic" => %w(instance_type scope in_type_args inside_is_a),
        "Union" => %w(inside_is_a),
        "TypeOf" => %w(in_type_args),
        "Arg" => %w(annotations original_name),
        "Def" => %w(annotations owner original_owner vars yield_vars previous next special_vars freeze_type block_nest raises closure self_closured captured_block no_inline always_inline returns_twice target_features target_cpu naked new original_name macro_owner self_restriction_type iyi_declared_return diagnostic_proc_node diagnostic_proc_parent diagnostic_proc_lexical_scope diagnostic_proc_ready diagnostic_proc_computing hook_expansions c_calling_convention abi_info),
        "TupleLiteral" => %w(program),
        "NamedTupleLiteral" => %w(program),
        "ClassVar" => %w(var),
        "Global" => %w(var expanded),
        "Block" => %w(scope vars after_vars context fun_literal freeze_type visited break binder),
        "Call" => %w(before_vars scope with_scope parent_visitor target_defs expanded expanded_macro uses_with_scope subclass_notifier),
        "If" => %w(and or truthy falsey),
        "Assign" => %w(discarded),
        "TypeDeclaration" => %w(discarded),
        "Macro" => %w(annotations owner),
        "While" => %w(break_vars),
        "Yield" => %w(expanded),
        "ProcLiteral" => %w(proc_pointer force_nil expected_return_type from_block),
        "ProcPointer" => %w(call expanded),
        "FunDef" => %w(external),
        "EnumDef" => %w(resolved_type),
        "ClassDef" => %w(hook_expansions resolved_type),
        "Include" => %w(hook_expansions),
        "Extend" => %w(hook_expansions),
        "TraitDef" => %w(resolved_type),
        "ImplDef" => %w(resolved_type),
        "ModuleDef" => %w(resolved_type),
        "LibDef" => %w(resolved_type),
        "CStructOrUnionDef" => %w(resolved_type),
        "Alias" => %w(resolved_type),
        "AnnotationDef" => %w(annotations resolved_type),
        "Return" => %w(target),
        "Break" => %w(target),
        "Next" => %w(target),
        "Cast" => %w(upcast),
        "NilableCast" => %w(upcast non_nilable_type),
        "IsA" => %w(syntax_replacement),
        "Asm" => %w(output_ptrofs),
        "And" => %w(expanded),
        "Or" => %w(expanded),
        "ArrayLiteral" => %w(expanded),
        "HashLiteral" => %w(expanded),
        "RegexLiteral" => %w(expanded),
        "RangeLiteral" => %w(expanded),
        "Case" => %w(expanded),
        "StringInterpolation" => %w(expanded),
        "MacroExpression" => %w(expanded),
        "MacroIf" => %w(expanded),
        "MacroFor" => %w(expanded),
        "MacroVerbatim" => %w(expanded),
        "MultiAssign" => %w(expanded),
        "SizeOf" => %w(expanded),
        "InstanceSizeOf" => %w(expanded),
        "AlignOf" => %w(expanded),
        "InstanceAlignOf" => %w(expanded),
        "OffsetOf" => %w(expanded),
        "Require" => %w(expanded),
        "Select" => %w(expanded),
        "ImportDecl" => %w(expanded),
      }
    )

    # Every concrete node class's reflected ivar names, with no instance needed.
    def self.reflected_fields(kind : String) : Array(String)
      {% begin %}
      case kind
      {% for sub in Iyi::ASTNode.all_subclasses %}
      {% unless sub.abstract? %}
      when {{ sub.name.split("::").last }}
        [{% for ivar in sub.instance_vars %}{{ ivar.name.stringify }}, {% end %}] of String
      {% end %}
      {% end %}
      else
        raise ArgumentError.new("unclassified AST kind #{kind}")
      end
      {% end %}
    end

    # Both directions for every supported kind. The declared semantic fields must
    # equal the table's semantic rows, and each declared field must be reflected.
    # A reflected field with no declaration is not semantic and is left to the census.
    def self.verify_coverage!(table = DiagnosticFieldTable::TABLE) : Nil
      DiagnosticAstFieldSchema::SUPPORTED.each do |kind|
        declared = declared_semantic_fields(kind)
        reflected = reflected_fields(kind)
        table_fields = (table[kind]? || raise ArgumentError.new("#{kind}: no table entry"))
          .select { |row| row.provenance == DiagnosticFieldTable::Provenance::Semantic }
          .map { |row| row.field }
        unless declared.sort == table_fields.sort
          raise ArgumentError.new("#{kind}: declared semantic fields differ from the table (declared #{declared.size}, table #{table_fields.size})")
        end
        declared.each do |field|
          raise ArgumentError.new("#{kind}.#{field}: declared semantic field is not reflected") unless reflected.includes?(field)
        end
      end
      nil
    end

    @@coverage_ok = false

    # Runs `verify_coverage!` once with the real table. A refusal is not memoised,
    # so every later call refuses too.
    def self.ensure_coverage! : Nil
      return if @@coverage_ok
      verify_coverage!
      @@coverage_ok = true
      nil
    end

    # Walks the tree and checks each node. Recursion keeps the success path free of
    # allocation. Depth is bounded by the census limit, so a cycle is refused.
    def self.verify_tree!(node : ASTNode, depth : Int32 = 0) : Nil
      raise ArgumentError.new("semantic gate: tree exceeds depth limit") if depth > DiagnosticAstInventorySnapshot::MAX_DEPTH
      verify!(node)
      DiagnosticDirectChildFields.each(node) { |_field, _index, _key, child| verify_tree!(child, depth + 1) }
      nil
    end
  end
end
