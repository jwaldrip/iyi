require "./diagnostic_capture"

module Iyi
  # Field table for the diagnostic AST capture (planner contract C6).
  #
  # Every row records two things. Its provenance says where the field is
  # declared: `Syntax` for a declaration in the syntax files (ast.cr and the
  # node base), `Semantic` for one a compiler file adds by reopening the node.
  # Its shape says how it is framed. Framed rows are the presence list, in
  # writer order, and are always `Syntax`. Base rows are the fields every node
  # carries from ASTNode. Infrastructure rows are classified but never framed.
  #
  # The census has two scopes. A syntax-only build sees only `Syntax` rows. A
  # full-compiler build sees both. Each scope is checked against its own census.
  #
  # Nothing here reads source text at runtime. Semantic rows are never framed,
  # so their nilability and type are left nil. `verify!` refuses an incomplete
  # or inconsistent table.
  module DiagnosticFieldTable
    enum Role
      Child
      Name
      Scalar
      Evidence
      Infrastructure
    end

    enum Coordinate
      Single
      Indexed
      Keyed
    end

    enum Presence
      # Writer emits Present. The declaration is not nilable.
      Always
      # Writer emits Absent or Present. The declaration is nilable.
      Optional
      # Writer emits Absent, Empty or Nonempty.
      Collection
    end

    enum Provenance
      # Declared in the syntax files.
      Syntax
      # Added by a compiler file that reopens the node.
      Semantic
    end

    enum Scope
      # A syntax-only build: only Syntax rows are in scope.
      Syntax
      # A full-compiler build: every row is in scope.
      Full
    end

    record Row,
      field : String,
      klass : DiagnosticAstFieldClass,
      role : Role,
      coordinate : Coordinate,
      presence : Presence?,
      nilable : Bool?,
      scalar : String?,
      provenance : Provenance = Provenance::Syntax,
      base : Bool = false do
      def framed? : Bool
        !base && role != Role::Infrastructure
      end
    end

    # One child or name entry in a frame. `base` is the field before the first
    # dot, and `sub` is what follows it ("key", "value" or empty).
    record Stub, base : String, sub : String, index : Int32?, key : String?, child : Bool

    # Fields every node carries from ASTNode, declared in ast.cr.
    SYNTAX_BASE = %w(
      location end_location diagnostic_origin diagnostic_macro_lineage
      diagnostic_name_slots diagnostic_literal_names diagnostic_literal_productions
      diagnostic_external_explicit diagnostic_capture_ref diagnostic_percent_witnesses
    )

    # Base fields that compiler files add to ASTNode.
    SEMANTIC_BASE = %w(type dependencies observers enclosing_call dirty)

    BASE_FIELDS = SYNTAX_BASE + SEMANTIC_BASE

    # Fields that compiler files add to reopened syntax nodes. Each was checked
    # against its declaration, which is noted by file. They are infrastructure, so
    # they are never framed. Their types and nilability are not claimed.
    SEMANTIC_FIELDS = {
      # semantic/ast.cr: ExpandableNode is included by these kinds (lines 788-801)
      "And" => %w(expanded), "Or" => %w(expanded), "ArrayLiteral" => %w(expanded),
      "HashLiteral" => %w(expanded), "RegexLiteral" => %w(expanded), "RangeLiteral" => %w(expanded),
      "Case" => %w(expanded), "StringInterpolation" => %w(expanded),
      "MacroExpression" => %w(expanded), "MacroIf" => %w(expanded), "MacroFor" => %w(expanded),
      "MacroVerbatim" => %w(expanded), "MultiAssign" => %w(expanded),
      "SizeOf" => %w(expanded), "InstanceSizeOf" => %w(expanded), "AlignOf" => %w(expanded),
      "InstanceAlignOf" => %w(expanded), "OffsetOf" => %w(expanded), "Global" => %w(expanded),
      "Require" => %w(expanded), "Select" => %w(expanded), "ImportDecl" => %w(expanded),
      # semantic/bindings.cr:871
      "Block" => %w(binder),
      # semantic/call.cr:6-12 and 1965
      "Call" => %w(scope with_scope parent_visitor target_defs expanded expanded_macro uses_with_scope subclass_notifier),
      # codegen/ast.cr:11, 121-122; semantic/hooks.cr:49-50 (HookExpansionsContainer, lines 90, 108, 125)
      "Def" => %w(hook_expansions c_calling_convention abi_info),
      # semantic/hooks.cr:72 (ClassDef); 90 (Include); 108 (Extend)
      "ClassDef" => %w(hook_expansions resolved_type),
      "Include" => %w(hook_expansions), "Extend" => %w(hook_expansions),
      # semantic/ast.cr:803-831
      "TraitDef" => %w(resolved_type), "ImplDef" => %w(resolved_type), "ModuleDef" => %w(resolved_type),
      "LibDef" => %w(resolved_type), "CStructOrUnionDef" => %w(resolved_type), "Alias" => %w(resolved_type),
      # semantic/ast.cr:833-837 (includes Annotatable, which declares annotations in src/compiler/iyi/annotatable.cr:4)
      "AnnotationDef" => %w(annotations resolved_type),
      # semantic/ast.cr:772-782
      "Return" => %w(target), "Break" => %w(target), "Next" => %w(target),
      # semantic/bindings.cr:479, 535-536
      "Cast" => %w(upcast), "NilableCast" => %w(upcast non_nilable_type),
      # semantic/ast.cr:785
      "IsA" => %w(syntax_replacement),
      # semantic/ast.cr:907
      "Asm" => %w(output_ptrofs),
    } of String => Array(String)

    def self.role_for(klass : DiagnosticAstFieldClass) : Role
      case klass
      when DiagnosticAstFieldClass::Child, DiagnosticAstFieldClass::ChildList,
           DiagnosticAstFieldClass::NamedChildMap, DiagnosticAstFieldClass::IndexedChildMap,
           DiagnosticAstFieldClass::Record, DiagnosticAstFieldClass::RecordList
        Role::Child
      when DiagnosticAstFieldClass::NamedValue
        Role::Name
      when DiagnosticAstFieldClass::SyntaxScalar
        Role::Scalar
      when DiagnosticAstFieldClass::OriginEvidence
        Role::Evidence
      when DiagnosticAstFieldClass::Infrastructure
        Role::Infrastructure
      else
        raise ArgumentError.new("unmapped field class #{klass}")
      end
    end

    # The class of a base field. Mirrors the classifier's generic entries.
    def self.base_class(kind : String, field : String) : DiagnosticAstFieldClass
      case field
      when "location", "end_location", "diagnostic_origin", "diagnostic_macro_lineage",
           "diagnostic_name_slots", "diagnostic_literal_names", "diagnostic_literal_productions"
        DiagnosticAstFieldClass::OriginEvidence
      when "diagnostic_external_explicit"
        kind == "Arg" ? DiagnosticAstFieldClass::OriginEvidence : DiagnosticAstFieldClass::Infrastructure
      when "diagnostic_capture_ref", "diagnostic_percent_witnesses", "dependencies",
           "observers", "enclosing_call", "dirty", "type"
        DiagnosticAstFieldClass::Infrastructure
      else
        raise ArgumentError.new("not a base field: #{field}")
      end
    end

    # Nilability of a base field where the declaration proves it. nil means unproven.
    def self.base_nilable(field : String) : Bool?
      case field
      when "location", "end_location", "diagnostic_origin", "diagnostic_name_slots",
           "diagnostic_literal_names", "diagnostic_literal_productions",
           "diagnostic_capture_ref", "diagnostic_percent_witnesses"
        true
      when "diagnostic_macro_lineage", "diagnostic_external_explicit"
        false
      else
        nil
      end
    end

    def self.base_provenance(field : String) : Provenance
      SYNTAX_BASE.includes?(field) ? Provenance::Syntax : Provenance::Semantic
    end

    private def self.presence_of(name : Symbol) : Presence
      case name
      when :always     then Presence::Always
      when :optional   then Presence::Optional
      when :collection then Presence::Collection
      else                  raise ArgumentError.new("unknown presence #{name}")
      end
    end

    private def self.coordinate_of(name : Symbol) : Coordinate
      case name
      when :single  then Coordinate::Single
      when :indexed then Coordinate::Indexed
      when :keyed   then Coordinate::Keyed
      else               raise ArgumentError.new("unknown coordinate #{name}")
      end
    end

    private def self.framed(field : String, klass : DiagnosticAstFieldClass, presence : Symbol, nilable : Bool, coordinate : Symbol, scalar : String?) : Row
      Row.new(field, klass, role_for(klass), coordinate_of(coordinate), presence_of(presence), nilable, scalar)
    end

    private def self.ch(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::Child, presence, nilable, :single, nil)
    end

    private def self.chl(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::ChildList, presence, nilable, :indexed, nil)
    end

    private def self.ncm(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::NamedChildMap, presence, nilable, :keyed, nil)
    end

    private def self.icm(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::IndexedChildMap, presence, nilable, :indexed, nil)
    end

    private def self.rec(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::Record, presence, nilable, :single, nil)
    end

    private def self.recl(field : String, presence : Symbol, nilable : Bool) : Row
      framed(field, DiagnosticAstFieldClass::RecordList, presence, nilable, :indexed, nil)
    end

    private def self.nv(field : String, presence : Symbol, nilable : Bool, coordinate : Symbol = :single) : Row
      framed(field, DiagnosticAstFieldClass::NamedValue, presence, nilable, coordinate, nil)
    end

    private def self.sc(field : String, presence : Symbol, nilable : Bool, scalar : String) : Row
      framed(field, DiagnosticAstFieldClass::SyntaxScalar, presence, nilable, :single, scalar)
    end

    private def self.ev(field : String, presence : Symbol, nilable : Bool, coordinate : Symbol = :single) : Row
      framed(field, DiagnosticAstFieldClass::OriginEvidence, presence, nilable, coordinate, nil)
    end

    # Infrastructure declared in the syntax files.
    private def self.sinf(field : String) : Row
      Row.new(field, DiagnosticAstFieldClass::Infrastructure, Role::Infrastructure, Coordinate::Single, nil, nil, nil, Provenance::Syntax)
    end

    # Infrastructure added by a compiler file.
    private def self.inf(field : String) : Row
      Row.new(field, DiagnosticAstFieldClass::Infrastructure, Role::Infrastructure, Coordinate::Single, nil, nil, nil, Provenance::Semantic)
    end

    private def self.sinfras(names : Array(String)) : Array(Row)
      names.map { |name| sinf(name) }
    end

    private def self.infras(names : Array(String)) : Array(Row)
      names.map { |name| inf(name) }
    end

    # The base rows of one kind, one per base field.
    private def self.base_rows(kind : String) : Array(Row)
      BASE_FIELDS.map do |field|
        klass = base_class(kind, field)
        Row.new(field, klass, role_for(klass), Coordinate::Single, nil, base_nilable(field), nil, base_provenance(field), true)
      end
    end

    private def self.table : Hash(String, Array(Row))
      raw = {
        "Path" => [
          nv("names", :collection, false, :indexed),
          sc("global", :always, false, "bool"),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ] + sinfras(%w(iyi_from_artifact iyi_synthetic)) + infras(%w(target_const target_type syntax_replacement)),

        "Generic" => [
          ch("name", :always, false),
          chl("type_vars", :collection, false),
          chl("named_args", :collection, true),
          sc("suffix", :always, false, "Generic::Suffix"),
        ] + infras(%w(instance_type scope in_type_args inside_is_a)),

        "Union" => [
          chl("types", :collection, false),
          sc("parens", :always, false, "bool"),
        ] + infras(%w(inside_is_a)),

        "TypeOf" => [
          chl("expressions", :collection, false),
        ] + infras(%w(in_type_args)),

        "ProcNotation" => [
          chl("inputs", :collection, true),
          ch("output", :optional, true),
        ],

        "Arg" => [
          nv("name", :always, false),
          nv("external_name", :always, false),
          ch("default_value", :optional, true),
          ch("restriction", :optional, true),
          chl("parsed_annotations", :collection, true),
          sc("doc", :optional, true, "bytes?"),
        ] + infras(%w(annotations original_name)),

        "NamedArgument" => [
          nv("name", :always, false),
          ch("value", :always, false),
        ],

        "Def" => [
          nv("name", :always, false),
          nv("free_vars", :collection, true, :indexed),
          ncm("free_var_bounds", :collection, true),
          ncm("where_bounds", :collection, true),
          ch("receiver", :optional, true),
          chl("args", :collection, false),
          ch("double_splat", :optional, true),
          ch("body", :always, false),
          ch("block_arg", :optional, true),
          ch("return_type", :optional, true),
          sc("block_arity", :optional, true, "int32?"),
          sc("splat_index", :optional, true, "int32?"),
          sc("doc", :optional, true, "bytes?"),
          ev("name_location", :optional, true),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
          sc("iyi_from_impl", :always, false, "bool"),
          sc("macro_def", :always, false, "bool"),
          sc("abstract", :always, false, "bool"),
          sc("calls_super", :always, false, "bool"),
          sc("calls_initialize", :always, false, "bool"),
          sc("calls_previous_def", :always, false, "bool"),
          sc("uses_block_arg", :always, false, "bool"),
          sc("assigns_special_var", :always, false, "bool"),
        ] + sinfras(%w(
          iyi_from_artifact iyi_body_travelled iyi_compiler_made iyi_origin
          diagnostic_specialization_json diagnostic_specialization_unusable
          iyi_open_travel iyi_defer iyi_from_derive iyi_share_block iyi_observer_wrapped
          effect iyi_share_serial iyi_share_crossing iyi_share_elements
        )) + infras(%w(
          annotations owner original_owner vars yield_vars previous next special_vars
          freeze_type block_nest raises closure self_closured captured_block no_inline
          always_inline returns_twice target_features target_cpu naked new original_name
          macro_owner self_restriction_type iyi_declared_return
          diagnostic_proc_node diagnostic_proc_parent diagnostic_proc_lexical_scope
          diagnostic_proc_ready diagnostic_proc_computing
        )),

        "Nop" => [] of Row,
        "NilLiteral" => [] of Row,
        "ImplicitObj" => [] of Row,
        "Self" => [] of Row,
        "Underscore" => [] of Row,

        "Expressions" => [
          chl("expressions", :collection, false),
          sc("keyword", :always, false, "Expressions::Keyword"),
        ],

        "BoolLiteral" => [
          sc("value", :always, false, "bool"),
        ],

        "NumberLiteral" => [
          sc("value", :always, false, "bytes"),
          sc("kind", :always, false, "NumberKind"),
        ],

        "CharLiteral" => [
          sc("value", :always, false, "char"),
        ],

        "StringLiteral" => [
          sc("value", :always, false, "bytes"),
        ],

        "SymbolLiteral" => [
          nv("value", :always, false),
        ],

        "MacroLiteral" => [
          sc("value", :always, false, "bytes"),
        ],

        "StringInterpolation" => [
          chl("expressions", :collection, false),
          sc("heredoc_indent", :always, false, "int32"),
        ],

        "ArrayLiteral" => [
          chl("elements", :collection, false),
          ch("of", :optional, true),
          ch("name", :optional, true),
        ],

        "TupleLiteral" => [
          chl("elements", :collection, false),
        ] + infras(%w(program)),

        "RangeLiteral" => [
          ch("from", :always, false),
          ch("to", :always, false),
          sc("exclusive", :always, false, "bool"),
        ],

        "RegexLiteral" => [
          ch("value", :always, false),
          sc("options", :always, false, "RegexOptions"),
        ],

        "HashLiteral" => [
          recl("entries", :collection, false),
          rec("of", :optional, true),
          ch("name", :optional, true),
        ],

        "NamedTupleLiteral" => [
          recl("entries", :collection, false),
        ] + infras(%w(program)),

        "Var" => [
          nv("name", :always, false),
          sc("doc", :optional, true, "bytes?"),
        ],

        "InstanceVar" => [
          nv("name", :always, false),
        ],

        "ClassVar" => [
          nv("name", :always, false),
        ] + infras(%w(var)),

        "Global" => [
          nv("name", :always, false),
        ] + infras(%w(var)),

        "ReadInstanceVar" => [
          ch("obj", :always, false),
          nv("name", :always, false),
        ],

        "Block" => [
          chl("args", :collection, false),
          ch("body", :always, false),
          sc("splat_index", :optional, true, "int32?"),
          icm("unpacks", :collection, true),
        ] + sinfras(%w(call diagnostic_specialization_json diagnostic_specialization_unusable)) + infras(%w(scope vars after_vars context fun_literal freeze_type visited break)),

        "Call" => [
          ch("obj", :optional, true),
          nv("name", :always, false),
          chl("args", :collection, false),
          chl("named_args", :collection, true),
          ch("block", :optional, true),
          ch("block_arg", :optional, true),
          sc("doc", :optional, true, "bytes?"),
          ev("name_location", :optional, true),
          ev("iyi_after_floor_div", :optional, true),
          sc("visibility", :always, false, "Visibility"),
          sc("global", :always, false, "bool"),
          sc("expansion", :always, false, "bool"),
          sc("args_in_brackets", :always, false, "bool"),
          sc("has_parentheses", :always, false, "bool"),
          sc("iyi_group", :always, false, "bool"),
          sc("iyi_banged", :always, false, "bool"),
        ] + sinfras(%w(name_size iyi_synthetic iyi_compiler_expansion iyi_open_dispatch)) + infras(%w(before_vars)),

        "If" => [
          ch("cond", :always, false),
          ch("then", :always, false),
          ch("else", :always, false),
          ev("else_location", :optional, true),
          sc("ternary", :always, false, "bool"),
        ] + sinfras(%w(iyi_definition_probe)) + infras(%w(and or truthy falsey)),

        "Unless" => [
          ch("cond", :always, false),
          ch("then", :always, false),
          ch("else", :always, false),
          ev("else_location", :optional, true),
        ],

        "Assign" => [
          ch("target", :always, false),
          ch("value", :always, false),
          sc("doc", :optional, true, "bytes?"),
        ] + infras(%w(discarded)),

        "OpAssign" => [
          ch("target", :always, false),
          ch("value", :always, false),
          nv("op", :always, false),
          ev("name_location", :optional, true),
        ],

        "MultiAssign" => [
          chl("targets", :collection, false),
          chl("values", :collection, false),
        ],

        "And" => [
          ch("left", :always, false),
          ch("right", :always, false),
        ],

        "Or" => [
          ch("left", :always, false),
          ch("right", :always, false),
        ],

        "Macro" => [
          nv("name", :always, false),
          chl("args", :collection, false),
          ch("body", :always, false),
          ch("double_splat", :optional, true),
          ch("block_arg", :optional, true),
          sc("splat_index", :optional, true, "int32?"),
          sc("doc", :optional, true, "bytes?"),
          ev("name_location", :optional, true),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ] + infras(%w(annotations owner)),

        "Not" => [ch("exp", :always, false)],
        "PointerOf" => [ch("exp", :always, false)],
        "SizeOf" => [ch("exp", :always, false)],
        "InstanceSizeOf" => [ch("exp", :always, false)],
        "AlignOf" => [ch("exp", :always, false)],
        "InstanceAlignOf" => [ch("exp", :always, false)],
        "Out" => [ch("exp", :always, false)],
        "MacroVerbatim" => [ch("exp", :always, false)],
        "Splat" => [ch("exp", :always, false)],
        "DoubleSplat" => [ch("exp", :always, false)],
        "Propagate" => [ch("exp", :always, false)],
        "Defer" => [ch("exp", :always, false)],

        "Return" => [
          ch("exp", :optional, true),
        ] + sinfras(%w(from_propagate)),

        "Break" => [
          ch("exp", :optional, true),
        ],

        "Next" => [
          ch("exp", :optional, true),
        ],

        "OffsetOf" => [
          ch("offsetof_type", :always, false),
          ch("offset", :always, false),
        ],

        "VisibilityModifier" => [
          ch("exp", :always, false),
          sc("modifier", :always, false, "Visibility"),
          sc("doc", :optional, true, "bytes?"),
        ],

        "IsA" => [
          ch("obj", :always, false),
          ch("const", :always, false),
          sc("nil_check", :always, false, "bool"),
          sc("error_construct", :optional, true, "bytes?"),
          sc("iyi_bang_call", :optional, true, "bytes_pair?"),
        ],

        "RespondsTo" => [
          ch("obj", :always, false),
          nv("name", :always, false),
        ],

        "Require" => [
          sc("string", :always, false, "bytes"),
        ] + sinfras(%w(iyi_prelude)),

        "When" => [
          chl("conds", :collection, false),
          ch("body", :always, false),
          sc("exhaustive", :always, false, "bool"),
        ],

        "Case" => [
          ch("cond", :optional, true),
          chl("whens", :collection, false),
          ch("else", :optional, true),
          sc("exhaustive", :always, false, "bool"),
          sc("binds_it", :always, false, "bool"),
        ],

        "Select" => [
          chl("whens", :collection, false),
          ch("else", :optional, true),
        ],

        "While" => [
          ch("cond", :always, false),
          ch("body", :always, false),
        ] + infras(%w(break_vars)),

        "Until" => [
          ch("cond", :always, false),
          ch("body", :always, false),
        ],

        "Rescue" => [
          ch("body", :always, false),
          chl("types", :collection, true),
          nv("name", :optional, true),
        ],

        "ExceptionHandler" => [
          ch("body", :always, false),
          chl("rescues", :collection, true),
          ch("else", :optional, true),
          ch("ensure", :optional, true),
          sc("implicit", :always, false, "bool"),
          sc("suffix", :always, false, "bool"),
          ev("else_location", :optional, true),
          ev("ensure_location", :optional, true),
        ] + sinfras(%w(iyi_defer)),

        "Yield" => [
          chl("exps", :collection, false),
          ch("scope", :optional, true),
          sc("has_parentheses", :always, false, "bool"),
        ] + infras(%w(expanded)),

        "ClassDef" => [
          ch("name", :always, false),
          ch("body", :always, false),
          ch("superclass", :optional, true),
          nv("type_vars", :collection, true, :indexed),
          ev("name_location", :optional, true),
          sc("doc", :optional, true, "bytes?"),
          sc("splat_index", :optional, true, "int32?"),
          sc("abstract", :always, false, "bool"),
          sc("struct", :always, false, "bool"),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ],

        "TraitDef" => [
          ch("name", :always, false),
          ch("body", :always, false),
          nv("type_vars", :collection, true, :indexed),
          nv("assoc_types", :collection, true, :indexed),
          chl("supertraits", :collection, true),
          ev("name_location", :optional, true),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ],

        "Recover" => [
          ch("exp", :always, false),
          ch("default", :optional, true),
        ],

        "AssocTypeDecl" => [
          nv("name", :always, false),
          ch("value", :optional, true),
          sc("in_type_body", :always, false, "bool"),
          sc("doc", :optional, true, "bytes?"),
          ev("name_location", :optional, true),
        ],

        "ImplDef" => [
          ch("trait", :always, false),
          ch("target", :always, false),
          ch("body", :always, false),
          chl("trait_args", :collection, true),
          nv("type_vars", :collection, true, :indexed),
          ncm("type_var_bounds", :collection, true),
          ncm("assoc_types", :collection, true),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          ev("name_location", :optional, true),
        ],

        "ModuleHeader" => [
          nv("path", :collection, false, :indexed),
        ],

        "ImportDecl" => [
          nv("path", :collection, false, :indexed),
          nv("names", :collection, true, :indexed),
          ev("name_locations", :collection, true, :indexed),
          sc("exported", :always, false, "bool"),
          sc("glob", :always, false, "bool"),
        ],

        "UsingDecl" => [
          nv("path", :collection, false, :indexed),
          nv("names", :collection, true, :indexed),
          ev("name_locations", :collection, true, :indexed),
        ],

        "ModuleDef" => [
          ch("name", :always, false),
          ch("body", :always, false),
          nv("type_vars", :collection, true, :indexed),
          sc("splat_index", :optional, true, "int32?"),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          sc("iyi_unit", :always, false, "bool"),
          ev("name_location", :optional, true),
        ],

        "AnnotationDef" => [
          ch("name", :always, false),
          sc("doc", :optional, true, "bytes?"),
          sc("exported", :always, false, "bool"),
          ev("name_location", :optional, true),
        ],

        "TypeDeclaration" => [
          ch("var", :always, false),
          ch("declared_type", :always, false),
          ch("value", :optional, true),
          sc("doc", :optional, true, "bytes?"),
        ] + infras(%w(discarded)),

        "UninitializedVar" => [
          ch("var", :always, false),
          ch("declared_type", :always, false),
        ],

        "ProcLiteral" => [
          ch("def", :always, false),
        ] + infras(%w(proc_pointer force_nil expected_return_type from_block)),

        "ProcPointer" => [
          ch("obj", :optional, true),
          nv("name", :always, false),
          chl("args", :collection, false),
          sc("global", :always, false, "bool"),
        ] + infras(%w(call expanded)),

        "Include" => [ch("name", :always, false)],
        "Extend" => [ch("name", :always, false)],
        "Metaclass" => [ch("name", :always, false)],

        "LibDef" => [
          ch("name", :always, false),
          ch("body", :always, false),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          ev("name_location", :optional, true),
        ],

        "FunDef" => [
          nv("name", :always, false),
          nv("real_name", :always, false),
          chl("args", :collection, false),
          ch("return_type", :optional, true),
          ch("body", :optional, true),
          sc("doc", :optional, true, "bytes?"),
          sc("varargs", :always, false, "bool"),
          ev("name_location", :optional, true),
        ] + infras(%w(external)),

        "TypeDef" => [
          nv("name", :always, false),
          ch("type_spec", :always, false),
          sc("doc", :optional, true, "bytes?"),
          ev("name_location", :optional, true),
        ],

        "CStructOrUnionDef" => [
          nv("name", :always, false),
          ch("body", :always, false),
          sc("doc", :optional, true, "bytes?"),
          sc("union", :always, false, "bool"),
        ],

        "EnumDef" => [
          ch("name", :always, false),
          ch("base_type", :optional, true),
          chl("members", :collection, false),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ] + infras(%w(resolved_type)),

        "ExternalVar" => [
          nv("name", :always, false),
          nv("real_name", :optional, true),
          ch("type_spec", :always, false),
          sc("doc", :optional, true, "bytes?"),
        ],

        "Alias" => [
          ch("name", :always, false),
          ch("value", :always, false),
          sc("doc", :optional, true, "bytes?"),
          sc("visibility", :always, false, "Visibility"),
          sc("exported", :always, false, "bool"),
        ],

        "Cast" => [
          ch("obj", :always, false),
          ch("to", :always, false),
        ],

        "NilableCast" => [
          ch("obj", :always, false),
          ch("to", :always, false),
        ],

        "Annotation" => [
          ch("path", :always, false),
          chl("args", :collection, false),
          chl("named_args", :collection, true),
          sc("doc", :optional, true, "bytes?"),
          sc("iyi_file_mark", :always, false, "bool"),
        ],

        "MacroExpression" => [
          ch("exp", :always, false),
          sc("output", :always, false, "bool"),
        ],

        "MacroIf" => [
          ch("cond", :always, false),
          ch("then", :always, false),
          ch("else", :always, false),
          sc("is_unless", :always, false, "bool"),
        ],

        "MacroFor" => [
          chl("vars", :collection, false),
          ch("exp", :always, false),
          ch("body", :always, false),
        ],

        "MacroVar" => [
          nv("name", :always, false),
          chl("exps", :collection, true),
        ],

        "MagicConstant" => [
          sc("name", :always, false, "Token::Kind"),
        ],

        "Asm" => [
          sc("text", :always, false, "bytes"),
          chl("outputs", :collection, true),
          chl("inputs", :collection, true),
          sc("clobbers", :collection, true, "bytes_array?"),
          sc("volatile", :always, false, "bool"),
          sc("alignstack", :always, false, "bool"),
          sc("intel", :always, false, "bool"),
          sc("can_throw", :always, false, "bool"),
        ],

        "AsmOperand" => [
          sc("constraint", :always, false, "bytes"),
          ch("exp", :always, false),
        ],
      } of String => Array(Row)

      result = {} of String => Array(Row)
      raw.each { |kind, rows| result[kind] = rows + base_rows(kind) + infras(SEMANTIC_FIELDS.fetch(kind, [] of String)) }
      result
    end

    TABLE = table

    def self.rows(kind : String) : Array(Row)
      TABLE[kind]? || raise ArgumentError.new("unclassified AST kind #{kind}")
    end

    # The rows of one kind that a scope covers.
    def self.rows_in_scope(kind : String, scope : Scope) : Array(Row)
      scoped(TABLE, kind, scope)
    end

    def self.supported_kind?(kind : String) : Bool
      TABLE.has_key?(kind)
    end

    # The scalar shape each writer type tag must produce.
    def self.shape_for(tag : String) : DiagnosticScalarShape
      case tag.rchop('?')
      when "bool"
        DiagnosticScalarShape::Flag
      when "int32", "char", "RegexOptions"
        DiagnosticScalarShape::Number
      when "bytes", "Visibility", "Expressions::Keyword", "NumberKind", "Generic::Suffix", "Token::Kind"
        DiagnosticScalarShape::Text
      when "bytes_array", "bytes_pair"
        DiagnosticScalarShape::TextList
      else
        raise ArgumentError.new("unknown scalar type #{tag}")
      end
    end

    # Refuses an incomplete or inconsistent table. Pass a copy to test refusal.
    def self.verify!(table : Hash(String, Array(Row)) = TABLE, kinds : Array(String) = DiagnosticAstFieldSchema::SUPPORTED) : Nil
      missing = kinds.reject { |kind| table.has_key?(kind) }
      raise ArgumentError.new("schema table lacks kinds: #{missing.join(", ")}") unless missing.empty?
      extra = table.keys.reject { |kind| kinds.includes?(kind) }
      raise ArgumentError.new("schema table has unsupported kinds: #{extra.join(", ")}") unless extra.empty?
      kinds.each do |kind|
        seen = Set(String).new
        rows = table[kind]
        rows.each do |row|
          raise ArgumentError.new("#{kind}: duplicate field #{row.field}") unless seen.add?(row.field)
          verify_row!(kind, row)
        end
        BASE_FIELDS.each do |field|
          count = rows.count { |row| row.base && row.field == field }
          raise ArgumentError.new("#{kind}: base field #{field} appears #{count} times") unless count == 1
        end
        raise ArgumentError.new("#{kind}: base rows outside BASE_FIELDS") unless rows.count(&.base) == BASE_FIELDS.size
      end
      nil
    end

    def self.verify_row!(kind : String, row : Row) : Nil
      where = "#{kind}.#{row.field}"
      raise ArgumentError.new("#{where}: class and role disagree") unless row.role == role_for(row.klass)
      if row.provenance == Provenance::Semantic && row.role != Role::Infrastructure
        raise ArgumentError.new("#{where}: semantic row is framed")
      end

      if row.base
        raise ArgumentError.new("#{where}: base row is not a base field") unless BASE_FIELDS.includes?(row.field)
        raise ArgumentError.new("#{where}: base row carries presence or scalar") if row.presence || row.scalar || row.coordinate != Coordinate::Single
        raise ArgumentError.new("#{where}: base class differs from #{base_class(kind, row.field)}") unless row.klass == base_class(kind, row.field)
        raise ArgumentError.new("#{where}: base provenance differs") unless row.provenance == base_provenance(row.field)
        raise ArgumentError.new("#{where}: base nilability differs") unless row.nilable == base_nilable(row.field)
        return
      end

      unless row.framed?
        raise ArgumentError.new("#{where}: infrastructure row carries framing data") if row.presence || !row.nilable.nil? || row.scalar || row.coordinate != Coordinate::Single
        return
      end

      raise ArgumentError.new("#{where}: framed row is not declared in syntax") unless row.provenance == Provenance::Syntax
      presence = row.presence
      nilable = row.nilable
      raise ArgumentError.new("#{where}: framed row lacks presence or nilability") if presence.nil? || nilable.nil?
      raise ArgumentError.new("#{where}: always-present field is nilable") if presence == Presence::Always && nilable
      raise ArgumentError.new("#{where}: optional field is not nilable") if presence == Presence::Optional && !nilable

      case row.klass
      when DiagnosticAstFieldClass::ChildList, DiagnosticAstFieldClass::RecordList, DiagnosticAstFieldClass::IndexedChildMap
        raise ArgumentError.new("#{where}: list must be indexed and collected") unless row.coordinate == Coordinate::Indexed && presence == Presence::Collection
      when DiagnosticAstFieldClass::NamedChildMap
        raise ArgumentError.new("#{where}: map must be keyed and collected") unless row.coordinate == Coordinate::Keyed && presence == Presence::Collection
      when DiagnosticAstFieldClass::Child, DiagnosticAstFieldClass::Record
        raise ArgumentError.new("#{where}: single child cannot be a collection") unless row.coordinate == Coordinate::Single && presence != Presence::Collection
      when DiagnosticAstFieldClass::NamedValue
        raise ArgumentError.new("#{where}: name cannot be keyed") if row.coordinate == Coordinate::Keyed
        raise ArgumentError.new("#{where}: name list must be collected") unless (row.coordinate == Coordinate::Indexed) == (presence == Presence::Collection)
      when DiagnosticAstFieldClass::SyntaxScalar
        raise ArgumentError.new("#{where}: scalar must be single-coordinate") unless row.coordinate == Coordinate::Single
      when DiagnosticAstFieldClass::OriginEvidence
        raise ArgumentError.new("#{where}: evidence list must be indexed and collected") unless (row.coordinate == Coordinate::Indexed) == (presence == Presence::Collection)
      end

      if row.role == Role::Scalar
        tag = row.scalar || raise ArgumentError.new("#{where}: scalar lacks a type")
        raise ArgumentError.new("#{where}: nilable type tag disagrees with nilability") unless tag.ends_with?('?') == nilable
        shape_for(tag)
      else
        raise ArgumentError.new("#{where}: non-scalar row carries a scalar type") if row.scalar
      end
    end

    # Checks a node's presence list against the framed rows, in table order.
    def self.check_presence!(kind : String, observed : Array({String, DiagnosticFieldPresence})) : Nil
      framed = rows(kind).select(&.framed?)
      fields = observed.map { |entry| entry[0] }
      unless fields == framed.map(&.field)
        raise ArgumentError.new("#{kind}: presence fields #{fields.join(", ")} differ from table #{framed.map(&.field).join(", ")}")
      end
      framed.each_with_index do |row, index|
        state = observed[index][1]
        presence = row.presence || raise ArgumentError.new("#{kind}.#{row.field}: framed row lacks presence")
        ok = case presence
             when Presence::Always
               state == DiagnosticFieldPresence::Present
             when Presence::Optional
               state == DiagnosticFieldPresence::Present || state == DiagnosticFieldPresence::Absent
             else
               state != DiagnosticFieldPresence::Present
             end
        raise ArgumentError.new("#{kind}.#{row.field}: state #{state} is not allowed") unless ok
        if state == DiagnosticFieldPresence::Absent && row.nilable != true
          raise ArgumentError.new("#{kind}.#{row.field}: absent on a field that is not nilable")
        end
      end
    end

    # Checks a node's scalars: every scalar row, with its type and shape, and nothing else.
    def self.check_scalars!(kind : String, observed : Array({String, String, DiagnosticScalarShape})) : Nil
      expected = rows(kind).select { |row| row.role == Role::Scalar }
      unless observed.size == expected.size
        raise ArgumentError.new("#{kind}: scalar fields #{observed.map { |entry| entry[0] }.join(", ")} differ from table")
      end
      expected.each do |row|
        entry = observed.find { |candidate| candidate[0] == row.field }
        raise ArgumentError.new("#{kind}.#{row.field}: scalar is omitted") unless entry
        _, type, shape = entry
        raise ArgumentError.new("#{kind}.#{row.field}: type #{type} differs from #{row.scalar}") unless type == row.scalar
        absent_ok = shape == DiagnosticScalarShape::Null && row.nilable == true
        raise ArgumentError.new("#{kind}.#{row.field}: shape #{shape} does not match #{type}") unless absent_ok || shape == shape_for(type)
      end
    end

    def self.stub_for(field : String, index : Int32?, key : String?, child : Bool) : Stub
      base, _, sub = field.partition('.')
      Stub.new(base, sub, index, key, child)
    end

    # Checks child and name stubs: membership, coordinates, uniqueness, and counts
    # against the presence state. Record fields are pairs of "key" and "value".
    def self.check_stubs!(kind : String, presence : Array({String, DiagnosticFieldPresence}), children : Array({String, Int32?, String?}), names : Array({String, Int32?, String?})) : Nil
      states = presence.to_h
      stubs = [] of Stub
      children.each { |field, index, key| stubs << stub_for(field, index, key, true) }
      names.each { |field, index, key| stubs << stub_for(field, index, key, false) }
      table = rows(kind)

      stubs.each do |stub|
        row = table.find { |candidate| candidate.framed? && candidate.field == stub.base }
        raise ArgumentError.new("#{kind}: stub #{stub.base} is not a child or name field") unless row && (row.role == Role::Child || row.role == Role::Name)
        allowed = case row.klass
                  when DiagnosticAstFieldClass::Record, DiagnosticAstFieldClass::RecordList
                    stub.sub == "key" || (stub.sub == "value" && stub.child)
                  when DiagnosticAstFieldClass::NamedChildMap
                    (stub.sub.empty? && stub.child) || (stub.sub == "key" && !stub.child)
                  else
                    stub.sub.empty? && stub.child == (row.role == Role::Child)
                  end
        raise ArgumentError.new("#{kind}: stub #{stub.base}.#{stub.sub} is not a field of this kind") unless allowed
        case row.coordinate
        when Coordinate::Single
          raise ArgumentError.new("#{kind}: #{stub.base} is single but carries an index or key") unless stub.index.nil? && stub.key.nil?
        when Coordinate::Indexed
          raise ArgumentError.new("#{kind}: #{stub.base} is indexed but lacks an index") if stub.index.nil? || !stub.key.nil?
        else
          raise ArgumentError.new("#{kind}: #{stub.base} is keyed but lacks a key") if stub.key.nil? || !stub.index.nil?
        end
      end

      table.each do |row|
        next unless row.framed? && (row.role == Role::Child || row.role == Role::Name)
        state = states[row.field]? || raise ArgumentError.new("#{kind}: presence omits #{row.field}")
        mine = stubs.select { |stub| stub.base == row.field }
        subs = case row.klass
               when DiagnosticAstFieldClass::Record, DiagnosticAstFieldClass::RecordList
                 ["key", "value"]
               when DiagnosticAstFieldClass::NamedChildMap
                 ["", "key"]
               else
                 [""]
               end
        counts = subs.map { |sub| mine.count { |stub| stub.sub == sub } }

        if row.coordinate == Coordinate::Single
          expected = state == DiagnosticFieldPresence::Present ? 1 : 0
          counts.each do |count|
            raise ArgumentError.new("#{kind}.#{row.field}: expected #{expected} entries, found #{count}") unless count == expected
          end
        else
          raise ArgumentError.new("#{kind}.#{row.field}: state #{state} is not a collection state") if state == DiagnosticFieldPresence::Present
          subs.each do |sub|
            group = mine.select { |stub| stub.sub == sub }
            if row.coordinate == Coordinate::Keyed
              keys = group.map(&.key)
              raise ArgumentError.new("#{kind}.#{row.field}: duplicate keys") unless keys.uniq.size == keys.size
            else
              group.each_with_index do |stub, index|
                raise ArgumentError.new("#{kind}.#{row.field}: indexes are not 0..n-1 in order") unless stub.index == index
              end
            end
          end
          raise ArgumentError.new("#{kind}.#{row.field}: key and value counts differ") unless counts.uniq.size == 1
          total = counts.first
          if state == DiagnosticFieldPresence::Absent || state == DiagnosticFieldPresence::Empty
            raise ArgumentError.new("#{kind}.#{row.field}: #{state} has #{total} entries") unless total == 0
          else
            raise ArgumentError.new("#{kind}.#{row.field}: nonempty has no entries") unless total >= 1
          end
        end
      end
      nil
    end

    # Checks one node's snapshot against the table. Child kinds must be in the table.
    def self.check_node!(kind : String, presence : Array({String, DiagnosticFieldPresence}), scalars : Array({String, String, DiagnosticScalarShape}), children : Array({String, Int32?, String?}), names : Array({String, Int32?, String?}), child_kinds : Array(String)) : Nil
      check_presence!(kind, presence)
      check_scalars!(kind, scalars)
      check_stubs!(kind, presence, children, names)
      child_kinds.each do |child|
        raise ArgumentError.new("#{kind}: child kind #{child} is not in the table") unless supported_kind?(child)
      end
      nil
    end

    private def self.scoped(table : Hash(String, Array(Row)), kind : String, scope : Scope) : Array(Row)
      (table[kind]? || [] of Row).select { |row| scope == Scope::Full || row.provenance == Provenance::Syntax }
    end

    # Census pairs of a supported kind that the table does not cover in the scope.
    # The census pairs must come from a build of the same scope.
    def self.uncovered(table : Hash(String, Array(Row)), pairs : Array({String, String}), scope : Scope = Scope::Syntax) : Array(String)
      pairs.select { |kind, _field| DiagnosticAstFieldSchema::SUPPORTED.includes?(kind) }
        .reject { |kind, field| scoped(table, kind, scope).any? { |row| row.field == field } }
        .map { |kind, field| "#{kind}.#{field}" }
    end

    # Rows in the scope that the census does not contain.
    def self.unlisted(table : Hash(String, Array(Row)), pairs : Array({String, String}), scope : Scope = Scope::Syntax) : Array(String)
      found = [] of String
      table.each_key do |kind|
        scoped(table, kind, scope).each do |row|
          found << "#{kind}.#{row.field}" unless pairs.includes?({kind, row.field})
        end
      end
      found
    end
  end
end
