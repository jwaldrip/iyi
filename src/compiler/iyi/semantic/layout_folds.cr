module Iyi
  # A layout fold is a `sizeof`, `alignof`, `instance_sizeof`, `instance_alignof`
  # or `offsetof` that typing folded to a literal. Typing can fold a layout
  # before it is final: a module gains implementors, or the shared typer cached
  # a tuple before one of its elements grew. Each record keeps the value the
  # typer saw, so settling can compare it with the final layout.
  enum LayoutFoldKind
    Size
    Align
    InstanceSize
    InstanceAlign
    Offset
    InstanceOffset
  end

  # `subject` is the type that the fold passed to `Program#size_of` and the
  # related methods. `index` is the element of an offset fold. `type_argument`
  # is true when the fold sits inside a type argument, so its value is part of a
  # type that is already built.
  record LayoutFold,
    node : ASTNode,
    kind : LayoutFoldKind,
    subject : Type,
    index : Int32?,
    value : UInt64,
    type_argument : Bool,
    owner : ASTNode?

  enum LayoutFoldState
    Unsettled
    Reported
    Patched
  end

  # The by-value containment of the folded layouts. Each open container is a
  # node, joined to every open container it holds by value. Joined nodes form a
  # component whose layouts move together, so a type argument that pins one
  # node pins the whole component.
  class LayoutFoldGraph
    def initialize
      @parents = [] of Int32
      @witnesses = [] of Type
      @ids = Hash(Type, Int32).new.compare_by_identity
      @instance_ids = Hash(Type, Int32).new.compare_by_identity
    end

    # Whether the shape of `type` can still change: a module gains implementors,
    # and an abstract or virtual struct gains subtypes.
    def self.open_layout?(type : Type) : Bool
      type.module? || (type.abstract? && type.struct?) ||
        (type.is_a?(VirtualType) && type.base_type.struct?)
    end

    # The node for `type`'s layout, or for a class's instance struct when
    # `instance` is set. `witness` is the open type a node stands for in a report.
    def id_for(type : Type, instance : Bool, witness : Type? = nil) : Int32
      ids = instance ? @instance_ids : @ids
      if id = ids[type]?
        return id
      end

      id = @parents.size
      @parents << id
      @witnesses << (witness || type)
      ids[type] = id
      id
    end

    def witness_of(id : Int32) : Type
      @witnesses[id]
    end

    def find(id : Int32) : Int32
      root = id
      while @parents[root] != root
        root = @parents[root]
      end
      while id != root
        parent = @parents[id]
        @parents[id] = root
        id = parent
      end
      root
    end

    def union(a : Int32, b : Int32) : Nil
      root_a = find(a)
      root_b = find(b)
      @parents[root_b] = root_a unless root_a == root_b
    end

    # The open nodes that `type` reaches by value, through the containers
    # between them. A layout that is closed reaches none. A pointer, a class
    # reference, a metaclass or a primitive stops the walk. `path` holds the
    # types on the walk, so a cycle stops there rather than recurring.
    def roots_of(type : Type, instance : Bool, path : Array(Type)) : Array(Int32)
      if self.class.open_layout?(type)
        return [id_for(type, false)]
      end
      return [] of Int32 if path.any? { |visited| visited.same?(type) }

      path << type
      roots = instance ? instance_roots(type, path) : value_roots(type, path)
      path.pop
      roots
    end

    private def instance_roots(type : Type, path : Array(Type)) : Array(Int32)
      children = layout_field_types(type.devirtualize).flat_map { |field| roots_of(field, false, path) }
      container(type, children, true)
    end

    private def value_roots(type : Type, path : Array(Type)) : Array(Int32)
      case type
      when TypeDefType
        roots_of(type.typedef, false, path)
      when AliasType
        if aliased = type.aliased_type?
          roots_of(aliased, false, path)
        else
          [] of Int32
        end
      when UnionType
        type.union_types.flat_map { |member| roots_of(member, false, path) }
      when ReferenceStorageType
        # Lowered as `llvm_struct_type` of the reference type (llvm_typer.cr,
        # `create_llvm_type(ReferenceStorageType)`). A class or other field-bearing
        # type lowers to its instance struct; tuples and static arrays lower to
        # their value layout, as their `create_llvm_struct_type` overloads show.
        target = type.reference_type
        instance_target = target.is_a?(InstanceVarContainer) &&
                          !(target.is_a?(TupleInstanceType) || target.is_a?(NamedTupleInstanceType) || target.is_a?(StaticArrayInstanceType))
        container(type, roots_of(target, instance_target, path))
      when StaticArrayInstanceType
        container(type, roots_of(type.element_type, false, path))
      when TupleInstanceType
        container(type, type.tuple_types.flat_map { |element| roots_of(element, false, path) })
      when NamedTupleInstanceType
        container(type, type.entries.flat_map { |entry| roots_of(entry.type, false, path) })
      else
        if type.struct? && type.is_a?(InstanceVarContainer)
          container(type, layout_field_types(type).flat_map { |field| roots_of(field, false, path) })
        else
          [] of Int32
        end
      end
    end

    # A container is open when an open layout lies somewhere below it by value,
    # so it has a node only when it has open children.
    private def container(type : Type, children : Array(Int32), instance : Bool = false) : Array(Int32)
      return [] of Int32 if children.empty?

      id = id_for(type, instance, witness_of(children.first))
      children.each { |child| union(id, child) }
      [id]
    end

    # The fields of an instance of `type`, in layout order. A superclass's fields
    # come first, as `index_of_instance_var` numbers them.
    private def layout_field_types(type : Type) : Array(Type)
      fields = [] of Type
      if superclass = type.superclass
        fields.concat layout_field_types(superclass)
      end
      if type.is_a?(InstanceVarContainer)
        type.instance_vars.each_value { |var| fields << var.type }
      end
      fields
    end
  end

  class Program
    getter layout_folds = Hash(ASTNode, LayoutFold).new.compare_by_identity
    getter layout_fold_lines = [] of String
    property layout_fold_state = LayoutFoldState::Unsettled

    # Records what a fold site folded during typing. The latest record for a node
    # wins, and settling compares that record with the final layout.
    def record_layout_fold(fold : LayoutFold) : Nil
      @layout_folds[fold.node] = fold
    end

    # Settles every recorded fold against the final layout.
    #
    # Each fold is recomputed with a fresh typer, which lowers the layouts as they
    # are now. A fold whose value differs is stale, and then:
    # - a stale fold inside a type argument keeps its value, because a type was
    #   built from it; a native program refuses it with a compile error instead;
    # - a stale expression fold that shares an open layout with such a type
    #   argument keeps its value, so it agrees with the type;
    # - any other stale expression fold is replaced by a new literal with the
    #   final value. The old literal is never mutated, because a generic instance
    #   may hold it as a type variable.
    #
    # A fold that cannot be recomputed keeps its value and is reported. With
    # `patch: false`, nothing in the AST changes; only the dispositions are
    # decided. A patched settle runs once, and a native program then gets a fresh
    # shared typer, so the GC tables and the barrier read the final layouts.
    def settle_layout_folds(patch : Bool) : Nil
      return if layout_fold_state == LayoutFoldState::Patched
      return if !patch && layout_fold_state == LayoutFoldState::Reported

      {% if flag?(:without_llvm) %}
        # The LLVM-free front end has no layouts to settle against. Its layout
        # queries raise before any fold is recorded (program.cr), so there is
        # nothing to settle and the front end is unchanged by this pass.
        self.layout_fold_state = patch ? LayoutFoldState::Patched : LayoutFoldState::Reported
      {% else %}
        settle_with_layouts(patch)
      {% end %}
    end

    {% unless flag?(:without_llvm) %}
    private def settle_with_layouts(patch : Bool) : Nil
      # The fresh typer lowers every folded type, so a recursive struct is refused
      # here, before the typer could recur on it.
      RecursiveStructChecker.new(self).run if patch

      native = iyi_prelude?
      report = ENV["IYI_LAYOUT_FOLD_REPORT"]?
      typer = LLVMTyper.new(self, LLVM::Context.new)
      graph = LayoutFoldGraph.new

      walked = layout_folds.values.map do |fold|
        instance = instance_layout_kind?(fold.kind)
        {fold, graph.id_for(fold.subject, instance), graph.roots_of(fold.subject, instance, [] of Type)}
      end

      settled = walked.map do |fold, own, roots|
        final : UInt64? = nil
        failure : String? = nil
        begin
          final = recompute_layout_fold(fold, typer)
        rescue error : Exception
          failure = error.message || error.class.name
          # A raise can leave the typer holding a half-lowered type: a tuple is
          # cached as an opaque struct before its elements are lowered
          # (llvm_typer.cr, `create_llvm_type(TupleInstanceType)`), so a later
          # fold in the same typer would read that struct. Later folds get a
          # fresh typer, and the native shared typer is that fresh one.
          typer = LLVMTyper.new(self, LLVM::Context.new)
        end
        {fold, own, roots, final, failure}
      end

      # Every stale type argument pins its layout, and everything that shares an
      # open layout with it, before any expression is decided.
      pinned = {} of Int32 => String
      settled.each do |fold, own, roots, final, failure|
        next unless fold.type_argument
        next unless final.nil? || final != fold.value

        if native && patch
          fold.node.raise native_type_argument_message(fold, final, failure)
        end
        ([own] + roots).each { |id| pinned[graph.find(id)] ||= layout_fold_location(fold) }
      end

      lines = [] of String
      settled.each do |fold, own, roots, final, failure|
        if report && !roots.empty?
          lines << "layout fold open: #{layout_fold_location(fold)}: #{layout_fold_node(fold)} in #{layout_fold_owner(fold)}: #{fold.subject} holds #{graph.witness_of(roots.first)} by value"
        end
        next if final && final == fold.value

        tie = ([own] + roots).compact_map { |id| pinned[graph.find(id)]? }.first?
        disposition =
          if final.nil?
            "kept (cannot recompute: #{failure})"
          elsif fold.type_argument
            "kept (type argument)"
          elsif tie
            "kept (tied to type argument at #{tie})"
          elsif !patch
            "kept (--crystal)"
          else
            correct_layout_fold(fold, final.not_nil!)
            "corrected"
          end

        next unless report

        final_text = final ? final.to_s : "unknown"
        lines << "layout fold stale: #{layout_fold_location(fold)}: #{layout_fold_node(fold)} in #{layout_fold_owner(fold)}: folded #{fold.value}, final #{final_text}: #{disposition}"
      end

      @llvm_typer = typer if patch && native
      @layout_fold_lines = lines
      self.layout_fold_state = patch ? LayoutFoldState::Patched : LayoutFoldState::Reported
    end

    # Prints the settled folds on stderr when IYI_LAYOUT_FOLD_REPORT is set. A
    # program not yet settled is settled here without patching, so a `--crystal`
    # run reports what it would keep.
    def report_layout_folds : Nil
      return unless ENV["IYI_LAYOUT_FOLD_REPORT"]?

      settle_layout_folds(patch: false)
      layout_fold_lines.each { |line| STDERR.puts line }
    end

    private def instance_layout_kind?(kind : LayoutFoldKind) : Bool
      case kind
      when LayoutFoldKind::InstanceSize, LayoutFoldKind::InstanceAlign, LayoutFoldKind::InstanceOffset
        true
      else
        false
      end
    end

    private def recompute_layout_fold(fold : LayoutFold, typer : LLVMTyper) : UInt64
      subject = fold.subject
      case fold.kind
      when LayoutFoldKind::Size
        size_of(subject, typer).to_u64
      when LayoutFoldKind::Align
        align_of(subject, typer).to_u64
      when LayoutFoldKind::InstanceSize
        instance_size_of(subject, typer).to_u64
      when LayoutFoldKind::InstanceAlign
        instance_align_of(subject, typer).to_u64
      when LayoutFoldKind::Offset
        offset_of(subject, fold.index.not_nil!, typer).to_u64
      else
        instance_offset_of(subject, fold.index.not_nil!, typer).to_u64
      end
    end

    {% end %}

    private def correct_layout_fold(fold : LayoutFold, final : UInt64) : Nil
      expanded = NumberLiteral.new(final.to_s, :i32)
      expanded.type = int32
      fold.node.as(ExpandableNode).expanded = expanded
    end

    private def native_type_argument_message(fold : LayoutFold, final : UInt64?, failure : String?) : String
      label = layout_fold_node(fold)
      if final
        "#{label} folded to #{fold.value} when it was used as a type argument, but its final value is #{final}. " \
        "A type argument can't be corrected after it is used, so measure it after the layout is final, " \
        "or use the value as an expression"
      else
        "#{label} is used as a type argument, but its final value can't be checked (#{failure}), so the type argument can't be verified"
      end
    end

    private def layout_fold_node(fold : LayoutFold) : String
      name = case fold.kind
             when LayoutFoldKind::Size then "sizeof"
             when LayoutFoldKind::Align then "alignof"
             when LayoutFoldKind::InstanceSize then "instance_sizeof"
             when LayoutFoldKind::InstanceAlign then "instance_alignof"
             else "offsetof"
             end
      "#{name}(#{fold.subject})"
    end

    private def layout_fold_location(fold : LayoutFold) : String
      fold.node.location.try(&.to_s) || "unknown location"
    end

    private def layout_fold_owner(fold : LayoutFold) : String
      fold.owner.as?(Def).try(&.name) || "main"
    end
  end
end
