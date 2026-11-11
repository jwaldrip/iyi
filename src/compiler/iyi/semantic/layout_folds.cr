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

    # Every record bumps the epoch. A patched settle keeps the epoch it saw and
    # whether a fold reached a layout that can still move, so a later call settles
    # again only when there is something new (a second `semantic_after_top_level`,
    # as the fork probe runs one).
    @layout_fold_epoch = 0
    @layout_fold_settled_epoch = -1
    @layout_fold_open = false
    # Set while codegen types code of its own (`codegen_visit_main`).
    @layout_fold_codegen = false
    # Whether the cleanup's typer has been replaced since the last settle.
    @layout_fold_typer_fresh = false
    # The open layouts that a settled fold reaches, each with its fingerprint at
    # settle time. The code codegen types afterwards is checked against them.
    @layout_fold_watch : Hash(Type, String)? = nil
    # Fold literals by identity, and the value of every read of one by the
    # MathInterpreter, so a read before settling can be judged against the final value.
    @layout_fold_literals = Hash(NumberLiteral, LayoutFold).new.compare_by_identity
    @layout_fold_reads = [] of {NumberLiteral, String}

    # Records what a fold site folded during typing. The latest record for a node
    # wins, and settling compares that record with the final layout.
    def record_layout_fold(fold : LayoutFold) : Nil
      @layout_folds[fold.node] = fold
      if literal = fold.node.as(ExpandableNode).expanded.as?(NumberLiteral)
        @layout_fold_literals[literal] = fold
      end
      @layout_fold_epoch += 1
    end

    # The MathInterpreter hook calls this for every literal it reads
    # (math_interpreter.cr, `interpret(node : NumberLiteral)`). A read of a fold
    # literal records the value read, which settling checks against the final value.
    def note_layout_fold_read(literal : NumberLiteral) : Nil
      return unless @layout_fold_literals[literal]?
      @layout_fold_reads << {literal, literal.value}
    end

    # Settles every recorded fold against the final layout.
    #
    # `semantic_after_top_level` calls this after the last code the compiler types,
    # including what the cleanup types itself: the raise it writes for an
    # unreachable enum branch or an untyped expression, a tuple or proc literal it
    # retypes, a splat it expands. It runs after `RecursiveStructChecker`, since the
    # fresh typer lowers every folded type.
    #
    # Each fold is recomputed with a fresh typer. A fold whose value differs is
    # stale, and then:
    # - a stale fold inside a type argument keeps its value, because a type was
    #   built from it; a native program refuses it with a compile error instead;
    # - a literal that code typed after the cleanup inlined can hold is judged as a
    #   type argument: a generic type variable, or a literal whose cast changed its
    #   kind or type. It is kept, and a native program refuses it;
    # - a stale expression fold that shares an open layout with a stale type
    #   argument keeps its value, so it agrees with the type;
    # - any other stale expression fold takes the final value, written into the
    #   literal the program holds. The write is in place, because the cleanup has
    #   already put that literal everywhere the fold was used.
    #
    # A fold that cannot be recomputed keeps its value and is reported. With
    # `patch: false`, nothing in the AST changes. A patched settle gives a native
    # program the settling typer as its shared typer, so the GC tables and the
    # barrier read final layouts.
    def settle_layout_folds(patch : Bool) : Nil
      if layout_fold_state == LayoutFoldState::Patched
        return unless patch
        return if @layout_fold_settled_epoch == @layout_fold_epoch && !@layout_fold_open
      elsif !patch && layout_fold_state == LayoutFoldState::Reported
        return
      end

      {% if flag?(:without_llvm) %}
        # The LLVM-free front end has no layouts to settle against. Its layout
        # queries raise before any fold is recorded (program.cr), so there is
        # nothing to settle, and the front end is unchanged by this pass.
        self.layout_fold_state = patch ? LayoutFoldState::Patched : LayoutFoldState::Reported
      {% else %}
        settle_with_layouts(patch)
      {% end %}
    end

    # A native program's cleanup folds the layouts it types with a typer that
    # cached nothing while typing, so a module that grew while typing is lowered as
    # it is now. `--crystal` keeps the shared typer, so a type argument its cleanup
    # folds keeps the value Crystal 1.21.0 gives it. Codegen's own typing keeps the
    # typer that settling left.
    def fresh_layout_typer_for_cleanup : Nil
      {% unless flag?(:without_llvm) %}
        return unless iyi_prelude?
        return if @layout_fold_codegen || @layout_fold_typer_fresh
        @layout_fold_typer_fresh = true
        @llvm_typer = LLVMTyper.new(self, LLVM::Context.new)
      {% end %}
    end

    # Codegen types code of its own through `visit_main` (the raise for a cast, and
    # the raise for a proc passed to C). That typing can grow an open layout that a
    # settled fold reaches. The fold's value was settled before, and codegen has
    # already read it, so nothing can correct it now. A native program is refused,
    # since iyi owns that rule. `--crystal` keeps the value Crystal 1.21.0 gives,
    # which its own codegen gives too, and reports it under IYI_LAYOUT_FOLD_REPORT.
    def codegen_visit_main(node : ASTNode, visitor : MainVisitor = MainVisitor.new(self)) : Nil
      watch = @layout_fold_watch
      previous = @layout_fold_codegen
      @layout_fold_codegen = true
      begin
        visit_main node, visitor: visitor
      ensure
        @layout_fold_codegen = previous
      end
      return unless watch

      watch.each do |type, stamp|
        next if layout_fingerprint(type) == stamp
        if iyi_prelude?
          node.raise "codegen types code that grows #{type}, a layout that a layout fold settled before codegen reaches, so that fold's value would be stale, and codegen can't correct a value it has already read"
        elsif ENV["IYI_LAYOUT_FOLD_REPORT"]?
          location = node.location.try(&.to_s) || "unknown location"
          STDERR.puts "layout fold codegen grew: #{location}: codegen typed code that grows #{type}, a layout a settled fold reaches: kept (--crystal, as Crystal 1.21.0 keeps it)"
        end
      end
    end

    # What a layout's implementors are now, as a string. A new implementor or a new
    # subtype changes it.
    private def layout_fingerprint(type : Type) : String
      if type.is_a?(VirtualType)
        type.subtypes.map(&.to_s).join(",")
      elsif type.module?
        type.including_types.to_s
      else
        type.subclasses.map(&.to_s).join(",")
      end
    end

    # Prints the settled folds on stderr when IYI_LAYOUT_FOLD_REPORT is set. A
    # program not yet settled is settled here without patching, so a `--crystal`
    # run reports what it would keep.
    def report_layout_folds : Nil
      return unless ENV["IYI_LAYOUT_FOLD_REPORT"]?

      settle_layout_folds(patch: false)
      layout_fold_lines.each { |line| STDERR.puts line }
    end

    {% unless flag?(:without_llvm) %}
    private def settle_with_layouts(patch : Bool) : Nil
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
          # fold in the same typer would read that struct. Later folds get a fresh one.
          typer = LLVMTyper.new(self, LLVM::Context.new)
        end
        literal = fold.node.as(ExpandableNode).expanded.as?(NumberLiteral)
        {fold, own, roots, final, failure, literal}
      end

      # Only a literal this settle would write is examined, and the type variables
      # are gathered only when there is one.
      held = Set(NumberLiteral).new.compare_by_identity
      if patch
        writable = [] of NumberLiteral
        settled.each do |fold, _, _, final, _, literal|
          next unless literal && final && !fold.type_argument
          next unless final != fold.value || literal.value != fold.value.to_s
          writable << literal
        end
        unless writable.empty?
          type_variables = layout_fold_type_variables
          writable.each do |literal|
            held << literal if type_variables.includes?(literal) || layout_fold_literal_altered?(literal)
          end
        end
      end

      # Every stale type argument, and every held literal gone stale, pins its layout
      # and everything that shares an open layout with it, before any expression is
      # decided.
      pinned = {} of Int32 => String
      settled.each do |fold, own, roots, final, failure, literal|
        held_here = literal ? held.includes?(literal) : false
        next unless fold.type_argument || held_here
        next if final && final == fold.value

        if native && patch
          fold.node.raise native_type_argument_message(fold, final, held_here, failure)
        end
        ([own] + roots).each { |id| pinned[graph.find(id)] ||= layout_fold_location(fold) }
      end

      # A literal read before settling (by constant arithmetic, or as a type argument
      # through TypeLookup) that settled to another value gives a derived value that
      # can't be corrected. A native program refuses it. `--crystal` keeps the value
      # the read computed, as Crystal 1.21.0 does, and reports it.
      lines = [] of String
      if patch && !@layout_fold_reads.empty?
        read_values = Hash(NumberLiteral, Array(String)).new.compare_by_identity
        @layout_fold_reads.each do |literal, value|
          (read_values[literal] ||= [] of String) << value
        end
        settled.each do |fold, _, _, final, _, literal|
          next unless literal && final && (reads = read_values[literal]?)
          next if reads.all? { |read| read == final.to_s }

          if native
            fold.node.raise "#{layout_fold_node(fold)} folded to #{fold.value}, and code typed before it settled read it as #{reads.first}, but its final value is #{final}. That derived value can't be corrected, so measure it after the layout is final"
          end
          if report
            lines << "layout fold read early: #{layout_fold_location(fold)}: #{layout_fold_node(fold)} in #{layout_fold_owner(fold)}: folded #{fold.value}, read as #{reads.first}, final #{final}: kept (--crystal, the read's value stands)"
          end
        end
        @layout_fold_reads.clear
      end
      settled.each do |fold, own, roots, final, failure, literal|
        if report && !roots.empty?
          lines << "layout fold open: #{layout_fold_location(fold)}: #{layout_fold_node(fold)} in #{layout_fold_owner(fold)}: #{fold.subject} holds #{graph.witness_of(roots.first)} by value"
        end

        held_here = literal ? held.includes?(literal) : false
        tie = ([own] + roots).compact_map { |id| pinned[graph.find(id)]? }.first?

        if patch && final && literal && !fold.type_argument && !held_here
          target = (tie ? fold.value : final).to_s
          literal.value = target unless literal.value == target
        end

        next if final && final == fold.value

        disposition =
          if final.nil?
            "kept (cannot recompute: #{failure})"
          elsif fold.type_argument
            "kept (type argument)"
          elsif held_here
            "kept (used by later typing)"
          elsif tie
            "kept (tied to type argument at #{tie})"
          elsif literal.nil?
            "kept (no literal)"
          elsif !patch
            "kept (--crystal)"
          else
            "corrected"
          end

        next unless report

        final_text = final ? final.to_s : "unknown"
        lines << "layout fold stale: #{layout_fold_location(fold)}: #{layout_fold_node(fold)} in #{layout_fold_owner(fold)}: folded #{fold.value}, final #{final_text}: #{disposition}"
      end

      if patch
        watch = Hash(Type, String).new.compare_by_identity
        walked.each do |_, _, roots|
          roots.each do |id|
            witness = graph.witness_of(id)
            watch[witness] ||= layout_fingerprint(witness)
          end
        end
        @layout_fold_watch = watch
        @llvm_typer = typer if native
        @layout_fold_typer_fresh = false
        @layout_fold_settled_epoch = @layout_fold_epoch
        @layout_fold_open = walked.any? { |_, _, roots| !roots.empty? }
      end
      @layout_fold_lines = lines
      self.layout_fold_state = patch ? LayoutFoldState::Patched : LayoutFoldState::Reported
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

    # A literal whose kind or type code typed later changed (a cast): it is no
    # longer the `Int32` literal the fold made.
    private def layout_fold_literal_altered?(literal : NumberLiteral) : Bool
      return true unless literal.kind.i32?
      type = literal.type?
      type.nil? || !type.same?(int32)
    end

    # Every number literal a generic instance holds as a type variable, by identity:
    # `StaticArray(UInt8, 8)` holds its `8`.
    private def layout_fold_type_variables : Set(NumberLiteral)
      literals = Set(NumberLiteral).new.compare_by_identity
      collect_layout_fold_type_variables(self, literals)
      file_modules.each_value { |file_module| collect_layout_fold_type_variables(file_module, literals) }
      literals
    end

    private def collect_layout_fold_type_variables(type : Type, literals : Set(NumberLiteral)) : Nil
      nested_types = type.types?
      return unless nested_types

      nested_types.each_value do |nested|
        if nested.is_a?(GenericType)
          nested.each_instantiated_type do |instance|
            next unless instance.is_a?(GenericInstanceType)
            instance.type_vars.each_value { |var| literals << var if var.is_a?(NumberLiteral) }
          end
        end
        collect_layout_fold_type_variables(nested, literals)
      end
    end

    private def native_type_argument_message(fold : LayoutFold, final : UInt64?, held : Bool, failure : String?) : String
      label = layout_fold_node(fold)
      if final.nil?
        "#{label} is used as a type argument, but its final value can't be checked (#{failure}), so the type argument can't be verified"
      elsif fold.type_argument
        "#{label} folded to #{fold.value} when it was used as a type argument, but its final value is #{final}. " \
        "A type argument can't be corrected after it is used, so measure it after the layout is final, " \
        "or use the value as an expression"
      else
        "#{label} folded to #{fold.value}, and code typed after that used the value as a type argument or a cast, but its final value is #{final}. " \
        "That use can't be corrected, so measure it after the layout is final"
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
