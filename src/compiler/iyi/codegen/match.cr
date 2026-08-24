require "./codegen"

class Iyi::CodeGenVisitor
  def match_type_id(type, restriction, type_id)
    match_type_id_impl(type.remove_indirection, restriction.remove_indirection, type_id)
  end

  private def match_type_id_impl(type, restriction : Program, type_id)
    llvm_true
  end

  private def match_type_id_impl(type, restriction : FileModule, type_id)
    llvm_true
  end

  private def match_type_id_impl(type : UnionType | VirtualType | VirtualMetaclassType, restriction, type_id)
    match_any_type_id(restriction, type_id)
  end

  private def match_type_id_impl(type : AliasType, restriction, type_id)
    match_type_id type.aliased_type, restriction, type_id
  end

  private def match_type_id_impl(type, restriction, type_id)
    # iyi: the restriction can be virtual while the value is not, which is a
    # shape a whole-program build never makes and a boundary does. A call to a
    # method read from a `.iyimod` is keyed on the parameter *as declared* and
    # the argument widened to it, so an `IO` parameter is matched against `IO+`
    # with a concrete `IO::FileDescriptor` in hand — and a single type id is
    # not what `IO+` is. It is a range, and the range is what answers.
    #
    # Handled here rather than as an overload on the restriction, because the
    # case above already takes a virtual *value* and the two would be ambiguous
    # where both are virtual.
    case restriction
    when VirtualType, VirtualMetaclassType, UnionType
      match_any_type_id(restriction, type_id)
    else
      equal? type_id(restriction), type_id
    end
  end

  def match_any_type_id(type, type_id)
    match_any_type_id_impl(type.remove_indirection, type_id)
  end

  private def match_any_type_id_impl(type : UnionType | VirtualType | VirtualMetaclassType, type_id)
    match_any_type_id_with_function(type, type_id)
  end

  private def match_any_type_id_impl(type, type_id)
    equal? type_id(type), type_id
  end

  private def match_any_type_id_with_function(type, type_id)
    match_fun_name = "~match<#{type.llvm_name}>"

    # iyi: which unit asks about it, so an artifact carrying that unit can say
    # so (SPEC.md IV.1g). The function is the main module's and the main module
    # does not travel, so the consumer defines it — and for a *union* it cannot
    # work out which ones to define. A virtual type is enumerable from the
    # program's own classes, which is what `iyi_define_all_match_funs` does; a
    # union is a type the producer's code made and the consumer may never form.
    # Recorded only while writing artifacts.
    unless @program.iyi_exported_owners.empty?
      if @llvm_mod != @main_mod
        (@program.iyi_unit_match_types[@llvm_mod.name] ||= Set(Type).new) << type
      end
    end

    func = typed_fun?(@main_mod, match_fun_name) || create_match_fun(match_fun_name, type)
    func = check_main_fun match_fun_name, func
    call func, [type_id] of LLVM::Value
  end

  # iyi: defines `~match<T>` for every type an artifact's object code might ask
  # about, for the reason `iyi_define_all_type_ids` exists (SPEC.md IV.1g).
  #
  # A unit that travels can call one of these — `~match<IO+>` is the one a
  # module using Crystal's library produced — and the function lives in the
  # *main* module, which the artifact does not carry. It cannot be carried
  # either: a match against a virtual type compares against a range of type
  # ids, and the numbering belongs to the program rather than to the module, so
  # a copy compiled by the producer would compare the consumer's ids against
  # the producer's numbers and answer wrongly with no symptom.
  #
  # So the consumer defines them, with its own numbering, exactly as it defines
  # the type ids. All of them rather than the ones an object file asks for,
  # because this build cannot see inside an object file, and each is a compare
  # or two.
  #
  # Collected before any of them is defined, because asking a type for its
  # virtual form is what creates that form: defining as we walk would be
  # mutating the numbering while reading it.
  def iyi_define_all_match_funs : Nil
    virtuals = [] of VirtualType

    @program.llvm_id.each_type do |type|
      next unless type.is_a?(ClassType) || type.is_a?(GenericClassInstanceType)

      virtual = type.virtual_type
      virtuals << virtual if virtual.is_a?(VirtualType)
    end

    virtuals.each do |virtual|
      iyi_define_match_fun(virtual)
      iyi_define_match_fun(virtual.metaclass.as(VirtualMetaclassType))
    end

    # And the ones the walk above cannot reach: the unions an artifact's units
    # ask about. A union is not a type this program has unless its own code
    # formed it, and `(Char | Iyi::Keyword | String | Nil)` is one kemal's code
    # formed and a consumer of kemal's never would.
    @program.iyi_artifact_match_types.each do |type|
      case type
      when VirtualType, VirtualMetaclassType, UnionType
        iyi_define_match_fun_for(type)
      end
    end
  end

  private def iyi_define_match_fun_for(type) : Nil
    name = "~match<#{type.llvm_name}>"
    return if typed_fun?(@main_mod, name)

    create_match_fun(name, type)
  end

  private def iyi_define_match_fun(type : VirtualType | VirtualMetaclassType) : Nil
    name = "~match<#{type.llvm_name}>"
    return if typed_fun?(@main_mod, name)

    create_match_fun(name, type)
  end

  private def create_match_fun(name, type)
    in_main do
      define_main_function(name, ([llvm_context.int32]), llvm_context.int1) do |func|
        set_internal_fun_debug_location(func, name)
        type_id = func.params.first
        create_match_fun_body(type, type_id)
      end
    end
  end

  private def create_match_fun_body(type : UnionType, type_id)
    result = nil
    type.expand_union_types.each do |sub_type|
      sub_type_cond = match_any_type_id(sub_type, type_id)
      result = result ? or(result, sub_type_cond) : sub_type_cond
    end
    ret result.not_nil!
  end

  private def create_match_fun_body(type : VirtualType, type_id)
    min, max = @program.llvm_id.min_max_type_id(type.base_type).not_nil!
    ret(
      and(
        builder.icmp(LLVM::IntPredicate::SGE, type_id, int(min)),
        builder.icmp(LLVM::IntPredicate::SLE, type_id, int(max))
      )
    )
  end

  private def create_match_fun_body(type, type_id)
    result = nil
    type.each_concrete_type do |sub_type|
      sub_type_cond = equal? type_id(sub_type), type_id
      result = result ? or(result, sub_type_cond) : sub_type_cond
    end
    ret result.not_nil!
  end
end
