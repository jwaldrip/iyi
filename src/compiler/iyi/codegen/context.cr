require "./codegen"

class Iyi::CodeGenVisitor
  class Context
    property fun : LLVM::Function
    property fun_type : LLVM::Type
    property fun_debug_params = [] of LibLLVM::MetadataRef
    property type : Type
    property vars : Hash(String, LLVMVar)
    property return_type : Type?
    # iyi: where the function writes its result when the result is passed
    # indirectly (`LLVMTyper#passed_indirectly?`): its last parameter.
    property indirect_return : LLVM::Value?
    property return_phi : Phi?
    property break_phi : Phi?
    property next_phi : Phi?
    property while_block : LLVM::BasicBlock?
    # iyi: whether code emitted here may run more than once per entry to
    # the function — inside a `while` or a block — which is what
    # `keep_call_out_of_main` asks before it keeps a call out of line.
    property? repeats = false
    # iyi: whether a loop's back-edge here checks the worker's preemption
    # word (`CodeGenVisitor#iyi_back_edge`): set per function, for the def
    # the function is, and kept through the blocks inlined into it.
    property? iyi_preempt = false
    # iyi: whether the code emitted here is the runtime's, or a library
    # def compiled for the runtime to call (`CodeGenVisitor#target_def_fun`):
    # a library def called from here is that copy, which checks nowhere.
    property? iyi_runtime = false
    property! block : Block
    property! block_context : Context
    property closure_vars : Array(MetaVar)?
    property closure_type : LLVM::Type?
    property closure_ptr : LLVM::Value?
    property closure_skip_parent : Bool
    property closure_parent_context : Context?
    property closure_self : Type?
    property diagnostic_scope : Def | Program | Nil

    def initialize(@fun, @fun_type, @type, @vars = LLVMVars.new)
      @closure_skip_parent = false
    end

    def block_context=(@block_context : Nil)
    end

    def block=(@block : Nil)
    end

    def reset_closure
      @closure_vars = nil
      @closure_type = nil
      @closure_ptr = nil
      @closure_skip_parent = false
      @closure_parent_context = nil
      @closure_self = nil
    end

    # Describe the physical closure chain, not merely the variables a body
    # happens to read. A missing binding or scope identity invalidates it.
    def diagnostic_capture(node : ProcLiteral, is_closure : Bool) : JSON::Any?
      proc_type = node.type?
      return nil unless proc_type.is_a?(ProcInstanceType)
      proc_identity = DiagnosticType.identity(proc_type) || return nil
      environment = nil
      if is_closure
        return nil unless @closure_type && @closure_ptr
        environment = diagnostic_environment(Set(UInt64).new)
        return nil unless environment
      end

      JSON::Any.new({
        "proc_type"   => proc_identity,
        "is_closure"  => JSON::Any.new(is_closure),
        "environment" => environment || JSON::Any.new(nil),
      })
    end

    def diagnostic_environment(seen : Set(UInt64)) : JSON::Any?
      return nil unless seen.add?(object_id)
      if @closure_skip_parent
        parent = @closure_parent_context || return nil
        return nil unless @closure_type && parent.closure_type
        return parent.diagnostic_environment(seen)
      end
      return nil unless @closure_type && @closure_ptr
      vars = @closure_vars || return nil
      bindings = [] of JSON::Any
      vars.each do |var|
        origin = var.diagnostic_origin_json || return nil
        var_type = var.type? || return nil
        type = DiagnosticType.identity(var_type) || return nil
        scope =
          case owner = var.context
          when Def
            owner_origin = owner.diagnostic_origin_json || return nil
            specialization = owner.diagnostic_specialization_json || return nil
            JSON::Any.new({"kind" => JSON::Any.new("def"), "origin" => owner_origin, "specialization" => specialization})
          when Block
            owner_origin = owner.diagnostic_origin_json || return nil
            specialization = owner.diagnostic_specialization_json || return nil
            return nil unless specialization.as_h? && specialization["environment"]?.try(&.as_h?)
            JSON::Any.new({"kind" => JSON::Any.new("block"), "origin" => owner_origin, "specialization" => specialization})
          when Program
            JSON::Any.new({"kind" => JSON::Any.new("program")})
          else
            return nil
          end
        bindings << JSON::Any.new({
          "name"           => JSON::Any.new(var.name),
          "binding_origin" => origin,
          "scope"          => scope,
          "type"           => type,
          "mutable"        => JSON::Any.new(var.mutably_closured?),
        })
      end
      captured_self = @closure_self.try { |type| DiagnosticType.identity(type) }
      return nil if @closure_self && !captured_self
      parent_identity = nil
      if parent = @closure_parent_context
        if parent.closure_type
          parent_identity = parent.diagnostic_environment(seen) || return nil
        end
      end
      JSON::Any.new({
        "captured_self_type" => captured_self || JSON::Any.new(nil),
        "bindings"           => JSON::Any.new(bindings),
        "parent"             => parent_identity || JSON::Any.new(nil),
      })
    end

    def clone
      context = Context.new @fun, @fun_type, @type, @vars
      context.return_type = @return_type
      context.indirect_return = @indirect_return
      context.return_phi = @return_phi
      context.break_phi = @break_phi
      context.next_phi = @next_phi
      context.while_block = @while_block
      context.repeats = @repeats
      context.iyi_preempt = @iyi_preempt
      context.diagnostic_scope = @diagnostic_scope
      context.iyi_runtime = @iyi_runtime
      if block = @block
        context.block = block
      end
      context.block_context = @block_context
      context.closure_vars = @closure_vars
      context.closure_type = @closure_type
      context.closure_ptr = @closure_ptr
      context.closure_skip_parent = @closure_skip_parent
      context.closure_parent_context = @closure_parent_context
      context.closure_self = @closure_self
      context
    end

    def add_fun_debug_param(debug_type)
      fun_debug_params << debug_type if debug_type
    end
  end

  def with_cloned_context(new_context = @context, &)
    with_context(new_context.clone) { |ctx| yield ctx }
  end

  def with_context(new_context, &)
    old_context = @context
    @context = new_context
    value = yield old_context
    @context = old_context
    value
  end
end
