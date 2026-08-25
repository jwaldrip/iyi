struct LLVM::Target
  def self.each(&)
    target = LibLLVM.get_first_target
    while target
      yield Target.new target
      target = LibLLVM.get_next_target target
    end
  end

  def self.first : self
    first? || raise "No LLVM targets available (did you forget to invoke LLVM.init_native_target?)"
  end

  def self.first? : self?
    target = LibLLVM.get_first_target
    target ? Target.new(target) : nil
  end

  def self.from_triple(triple) : self
    return_code = LibLLVM.get_target_from_triple triple, out target, out error
    raise ArgumentError.new(LLVM.string_and_dispose(error)) unless return_code == 0
    new target
  end

  def initialize(@unwrap : LibLLVM::TargetRef)
  end

  def name
    String.new LibLLVM.get_target_name(self)
  end

  def description
    String.new LibLLVM.get_target_description(self)
  end

  def create_target_machine(triple, cpu = "", features = "",
                            opt_level = LLVM::CodeGenOptLevel::Default,
                            reloc = LLVM::RelocMode::PIC,
                            code_model = LLVM::CodeModel::Default) : LLVM::TargetMachine
    target_machine = LibLLVM.create_target_machine(self, triple, cpu, features, opt_level, reloc, code_model)
    target_machine ? TargetMachine.new(target_machine) : raise "Couldn't create target machine"
  end

  # iyi: a target machine that emits wasm exception-handling instructions
  # (`try`/`catch`/`throw`) for `invoke` and its landing pads, instead of
  # deleting them.
  #
  # This is a separate entry point rather than a parameter on
  # `create_target_machine` because it cannot go through `LLVMCreateTargetMachine`
  # at all: the exception model lives in `TargetOptions`, which that function
  # builds itself. `src/llvm/ext/llvm_ext.cc` records the sequence.
  #
  # *legacy_eh* picks the encoding: `false` emits the standardised proposal
  # (`try_table`/`throw_ref`), `true` the earlier `try`/`catch`/`end_try` one
  # that engines shipped first.
  def create_wasm_eh_target_machine(triple, cpu = "", features = "",
                                    opt_level = LLVM::CodeGenOptLevel::Default,
                                    reloc = LLVM::RelocMode::PIC,
                                    code_model = LLVM::CodeModel::Default,
                                    legacy_eh = false) : LLVM::TargetMachine
    {% if LibLLVM::IS_LT_180 %}
      raise "wasm exception handling needs LLVM 18 or newer, and this compiler was built against #{LibLLVM::VERSION}"
    {% else %}
      target_machine = LibLLVMExt.create_target_machine_wasm_eh(self, triple, cpu, features, opt_level, reloc, code_model, legacy_eh ? 1 : 0)
      target_machine ? TargetMachine.new(target_machine) : raise "Couldn't create wasm target machine"
    {% end %}
  end

  def to_s(io : IO) : Nil
    io << "LLVM::Target(name="
    name.inspect(io)
    io << ", description="
    description.inspect(io)
    io << ')'
  end

  def inspect(io : IO) : Nil
    to_s(io)
  end

  def to_unsafe
    @unwrap
  end
end
