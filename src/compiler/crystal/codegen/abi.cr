# Based on https://github.com/rust-lang/rust/blob/29ac04402d53d358a1f6200bea45a301ff05b2d1/src/librustc_trans/trans/cabi.rs
abstract class Iyi::ABI
  getter target_data : LLVM::TargetData
  getter? osx : Bool
  getter? windows : Bool

  def initialize(target_machine : LLVM::TargetMachine)
    @target_data = target_machine.data_layout
    triple = target_machine.triple
    # iyi: substring tests, not regexes: an unanchored `/apple/` never meant
    # more than `includes?`, and the compiler's own code must not be what
    # keeps pcre2 linked (zero-dep).
    @osx = triple.includes?("apple")
    @windows = triple.includes?("windows")
  end

  def self.from(target_machine : LLVM::TargetMachine) : self
    triple = target_machine.triple
    # iyi: substring tests carry the literal alternations the regexes held,
    # in the same order, because the order is load-bearing: `arm64` contains
    # `arm`, so the aarch64 arm must answer first or every 64-bit Arm triple
    # would take the 32-bit ABI. if/elsif rather than `case ... when`,
    # because the win64 arm needs two conditions on one branch and a `when`
    # clause cannot hold a conjunction; this is the same shape the sweep
    # left in `config.cr`. A triple is arch-vendor-os-environment, so
    # `x86_64.+windows-(?:msvc|gnu)` and these two substring tests agree on
    # every triple that names a real target, and the compiler's own code is
    # not what keeps pcre2 linked (zero-dep).
    if triple.includes?("x86_64") && (triple.includes?("windows-msvc") || triple.includes?("windows-gnu"))
      X86_Win64.new(target_machine)
    elsif triple.includes?("x86_64") || triple.includes?("amd64")
      X86_64.new(target_machine)
    elsif triple.includes?("i386") || triple.includes?("i486") || triple.includes?("i586") || triple.includes?("i686")
      X86.new(target_machine)
    elsif triple.includes?("aarch64") || triple.includes?("arm64")
      AArch64.new(target_machine)
    elsif triple.includes?("arm")
      ARM.new(target_machine)
    elsif triple.includes?("avr")
      AVR.new(target_machine, target_machine.cpu)
    elsif triple.includes?("wasm32")
      Wasm32.new(target_machine)
    else
      raise "Unsupported ABI for target triple: #{triple}"
    end
  end

  abstract def abi_info(atys : Array(LLVM::Type), rty : LLVM::Type, ret_def : Bool, context : Context)
  abstract def size(type : LLVM::Type)
  abstract def align(type : LLVM::Type)

  def size(type : LLVM::Type, pointer_size) : Int32
    case type.kind
    when LLVM::Type::Kind::Integer
      (type.int_width + 7) // 8
    when LLVM::Type::Kind::Float
      4
    when LLVM::Type::Kind::Double
      8
    when LLVM::Type::Kind::Pointer
      pointer_size
    when LLVM::Type::Kind::Struct
      if type.packed_struct?
        type.struct_element_types.reduce(0) do |memo, elem|
          memo + size(elem)
        end
      else
        size = type.struct_element_types.reduce(0) do |memo, elem|
          align_offset(memo, elem) + size(elem)
        end
        align_offset(size, type)
      end
    when LLVM::Type::Kind::Array
      size(type.element_type) * type.array_size
    else
      raise "Unhandled LLVM::Type::Kind in size: #{type.kind}"
    end
  end

  def align_offset(offset, type) : Int32
    align = align(type)
    (offset + align - 1) // align * align
  end

  def align(type : LLVM::Type, pointer_size) : Int32
    case type.kind
    when LLVM::Type::Kind::Integer
      (type.int_width + 7) // 8
    when LLVM::Type::Kind::Float
      4
    when LLVM::Type::Kind::Double
      8
    when LLVM::Type::Kind::Pointer
      pointer_size
    when LLVM::Type::Kind::Struct
      if type.packed_struct?
        1
      else
        type.struct_element_types.reduce(1) do |memo, elem|
          Math.max(memo, align(elem))
        end
      end
    when LLVM::Type::Kind::Array
      align(type.element_type)
    else
      raise "Unhandled LLVM::Type::Kind in align: #{type.kind}"
    end
  end

  enum ArgKind
    Direct
    Indirect
    Ignore
  end

  struct ArgType
    getter kind : ArgKind
    getter type : LLVM::Type
    getter cast : LLVM::Type?
    getter pad : Nil
    getter attr : LLVM::Attribute?

    def self.direct(type, cast = nil, pad = nil, attr = nil)
      new ArgKind::Direct, type, cast, pad, attr
    end

    def self.indirect(type, attr) : self
      new ArgKind::Indirect, type, attr: attr
    end

    def self.ignore(type) : self
      new ArgKind::Ignore, type
    end

    def initialize(@kind, @type, @cast = nil, @pad = nil, @attr = nil)
    end
  end

  class FunctionType
    getter arg_types : Array(ArgType)
    getter return_type : ArgType

    def initialize(@arg_types, @return_type)
    end
  end
end
