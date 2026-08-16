# iyi: what the front end needs from `LLVM`, without linking it.
#
# **Why this file exists is a measurement.** Starting the compiler and doing
# nothing costs 0.029 s against a 0.042 s front end. The dynamic loader is a
# millisecond of that; the rest is libLLVM's load-time initialisers, which a
# process pays for linking the library rather than for calling it. A C program
# whose `main` returns zero costs 0.001 s built plainly and 0.026 s built with a
# `NEEDED` entry on libLLVM and no call to it.
#
# `crystal build --no-codegen` is exactly a process that never calls it. So a
# front end that does not link it starts in 0.004 s like any other Crystal
# program, and the figure the 0.1.0 target is set on becomes mostly analysis
# rather than mostly a code generator coming up (SPEC.md 0.1.0, IV.1d).
#
# Required in place of `llvm` under `-Dwithout_llvm`, and nowhere else. What it
# has to cover is small, which is the finding that made the split worth trying:
# outside codegen the compiler names `LLVM` in four places, and three of them
# are strings decided when this binary was built.
# Skipped unless asked for, because `requires.cr` globs this directory and a
# build that has the library must not also have this.
{% skip_file unless flag?(:without_llvm) %}

module LLVM
  # Baked at build time by the Makefile rather than asked of the library.
  # `LLVM.version` is a string in the report and in `Crystal::LLVM_VERSION`,
  # and a build that cannot generate code still has to say which LLVM the
  # compiler that *can* was built against.
  VERSION = {{ env("CRYSTAL_CONFIG_LLVM_VERSION") || "unknown" }}

  def self.version : String
    VERSION
  end

  # The host triple, likewise baked. With LLVM this is `LLVMGetDefaultTargetTriple`;
  # without it there is nothing to ask, and the answer does not change between
  # runs of one binary on one machine.
  def self.default_target_triple : String
    {{ env("CRYSTAL_CONFIG_TARGET") || "" }}
  end

  # Identity, and the one place this shim is weaker than the library.
  #
  # `LLVMNormalizeTargetTriple` turns `x86_64-linux` into
  # `x86_64-pc-linux-gnu`. The host triple arrives normalised already — it is
  # baked above from a build that had LLVM — so this only matters for a triple
  # a user types, and a front end that cannot generate code for it is a
  # strange place to be typing one.
  def self.normalize_triple(triple : String) : String
    triple
  end

  # Used by `Crystal::External#call_convention` and by `@[CallConvention]`,
  # which the front end reads and checks. The values are LLVM's, kept in step
  # with `src/llvm/enums.cr` — they are ABI, so they do not drift.
  enum CallConvention
    C            =  0
    Fast         =  8
    Cold         =  9
    WebKit_JS    = 12
    AnyReg       = 13
    X86_StdCall  = 64
    X86_FastCall = 65
    ARM_APCS     = 66
    ARM_AAPCS    = 67
    ARM_AAPCS_VFP = 68
    MSP430_INTR  = 69
    X86_ThisCall = 70
    PTX_Kernel   = 71
    PTX_Device   = 72
    SPIR_FUNC    = 75
    SPIR_KERNEL  = 76
    Intel_OCL_BI = 77
    X86_64_SysV  = 78
    X86_64_Win64 = 79
    X86_VectorCall = 80
  end
end
