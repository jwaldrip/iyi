#include <llvm-c/TargetMachine.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Target/TargetMachine.h>

using namespace llvm;

#define LLVM_VERSION_GE(major, minor)                                          \
  (LLVM_VERSION_MAJOR > (major) ||                                             \
   LLVM_VERSION_MAJOR == (major) && LLVM_VERSION_MINOR >= (minor))

#if !LLVM_VERSION_GE(9, 0)
#include <llvm/IR/DIBuilder.h>
#endif

#if LLVM_VERSION_GE(16, 0)
#define makeArrayRef ArrayRef
#endif

// iyi: `LLVMExtCreateTargetMachineWasmEH` needs the option registry and the
// `LLVMCodeModel` mapping the C API keeps to itself.
#if LLVM_VERSION_GE(18, 0)
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Target/CodeGenCWrappers.h>
#include <optional>
#endif

#if !LLVM_VERSION_GE(18, 0)
typedef struct LLVMOpaqueOperandBundle *LLVMOperandBundleRef;
DEFINE_SIMPLE_CONVERSION_FUNCTIONS(OperandBundleDef, LLVMOperandBundleRef)
#endif

extern "C" {

#if !LLVM_VERSION_GE(9, 0)
LLVMMetadataRef LLVMExtDIBuilderCreateEnumerator(LLVMDIBuilderRef Builder,
                                                 const char *Name,
                                                 size_t NameLen, int64_t Value,
                                                 LLVMBool IsUnsigned) {
  return wrap(unwrap(Builder)->createEnumerator({Name, NameLen}, Value,
                                                IsUnsigned != 0));
}

void LLVMExtClearCurrentDebugLocation(LLVMBuilderRef B) {
  unwrap(B)->SetCurrentDebugLocation(DebugLoc::get(0, 0, nullptr));
}
#endif

#if !LLVM_VERSION_GE(18, 0)
LLVMOperandBundleRef LLVMExtCreateOperandBundle(const char *Tag, size_t TagLen,
                                                LLVMValueRef *Args,
                                                unsigned NumArgs) {
  return wrap(new OperandBundleDef(std::string(Tag, TagLen),
                                   makeArrayRef(unwrap(Args), NumArgs)));
}

void LLVMExtDisposeOperandBundle(LLVMOperandBundleRef Bundle) {
  delete unwrap(Bundle);
}

LLVMValueRef LLVMExtBuildCallWithOperandBundles(
    LLVMBuilderRef B, LLVMTypeRef Ty, LLVMValueRef Fn, LLVMValueRef *Args,
    unsigned NumArgs, LLVMOperandBundleRef *Bundles, unsigned NumBundles,
    const char *Name) {
  FunctionType *FTy = unwrap<FunctionType>(Ty);
  SmallVector<OperandBundleDef, 8> OBs;
  for (auto *Bundle : makeArrayRef(Bundles, NumBundles)) {
    OperandBundleDef *OB = unwrap(Bundle);
    OBs.push_back(*OB);
  }
  return wrap(unwrap(B)->CreateCall(
      FTy, unwrap(Fn), makeArrayRef(unwrap(Args), NumArgs), OBs, Name));
}

LLVMValueRef LLVMExtBuildInvokeWithOperandBundles(
    LLVMBuilderRef B, LLVMTypeRef Ty, LLVMValueRef Fn, LLVMValueRef *Args,
    unsigned NumArgs, LLVMBasicBlockRef Then, LLVMBasicBlockRef Catch,
    LLVMOperandBundleRef *Bundles, unsigned NumBundles, const char *Name) {
  SmallVector<OperandBundleDef, 8> OBs;
  for (auto *Bundle : makeArrayRef(Bundles, NumBundles)) {
    OperandBundleDef *OB = unwrap(Bundle);
    OBs.push_back(*OB);
  }
  return wrap(unwrap(B)->CreateInvoke(
      unwrap<FunctionType>(Ty), unwrap(Fn), unwrap(Then), unwrap(Catch),
      makeArrayRef(unwrap(Args), NumArgs), OBs, Name));
}
#endif

#if !LLVM_VERSION_GE(18, 0)
static TargetMachine *unwrap(LLVMTargetMachineRef P) {
  return reinterpret_cast<TargetMachine *>(P);
}

void LLVMExtSetTargetMachineGlobalISel(LLVMTargetMachineRef T,
                                       LLVMBool Enable) {
  unwrap(T)->setGlobalISel(Enable);
}
#endif

#if LLVM_VERSION_GE(18, 0)
// iyi: a target machine whose exception model is wasm, which is the one thing
// the LLVM C API cannot build and the whole reason this file is compiled again
// on LLVM 18 and newer.
//
// `TargetPassConfig::addPassesToHandleExceptions` (llvm/lib/CodeGen/
// TargetPassConfig.cpp:920) switches on `TM->getMCAsmInfo()
// ->getExceptionHandlingType()`, and for wasm that field starts at
// `ExceptionHandling::None` (WebAssemblyMCAsmInfo.cpp:58). The only thing that
// changes it is `LLVMTargetMachine::initAsmInfo()`, which copies
// `Options.ExceptionModel` — and `initAsmInfo()` runs inside the
// `WebAssemblyTargetMachine` constructor (WebAssemblyTargetMachine.cpp:215)
// one line *before* `basicCheckForEHAndSjLj` gets a chance to infer the model
// from `-wasm-enable-eh`. So the field has to be set before construction, and
// `LLVMCreateTargetMachine` builds its own `TargetOptions` and never touches
// it: with the C API alone, every `invoke` is replaced by a plain call and
// every landing pad is deleted, silently.
//
// `-wasm-enable-eh` is a `cl::opt` in the backend, so it is reachable through
// the registry rather than through a command line. Assigning through
// `cl::opt::operator=` rather than `addOccurrence` keeps this callable more
// than once, which the compiler does.
static void llvmExtSetBoolOption(const char *Name, bool Value) {
  auto &Registered = cl::getRegisteredOptions();
  auto Found = Registered.find(Name);
  if (Found == Registered.end())
    return;
  *static_cast<cl::opt<bool> *>(Found->second) = Value;
}

LLVMTargetMachineRef
LLVMExtCreateTargetMachineWasmEH(LLVMTargetRef T, const char *TripleStr,
                                 const char *CPU, const char *Features,
                                 LLVMCodeGenOptLevel Level, LLVMRelocMode Reloc,
                                 LLVMCodeModel CodeModel, LLVMBool LegacyEH) {
  llvmExtSetBoolOption("wasm-enable-eh", true);
  llvmExtSetBoolOption("wasm-use-legacy-eh", LegacyEH != 0);

  CodeGenOptLevel OL;
  switch (Level) {
  case LLVMCodeGenLevelNone:
    OL = CodeGenOptLevel::None;
    break;
  case LLVMCodeGenLevelLess:
    OL = CodeGenOptLevel::Less;
    break;
  case LLVMCodeGenLevelAggressive:
    OL = CodeGenOptLevel::Aggressive;
    break;
  default:
    OL = CodeGenOptLevel::Default;
    break;
  }

  std::optional<Reloc::Model> RM;
  switch (Reloc) {
  case LLVMRelocStatic:
    RM = Reloc::Static;
    break;
  case LLVMRelocPIC:
    RM = Reloc::PIC_;
    break;
  case LLVMRelocDynamicNoPic:
    RM = Reloc::DynamicNoPIC;
    break;
  case LLVMRelocROPI:
    RM = Reloc::ROPI;
    break;
  case LLVMRelocRWPI:
    RM = Reloc::RWPI;
    break;
  case LLVMRelocROPI_RWPI:
    RM = Reloc::ROPI_RWPI;
    break;
  default:
    break;
  }

  bool JIT = false;
  std::optional<CodeModel::Model> CM = unwrap(CodeModel, JIT);

  TargetOptions Options;
  Options.ExceptionModel = ExceptionHandling::Wasm;

  const Target *Target = reinterpret_cast<const class Target *>(T);
#if LLVM_VERSION_GE(21, 0)
  TargetMachine *Machine = Target->createTargetMachine(
      Triple(TripleStr), CPU, Features, Options, RM, CM, OL, JIT);
#else
  TargetMachine *Machine = Target->createTargetMachine(
      StringRef(TripleStr), CPU, Features, Options, RM, CM, OL, JIT);
#endif
  return reinterpret_cast<LLVMTargetMachineRef>(Machine);
}
#endif

} // extern "C"
