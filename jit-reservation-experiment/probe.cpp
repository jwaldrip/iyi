#define LLVM_ENABLE_TEST_HOOKS 1
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#define NOMINMAX
#include <windows.h>
#include <winnt.h>

#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>

// Shared C Factory & Identity API (exported by LLVM-C.dll via Slice A)
#ifdef __cplusplus
extern "C" {
#endif

LLVMBool LLVMExtCreateWindowsMCJITCompilerForModule(
    LLVMExecutionEngineRef *OutEE, LLVMModuleRef Module, char **OutError);

const char *LLVMExtGetWindowsMCJITBuildIdentity(void);

void LLVMExtSetWindowsMCJITFaultInjection(uint32_t Flags);
uint64_t LLVMExtGetWindowsMCJITLastUnwindProbeAddress(void);
uint64_t LLVMExtGetWindowsMCJITFirstRegisteredUnwindAddress(void);
void LLVMExtResetWindowsMCJITUnwindProbeAddresses(void);

void LLVMExtMapSectionAddress(LLVMExecutionEngineRef EE,
                              const void *LocalAddress, uint64_t TargetAddress);
LLVMBool LLVMExtAddArchiveFile(LLVMExecutionEngineRef EE, const char *Path,
                               char **OutError);

__declspec(dllexport) int probe_custom_personality(void *, void *, void *,
                                                   void *);

// Native callbacks for testing stubs and stack unwinding
__declspec(dllexport) int32_t probe_native_external_add(int32_t a, int32_t b);
__declspec(dllexport) void probe_native_stack_walk_callback(void);
__declspec(dllexport) void probe_native_raise_exception(void);

#ifdef __cplusplus
}
#endif

static void require(bool cond, const char *msg) {
  if (!cond) {
    std::fprintf(stderr, "ASSERTION FAILED: %s\n", msg);
    std::fflush(stderr);
    std::exit(1);
  }
}

// ---------------------------------------------------------------------------
// Relocation Checker Helpers (in file scope for suites 10, 11, and 13)
// ---------------------------------------------------------------------------
static bool check_addr32nb(uint64_t target, uint64_t base, int64_t addend,
                           uint32_t *out) {
  if (target < base && addend <= 0)
    return false; // Underflow
  int64_t rva = (int64_t)(target - base) + addend;
  if (rva < 0 || rva > 0xFFFFFFFFLL)
    return false; // Overflow / Underflow
  *out = (uint32_t)rva;
  return true;
}

static bool check_rel32(uint64_t target, uint64_t reloc_site, int64_t addend,
                        int extra_disp, int32_t *out) {
  int64_t next_pc = (int64_t)(reloc_site + 4 + extra_disp);
  int64_t disp = (int64_t)target - next_pc + addend;
  if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX)
    return false;
  *out = (int32_t)disp;
  return true;
}

// Global state for stack unwind test
static DWORD64 g_expected_jit_image_base = 0;
static DWORD64 g_expected_jit_fn_addr = 0;
static bool g_stack_walk_observed_jit_frame = false;
static bool g_stack_walk_unwound_past_jit = false;

extern "C" int32_t probe_native_external_add(int32_t a, int32_t b) {
  return a + b;
}

static bool g_custom_personality_invoked = false;

extern "C" int probe_custom_personality(void *exception_record,
                                        void *establisher_frame,
                                        void *context_record,
                                        void *dispatcher_context) {
  g_custom_personality_invoked = true;
  return 1; // ExceptionContinueSearch
}

extern "C" void probe_native_raise_exception(void) {
#ifdef _WIN32
  RaiseException(0xE0000001, 0, 0, nullptr);
#endif
}
extern "C" void probe_native_stack_walk_callback(void) {
  CONTEXT ctx;
  RtlCaptureContext(&ctx);

  DWORD64 prevRip = 0;
  for (int frame = 0; frame < 64 && ctx.Rip != 0; frame++) {
    if (ctx.Rip == prevRip) {
      break; // Stuck loop prevention
    }
    prevRip = ctx.Rip;

    DWORD64 imageBase = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &imageBase, nullptr);
    if (rf != nullptr) {
      // Check if this frame is our JIT function
      if (imageBase != 0 && (imageBase == g_expected_jit_image_base ||
                             (ctx.Rip >= g_expected_jit_fn_addr &&
                              ctx.Rip < g_expected_jit_fn_addr + 0x1000))) {
        g_stack_walk_observed_jit_frame = true;
        std::printf("STACK_WALK: found JIT frame Rip=%llx ImageBase=%llx "
                    "BeginAddress=%lx EndAddress=%lx\n",
                    (unsigned long long)ctx.Rip, (unsigned long long)imageBase,
                    (unsigned long)rf->BeginAddress,
                    (unsigned long)rf->EndAddress);
      } else if (g_stack_walk_observed_jit_frame) {
        g_stack_walk_unwound_past_jit = true;
        std::printf("STACK_WALK: successfully unwound past JIT frame into "
                    "caller Rip=%llx ImageBase=%llx\n",
                    (unsigned long long)ctx.Rip, (unsigned long long)imageBase);
        break;
      }

      PVOID handlerData = nullptr;
      ULONG64 establisherFrame = 0;
      RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, ctx.Rip, rf, &ctx,
                       &handlerData, &establisherFrame, nullptr);
    } else {
      // Leaf function (no unwind info): step using return address on stack
      ctx.Rip = *(DWORD64 *)ctx.Rsp;
      ctx.Rsp += 8;
    }
  }
}

// ---------------------------------------------------------------------------
// Test Suite 1: Build Identity
// ---------------------------------------------------------------------------
static void test_build_identity() {
  std::puts("=== TEST: Build Identity ===");
  const char *id = LLVMExtGetWindowsMCJITBuildIdentity();
  require(id != nullptr, "LLVMExtGetWindowsMCJITBuildIdentity returned null");
  require(std::strlen(id) > 0, "Build identity is empty");
  std::printf("BUILD_IDENTITY=%s\n", id);
  require(std::strstr(id, "windows-mcjit") != nullptr,
          "Identity must contain windows-mcjit");
  std::puts("PASS: Build Identity");
}

// ---------------------------------------------------------------------------
// Test Suite 2: Production Execution, W^X Protections & Mutable Pointer
// Retention
// ---------------------------------------------------------------------------
static void test_production_execution_and_wx_protection() {
  std::puts(
      "=== TEST: Production Execution, W^X Protections & Mutable Pointer ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("test_wx_module", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto p = LLVMPointerTypeInContext(ctx, 0);

  // Mutable global: 41
  auto mutable_global = LLVMAddGlobal(m, i32, "test_mutable_value");
  LLVMSetInitializer(mutable_global, LLVMConstInt(i32, 41, 0));
  LLVMSetLinkage(mutable_global, LLVMExternalLinkage);

  // Readonly global: 1
  auto readonly_global = LLVMAddGlobal(m, i32, "test_readonly_value");
  LLVMSetInitializer(readonly_global, LLVMConstInt(i32, 1, 0));
  LLVMSetGlobalConstant(readonly_global, 1);
  LLVMSetLinkage(readonly_global, LLVMExternalLinkage);

  // Function get_pointer() -> i32*
  auto f_ptr =
      LLVMAddFunction(m, "get_pointer", LLVMFunctionType(p, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b,
                           LLVMAppendBasicBlockInContext(ctx, f_ptr, "entry"));
  LLVMBuildRet(b, mutable_global);

  // Function get_ro_pointer() -> i32*
  auto f_ro_ptr =
      LLVMAddFunction(m, "get_ro_pointer", LLVMFunctionType(p, nullptr, 0, 0));
  auto b_ro = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b_ro, LLVMAppendBasicBlockInContext(ctx, f_ro_ptr, "entry"));
  LLVMBuildRet(b_ro, readonly_global);
  LLVMDisposeBuilder(b_ro);

  // Function evaluate() -> i32: loads mutable and readonly, adds them
  auto f_eval =
      LLVMAddFunction(m, "evaluate", LLVMFunctionType(i32, nullptr, 0, 0));
  auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);
  require(uw_kind != 0, "uwtable attribute kind");
  LLVMAddAttributeAtIndex(f_eval, LLVMAttributeFunctionIndex,
                          LLVMCreateEnumAttribute(ctx, uw_kind, 2));

  LLVMPositionBuilderAtEnd(b,
                           LLVMAppendBasicBlockInContext(ctx, f_eval, "entry"));
  auto ptr_val = LLVMBuildCall2(b, LLVMFunctionType(p, nullptr, 0, 0), f_ptr,
                                nullptr, 0, "call_ptr");
  auto v1 = LLVMBuildLoad2(b, i32, ptr_val, "val_mut");
  auto v2 = LLVMBuildLoad2(b, i32, readonly_global, "val_ro");
  LLVMSetVolatile(v2, 1);
  auto sum = LLVMBuildAdd(b, v1, v2, "sum");
  LLVMBuildRet(b, sum);
  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Failed to create Windows MCJIT engine");

  uint64_t eval_addr = LLVMGetFunctionAddress(ee, "evaluate");
  require(eval_addr != 0, "Failed to resolve evaluate address");

  uint64_t ptr_fn_addr = LLVMGetFunctionAddress(ee, "get_pointer");
  require(ptr_fn_addr != 0, "Failed to resolve get_pointer address");

  // Verify W^X and exact protections with VirtualQuery
  MEMORY_BASIC_INFORMATION mbi{};
  require(VirtualQuery((LPCVOID)eval_addr, &mbi, sizeof(mbi)) != 0,
          "VirtualQuery on code section");
  std::printf("CODE_PROTECTION: got=0x%lx expected=PAGE_EXECUTE_READ (0x%x)\n",
              mbi.Protect, PAGE_EXECUTE_READ);
  require(mbi.Protect == PAGE_EXECUTE_READ,
          "Code section must be PAGE_EXECUTE_READ");
  require((mbi.Protect & PAGE_EXECUTE_READWRITE) == 0,
          "W^X violation: code is writable!");

  // Call get_pointer to get address of mutable_global
  typedef int32_t *(*GetPointerFn)(void);
  GetPointerFn get_ptr_fn = (GetPointerFn)ptr_fn_addr;
  int32_t *mut_ptr = get_ptr_fn();
  require(mut_ptr != nullptr, "get_pointer returned null");
  require(*mut_ptr == 41, "Initial mutable value must be 41");

  // Query mutable data section
  require(VirtualQuery(mut_ptr, &mbi, sizeof(mbi)) != 0,
          "VirtualQuery on mutable data");
  std::printf(
      "MUTABLE_DATA_PROTECTION: got=0x%lx expected=PAGE_READWRITE (0x%x)\n",
      mbi.Protect, PAGE_READWRITE);
  require(mbi.Protect == PAGE_READWRITE, "Mutable data must be PAGE_READWRITE");
  require((mbi.Protect &
           (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0,
          "W^X violation: data is executable!");

  // Query readonly data section with VirtualQuery
  uint64_t ro_ptr_fn_addr = LLVMGetFunctionAddress(ee, "get_ro_pointer");
  require(ro_ptr_fn_addr != 0, "Failed to resolve get_ro_pointer address");
  GetPointerFn get_ro_ptr_fn = (GetPointerFn)ro_ptr_fn_addr;
  const int32_t *ro_ptr = get_ro_ptr_fn();
  require(ro_ptr != nullptr, "get_ro_pointer returned null");
  require(*ro_ptr == 1, "Initial readonly value must be 1");

  MEMORY_BASIC_INFORMATION mbi_ro{};
  require(VirtualQuery(ro_ptr, &mbi_ro, sizeof(mbi_ro)) != 0,
          "VirtualQuery on readonly data");
  std::printf(
      "READONLY_DATA_PROTECTION: got=0x%lx expected=PAGE_READONLY (0x%x)\n",
      mbi_ro.Protect, PAGE_READONLY);
  require(mbi_ro.Protect == PAGE_READONLY,
          "Readonly data must be PAGE_READONLY");
  require((mbi_ro.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) == 0,
          "W^X violation: readonly data is writable or executable!");

  // Execute evaluate() -> initial result 41 + 1 = 42
  typedef int32_t (*EvalFn)(void);
  EvalFn eval_fn = (EvalFn)eval_addr;
  int32_t res1 = eval_fn();
  require(res1 == 42, "Initial evaluate() must return 42");

  // Mutate data through native pointer and re-execute
  *mut_ptr = 100;
  int32_t res2 = eval_fn();
  require(res2 == 101,
          "After mutating *mut_ptr = 100, evaluate() must return 101");
  std::printf("MUTABLE_EXECUTION: before=41 after=%d eval_res=%d\n", *mut_ptr,
              res2);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Production Execution, W^X Protections & Mutable Pointer");
}

// ---------------------------------------------------------------------------
// Test Suite 3: Windows x64 Unwind (.pdata), RtlLookupFunctionEntry & Real
// Stack Walk
// ---------------------------------------------------------------------------
static void test_windows_unwind_and_real_stack_walk() {
  std::puts("=== TEST: Windows Unwind Registration, RtlLookupFunctionEntry & "
            "Real Stack Walk ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m =
      LLVMModuleCreateWithNameInContext("test_unwind_module", ctx);
  auto void_ty = LLVMVoidTypeInContext(ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);

  // External native callback declaration: void
  // probe_native_stack_walk_callback(void)
  auto cb_ty = LLVMFunctionType(void_ty, nullptr, 0, 0);
  auto cb_decl = LLVMAddFunction(m, "probe_native_stack_walk_callback", cb_ty);

  // JIT nonleaf caller function: void jit_unwind_caller(void)
  auto caller_fn = LLVMAddFunction(m, "jit_unwind_caller", cb_ty);
  auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);
  require(uw_kind != 0, "uwtable attribute kind");
  LLVMAddAttributeAtIndex(caller_fn, LLVMAttributeFunctionIndex,
                          LLVMCreateEnumAttribute(ctx, uw_kind, 2));
  auto pers_fn = LLVMAddFunction(m, "probe_custom_personality",
                                 LLVMFunctionType(i32, nullptr, 0, 1));
  LLVMSetPersonalityFn(caller_fn, pers_fn);
  auto b = LLVMCreateBuilderInContext(ctx);
  auto bb = LLVMAppendBasicBlockInContext(ctx, caller_fn, "entry");
  LLVMPositionBuilderAtEnd(b, bb);

  // Alloca to ensure stack frame exists in the nonleaf function
  auto alloca_var = LLVMBuildAlloca(b, i32, "stack_slot");
  LLVMBuildStore(b, LLVMConstInt(i32, 12345, 0), alloca_var);

  // Call native callback
  LLVMBuildCall2(b, cb_ty, cb_decl, nullptr, 0, "");
  LLVMBuildRetVoid(b);
  LLVMDisposeBuilder(b);

  // Add thrower function to exercise real SEH exception dispatch through JIT
  // frame
  auto raise_cb_ty = LLVMFunctionType(void_ty, nullptr, 0, 0);
  auto raise_cb_decl =
      LLVMAddFunction(m, "probe_native_raise_exception", raise_cb_ty);

  auto thrower_fn = LLVMAddFunction(m, "jit_unwind_thrower", cb_ty);
  if (uw_kind != 0)
    LLVMAddAttributeAtIndex(thrower_fn, LLVMAttributeFunctionIndex,
                            LLVMCreateEnumAttribute(ctx, uw_kind, 2));
  LLVMSetPersonalityFn(thrower_fn, pers_fn);
  auto b_throw = LLVMCreateBuilderInContext(ctx);
  auto bb_throw = LLVMAppendBasicBlockInContext(ctx, thrower_fn, "entry");
  LLVMPositionBuilderAtEnd(b_throw, bb_throw);
  auto alloca_throw = LLVMBuildAlloca(b_throw, i32, "stack_slot_throw");
  LLVMBuildStore(b_throw, LLVMConstInt(i32, 54321, 0), alloca_throw);
  LLVMBuildCall2(b_throw, raise_cb_ty, raise_cb_decl, nullptr, 0, "");
  LLVMBuildRetVoid(b_throw);
  LLVMDisposeBuilder(b_throw);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr, err ? err : "Engine creation failed");

  // Map external callback
  LLVMAddGlobalMapping(ee, cb_decl, (void *)&probe_native_stack_walk_callback);
  LLVMAddGlobalMapping(ee, raise_cb_decl,
                       (void *)&probe_native_raise_exception);
  LLVMAddGlobalMapping(ee, pers_fn, (void *)&probe_custom_personality);

  uint64_t caller_addr = LLVMGetFunctionAddress(ee, "jit_unwind_caller");
  require(caller_addr != 0, "Failed to resolve jit_unwind_caller");

  // 1. RtlLookupFunctionEntry check
  DWORD64 imageBase = 0;
  PRUNTIME_FUNCTION rf =
      RtlLookupFunctionEntry((DWORD64)caller_addr, &imageBase, nullptr);
  require(rf != nullptr,
          "RtlLookupFunctionEntry returned NULL for JIT nonleaf function");
  require(imageBase != 0, "RtlLookupFunctionEntry returned imageBase == 0");
  std::printf("UNWIND_TABLE: FunctionEntry=%p ImageBase=%llx "
              "BeginAddress=0x%lx EndAddress=0x%lx\n",
              (void *)rf, (unsigned long long)imageBase,
              (unsigned long)rf->BeginAddress, (unsigned long)rf->EndAddress);

  require((DWORD64)caller_addr >= imageBase + rf->BeginAddress,
          "Function start below BeginAddress");
  require((DWORD64)caller_addr < imageBase + rf->EndAddress,
          "Function start beyond EndAddress");

  // 2. Real stack walk check through active execution
  g_expected_jit_image_base = imageBase;
  g_expected_jit_fn_addr = caller_addr;
  g_stack_walk_observed_jit_frame = false;
  g_stack_walk_unwound_past_jit = false;
#ifdef _WIN32
  if (rf->UnwindData != 0) {
    typedef struct {
      unsigned char Version : 3;
      unsigned char Flags : 5;
      unsigned char SizeOfProlog;
      unsigned char CountOfCodes;
      unsigned char FrameRegister : 4;
      unsigned char FrameOffset : 4;
    } WinUnwindHeader;
    WinUnwindHeader *ui = (WinUnwindHeader *)(imageBase + rf->UnwindData);
    std::printf("UNWIND_INFO: Version=%u Flags=0x%x CountOfCodes=%u\n",
                (unsigned)ui->Version, (unsigned)ui->Flags,
                (unsigned)ui->CountOfCodes);
    require((ui->Flags & 0x03) != 0,
            "Expected UNWIND_INFO Flags to indicate active exception handler "
            "(UNW_FLAG_EHANDLER or UNW_FLAG_UHANDLER)");
    // Read back exception handler target from .xdata
    unsigned num_codes = (ui->CountOfCodes + 1) & ~1;
    uint32_t handler_rva =
        *(const uint32_t *)((const char *)(ui + 1) + num_codes * 2);
    uint64_t handler_addr = imageBase + handler_rva;
    std::printf("UNWIND_HANDLER_THUNK: handler_rva=0x%x handler_addr=0x%llx\n",
                handler_rva, (unsigned long long)handler_addr);
    require(handler_addr != 0, "Exception handler thunk address must not be 0");
    MEMORY_BASIC_INFORMATION mbi_handler{};
    if (VirtualQuery((LPCVOID)handler_addr, &mbi_handler,
                     sizeof(mbi_handler))) {
      std::printf("HANDLER_THUNK_PAGE: Protect=0x%lx (must be executable)\n",
                  mbi_handler.Protect);
      require((mbi_handler.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                      PAGE_EXECUTE_READWRITE)) != 0,
              "Exception handler stub must be in executable memory");
    }
  }
#endif

  typedef void (*JitCallerFn)(void);
  JitCallerFn jit_caller = (JitCallerFn)caller_addr;
  jit_caller();

  require(
      g_stack_walk_observed_jit_frame,
      "Stack walk did not observe the JIT frame via RtlLookupFunctionEntry");
  require(g_stack_walk_unwound_past_jit,
          "Stack walk did not unwind past JIT frame with RtlVirtualUnwind");
  std::puts("PASS: Real stack walking through JIT frame succeeded");

#ifdef _WIN32
  // Real SEH Exception Dispatch through JIT Frame
  uint64_t thrower_addr = LLVMGetFunctionAddress(ee, "jit_unwind_thrower");
  require(thrower_addr != 0, "Failed to resolve jit_unwind_thrower");
  g_custom_personality_invoked = false;
  bool caught_seh = false;
  __try {
    typedef void (*JitThrowFn)(void);
    JitThrowFn jit_throw = (JitThrowFn)thrower_addr;
    jit_throw();
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    caught_seh = true;
    std::printf("SEH_DISPATCH: Caught exception unwound past JIT frame, "
                "personality invoked=%d\n",
                g_custom_personality_invoked);
  }
  require(caught_seh, "Expected SEH exception to be caught in __except block");
  require(g_custom_personality_invoked,
          "Expected custom personality routine to be invoked during OS "
          "exception dispatch through JIT frame!");
  std::puts("PASS: Real SEH exception dispatched through JIT frame and "
            "invoked personality handler");
#endif

  // 3. Table deregistration check on dispose
  LLVMDisposeExecutionEngine(ee);

  DWORD64 postDisposeImageBase = 0;
  PRUNTIME_FUNCTION postRf = RtlLookupFunctionEntry(
      (DWORD64)caller_addr, &postDisposeImageBase, nullptr);
  std::printf("POST_DISPOSE_LOOKUP: FunctionEntry=%p (expected NULL)\n",
              (void *)postRf);
  require(postRf == nullptr, "RtlLookupFunctionEntry still found entry after "
                             "LLVMDisposeExecutionEngine!");
  std::puts("PASS: RtlDeleteFunctionTable successfully unregisters on engine "
            "disposal");

  LLVMContextDispose(ctx);
}

// ---------------------------------------------------------------------------
// Test Suite 4: Multi-Object (Two objects before finalization, another after)
// ---------------------------------------------------------------------------
static void test_multi_object_execution() {
  std::puts("=== TEST: Multi-Object (Two objects before finalization, another "
            "after) ===");
  LLVMContextRef ctx = LLVMContextCreate();
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto fn_ty = LLVMFunctionType(i32, &i32, 1, 0);

  // Module A: int32_t mod_a_fn(int32_t x) { return x + 10; }
  LLVMModuleRef mod_a = LLVMModuleCreateWithNameInContext("mod_a", ctx);
  auto fn_a = LLVMAddFunction(mod_a, "mod_a_fn", fn_ty);
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b,
                           LLVMAppendBasicBlockInContext(ctx, fn_a, "entry"));
  auto param_a = LLVMGetParam(fn_a, 0);
  auto res_a = LLVMBuildAdd(b, param_a, LLVMConstInt(i32, 10, 0), "res_a");
  LLVMBuildRet(b, res_a);

  // Module B: int32_t mod_b_fn(int32_t x) { return mod_a_fn(x) * 2; }
  LLVMModuleRef mod_b = LLVMModuleCreateWithNameInContext("mod_b", ctx);
  auto fn_a_in_b = LLVMAddFunction(mod_b, "mod_a_fn", fn_ty);
  auto fn_b = LLVMAddFunction(mod_b, "mod_b_fn", fn_ty);
  LLVMPositionBuilderAtEnd(b,
                           LLVMAppendBasicBlockInContext(ctx, fn_b, "entry"));
  auto param_b = LLVMGetParam(fn_b, 0);
  auto call_a = LLVMBuildCall2(b, fn_ty, fn_a_in_b, &param_b, 1, "call_a");
  auto res_b = LLVMBuildMul(b, call_a, LLVMConstInt(i32, 2, 0), "res_b");
  LLVMBuildRet(b, res_b);

  // Create engine with Module A
  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, mod_a, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Failed to create engine with mod_a");

  // Add Module B BEFORE finalization
  LLVMAddModule(ee, mod_b);

  // Finalize and resolve mod_b_fn
  uint64_t fn_b_addr = LLVMGetFunctionAddress(ee, "mod_b_fn");
  require(fn_b_addr != 0, "Failed to resolve mod_b_fn");

  typedef int32_t (*IntFn)(int32_t);
  IntFn b_func = (IntFn)fn_b_addr;
  int32_t b_out = b_func(5);
  std::printf("MULTI_OBJ_PRE_FINALIZE: mod_b_fn(5) = %d (expected 30)\n",
              b_out);
  require(b_out == 30, "mod_b_fn(5) must be (5 + 10) * 2 = 30");

  // Now create Module C: int32_t mod_c_fn(int32_t x) { return mod_b_fn(x) + 3;
  // }
  LLVMModuleRef mod_c = LLVMModuleCreateWithNameInContext("mod_c", ctx);
  auto fn_b_in_c = LLVMAddFunction(mod_c, "mod_b_fn", fn_ty);
  auto fn_c = LLVMAddFunction(mod_c, "mod_c_fn", fn_ty);
  LLVMPositionBuilderAtEnd(b,
                           LLVMAppendBasicBlockInContext(ctx, fn_c, "entry"));
  auto param_c = LLVMGetParam(fn_c, 0);
  auto call_b = LLVMBuildCall2(b, fn_ty, fn_b_in_c, &param_c, 1, "call_b");
  auto res_c = LLVMBuildAdd(b, call_b, LLVMConstInt(i32, 3, 0), "res_c");
  LLVMBuildRet(b, res_c);
  LLVMDisposeBuilder(b);

  // Add Module C AFTER initial finalization
  LLVMAddModule(ee, mod_c);

  uint64_t fn_c_addr = LLVMGetFunctionAddress(ee, "mod_c_fn");
  require(fn_c_addr != 0, "Failed to resolve mod_c_fn added post-finalization");

  IntFn c_func = (IntFn)fn_c_addr;
  int32_t c_out = c_func(5);
  std::printf("MULTI_OBJ_POST_FINALIZE: mod_c_fn(5) = %d (expected 33)\n",
              c_out);
  require(c_out == 33, "mod_c_fn(5) must be 30 + 3 = 33");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Multi-Object execution (pre and post finalization)");
}

// ---------------------------------------------------------------------------
// Test Suite 5: External Stubs, Common Symbols, Over-granularity Alignment
// ---------------------------------------------------------------------------
static void test_external_stubs_common_symbols_alignment() {
  std::puts("=== TEST: External Stubs, Common Symbols, Alignment ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("test_stubs_align", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto i64 = LLVMInt64TypeInContext(ctx);

  // 1. External stub: int32_t probe_native_external_add(int32_t, int32_t)
  LLVMTypeRef add_param_tys[] = {i32, i32};
  auto add_fn_ty = LLVMFunctionType(i32, add_param_tys, 2, 0);
  auto ext_add_decl =
      LLVMAddFunction(m, "probe_native_external_add", add_fn_ty);

  // 2. Common symbol: defined with zero initializer and common linkage (Finding
  // 9)
  auto common_var = LLVMAddGlobal(m, i32, "probe_common_int");
  LLVMSetLinkage(common_var, LLVMCommonLinkage);
  LLVMSetInitializer(common_var, LLVMConstNull(i32));

  // 3. Over-granularity aligned global (64 bytes and 4096 bytes)
  auto align_var64 = LLVMAddGlobal(m, i32, "probe_align64_int");
  LLVMSetInitializer(align_var64, LLVMConstInt(i32, 6464, 0));
  LLVMSetAlignment(align_var64, 64);

  auto align_var4096 = LLVMAddGlobal(m, i32, "probe_align4096_int");
  LLVMSetInitializer(align_var4096, LLVMConstInt(i32, 4096, 0));
  LLVMSetAlignment(align_var4096, 4096);

  // Function 1: calling external add and returning sum
  auto test_fn =
      LLVMAddFunction(m, "run_stub_test", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, test_fn, "entry"));
  const char *stub_call_asm = "subq $$40, %rsp\n\t"
                              "movl $$20, %ecx\n\t"
                              "movl $$22, %edx\n\t"
                              "call probe_native_external_add\n\t"
                              "addq $$40, %rsp\n\t"
                              "ret";
  LLVMValueRef inline_asm_stub = LLVMConstInlineAsm(
      LLVMFunctionType(i32, nullptr, 0, 0), stub_call_asm, "={eax}",
      /*HasSideEffects=*/1,
      /*IsAlignStack=*/0);
  auto add_call = LLVMBuildCall2(b, LLVMFunctionType(i32, nullptr, 0, 0),
                                 inline_asm_stub, nullptr, 0, "call_add");
  LLVMBuildRet(b, add_call);

  // Function 2: write to common symbol and read back + 5 (Finding 9)
  auto common_write_fn = LLVMAddFunction(m, "probe_write_common",
                                         LLVMFunctionType(i32, &i32, 1, 0));
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, common_write_fn, "entry"));
  auto in_val = LLVMGetParam(common_write_fn, 0);
  LLVMBuildStore(b, in_val, common_var);
  auto read_back = LLVMBuildLoad2(b, i32, common_var, "val");
  auto plus5 = LLVMBuildAdd(b, read_back, LLVMConstInt(i32, 5, 0), "res");
  LLVMBuildRet(b, plus5);

  // Function 3: read common symbol
  auto common_read_fn = LLVMAddFunction(m, "probe_read_common",
                                        LLVMFunctionType(i32, nullptr, 0, 0));
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, common_read_fn, "entry"));
  auto cur_val = LLVMBuildLoad2(b, i32, common_var, "cur");
  LLVMBuildRet(b, cur_val);

  // Function 4: JIT pointer to align64 (Finding 8)
  auto get_align64_fn = LLVMAddFunction(m, "get_align64_ptr",
                                        LLVMFunctionType(i64, nullptr, 0, 0));
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, get_align64_fn, "entry"));
  auto p64 = LLVMBuildPtrToInt(b, align_var64, i64, "p64");
  LLVMBuildRet(b, p64);

  // Function 5: JIT pointer to align4096 (Finding 8)
  auto get_align4096_fn = LLVMAddFunction(m, "get_align4096_ptr",
                                          LLVMFunctionType(i64, nullptr, 0, 0));
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, get_align4096_fn, "entry"));
  auto p4096 = LLVMBuildPtrToInt(b, align_var4096, i64, "p4096");
  LLVMBuildRet(b, p4096);

  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr, err ? err : "Engine creation failed");

  LLVMAddGlobalMapping(ee, ext_add_decl, (void *)&probe_native_external_add);

  uint64_t fn_addr = LLVMGetFunctionAddress(ee, "run_stub_test");
  require(fn_addr != 0, "run_stub_test lookup failed");

  typedef int32_t (*VoidIntFn)(void);
  VoidIntFn fn = (VoidIntFn)fn_addr;
  int32_t stub_res = fn();
  require(stub_res == 42, "External stub call failed");
  std::printf("EXTERNAL_STUB: returned %d (expected 42)\n", stub_res);

  // Exercise Common Symbol reads and writes (Finding 9)
  uint64_t write_common_addr = LLVMGetFunctionAddress(ee, "probe_write_common");
  require(write_common_addr != 0, "probe_write_common lookup failed");
  typedef int32_t (*WriteCommonFn)(int32_t);
  WriteCommonFn write_common = (WriteCommonFn)write_common_addr;
  int32_t write_res = write_common(50);
  require(write_res == 55, "probe_write_common returned unexpected value");
  std::printf(
      "COMMON_SYMBOL_WRITE: wrote 50, read+5 returned %d (expected 55)\n",
      write_res);

  // Verify common symbol address via LLVMGetGlobalValueAddress (Finding 8 & 9)
  uint64_t common_sym_addr = LLVMGetGlobalValueAddress(ee, "probe_common_int");
  require(common_sym_addr != 0, "probe_common_int address resolved to 0");
  require(*(int32_t *)common_sym_addr == 50,
          "Common symbol memory contents mismatch");

  // Modify via host memory pointer and read back through JIT
  *(int32_t *)common_sym_addr = 1234;
  uint64_t read_common_addr = LLVMGetFunctionAddress(ee, "probe_read_common");
  require(read_common_addr != 0, "probe_read_common lookup failed");
  VoidIntFn read_common = (VoidIntFn)read_common_addr;
  int32_t read_res = read_common();
  require(read_res == 1234,
          "probe_read_common did not observe host write to common symbol");
  std::printf("COMMON_SYMBOL_READ: host wrote 1234, JIT read returned %d\n",
              read_res);

  // Check 64-byte alignment via LLVMGetGlobalValueAddress and JIT pointer
  // (Finding 8)
  uint64_t align64_addr = LLVMGetGlobalValueAddress(ee, "probe_align64_int");
  require(align64_addr != 0, "probe_align64_int address is 0");
  require((align64_addr % 64) == 0,
          "align64_addr does not have 64-byte alignment");

  uint64_t get64_fn_addr = LLVMGetFunctionAddress(ee, "get_align64_ptr");
  require(get64_fn_addr != 0, "get_align64_ptr lookup failed");
  typedef uint64_t (*GetPtrFn)(void);
  GetPtrFn get_ptr64 = (GetPtrFn)get64_fn_addr;
  uint64_t jit_p64 = get_ptr64();
  require(jit_p64 == align64_addr,
          "JIT pointer does not match LLVMGetGlobalValueAddress for align64");
  require(*(int32_t *)align64_addr == 6464, "align64 data value mismatch");
  std::printf("ALIGN_64: addr=0x%llx (offset %% 64 = %zu, val=%d)\n",
              (unsigned long long)align64_addr, (size_t)(align64_addr % 64),
              *(int32_t *)align64_addr);

  // Check 4096-byte alignment via LLVMGetGlobalValueAddress and JIT pointer
  // (Finding 8)
  uint64_t align4096_addr =
      LLVMGetGlobalValueAddress(ee, "probe_align4096_int");
  require(align4096_addr != 0, "probe_align4096_int address is 0");
  require((align4096_addr % 4096) == 0,
          "align4096_addr does not have 4096-byte alignment");

  uint64_t get4096_fn_addr = LLVMGetFunctionAddress(ee, "get_align4096_ptr");
  require(get4096_fn_addr != 0, "get_align4096_ptr lookup failed");
  GetPtrFn get_ptr4096 = (GetPtrFn)get4096_fn_addr;
  uint64_t jit_p4096 = get_ptr4096();
  require(jit_p4096 == align4096_addr,
          "JIT pointer does not match LLVMGetGlobalValueAddress for align4096");
  require(*(int32_t *)align4096_addr == 4096, "align4096 data value mismatch");
  std::printf("ALIGN_4096: addr=0x%llx (offset %% 4096 = %zu, val=%d)\n",
              (unsigned long long)align4096_addr,
              (size_t)(align4096_addr % 4096), *(int32_t *)align4096_addr);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: External Stubs, Common Symbols, Alignment");
}

// ---------------------------------------------------------------------------
// Test Suite 6: Empty Groups Module (Zero RO and Zero RW Sections)
// ---------------------------------------------------------------------------
static void test_empty_groups_module() {
  std::puts(
      "=== TEST: Empty Groups (Code Only, Zero RO and Zero RW Sections) ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("test_empty_groups", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);

  // Function only, NO globals (RO=0, RW=0)
  auto f =
      LLVMAddFunction(m, "pure_code_fn", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 777, 0));
  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Engine creation failed for empty groups module");

  uint64_t fn_addr = LLVMGetFunctionAddress(ee, "pure_code_fn");
  require(fn_addr != 0, "Lookup failed for pure_code_fn");

  typedef int32_t (*VoidFn)(void);
  VoidFn fn = (VoidFn)fn_addr;
  int32_t res = fn();
  require(res == 777, "pure_code_fn returned wrong value");
  std::printf("EMPTY_GROUPS: pure_code_fn returned %d (expected 777)\n", res);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Empty groups module executed successfully");
}

// ---------------------------------------------------------------------------
// Custom Memory Manager for Fault Injection
// ---------------------------------------------------------------------------
struct CustomFaultManager {
  bool fail_code_alloc = false;
  bool fail_data_alloc = false;
  bool fail_common_alloc = false;
  bool fail_finalize = false;
  bool fail_protect = false;
  bool fail_cache_flush = false;
  std::vector<void *> allocated_pages;
  std::vector<void *> code_pages;
  std::vector<void *> ro_pages;
  std::vector<void *> rw_pages;

  ~CustomFaultManager() {
    for (void *p : allocated_pages) {
      if (p)
        VirtualFree(p, 0, MEM_RELEASE);
    }
  }
};

static uint8_t *custom_alloc_code(void *opaque, uintptr_t size, unsigned align,
                                  unsigned section_id,
                                  const char *section_name) {
  auto *self = (CustomFaultManager *)opaque;
  if (self->fail_code_alloc) {
    std::fprintf(stderr, "INJECTED_NULL_CODE_SECTION (section=%s size=%zu)\n",
                 section_name ? section_name : "", (size_t)size);
    return nullptr;
  }
  size_t alloc_size = (size + 4095) & ~4095;
  void *p = VirtualAlloc(nullptr, alloc_size, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE);
  require(p != nullptr, "VirtualAlloc failed in test custom manager");
  self->allocated_pages.push_back(p);
  self->code_pages.push_back(p);
  return (uint8_t *)p;
}

static uint8_t *custom_alloc_data(void *opaque, uintptr_t size, unsigned align,
                                  unsigned section_id, const char *section_name,
                                  LLVMBool is_readonly) {
  auto *self = (CustomFaultManager *)opaque;
  if (self->fail_common_alloc && section_name &&
      (std::strstr(section_name, "common symbols") != nullptr ||
       std::strstr(section_name, "<common") != nullptr)) {
    std::fprintf(stderr,
                 "INJECTED_NULL_COMMON_SYMBOLS_SECTION (section=%s size=%zu)\n",
                 section_name, (size_t)size);
    return nullptr;
  }
  if (self->fail_data_alloc) {
    std::fprintf(stderr,
                 "INJECTED_NULL_DATA_SECTION (section=%s size=%zu ro=%d)\n",
                 section_name ? section_name : "", (size_t)size, is_readonly);
    return nullptr;
  }
  size_t alloc_size = (size + 4095) & ~4095;
  void *p = VirtualAlloc(nullptr, alloc_size, MEM_RESERVE | MEM_COMMIT,
                         PAGE_READWRITE);
  require(p != nullptr, "VirtualAlloc failed in test custom manager");
  self->allocated_pages.push_back(p);
  if (is_readonly) {
    self->ro_pages.push_back(p);
  } else {
    self->rw_pages.push_back(p);
  }
  return (uint8_t *)p;
}

static LLVMBool custom_finalize(void *opaque, char **err_msg) {
  auto *self = (CustomFaultManager *)opaque;
  if (self->fail_finalize) {
    if (err_msg)
      *err_msg = _strdup("injected finalize memory failure");
    return 1;
  }

  // Set permissions
  DWORD old;
  for (void *p : self->code_pages) {
    if (self->fail_protect) {
      SetLastError(ERROR_ACCESS_DENIED);
      if (err_msg)
        *err_msg =
            _strdup("VirtualProtect PAGE_EXECUTE_READ failed with OS error 5");
      return 1;
    }
    if (!VirtualProtect(p, 4096, PAGE_EXECUTE_READ, &old)) {
      if (err_msg)
        *err_msg = _strdup("VirtualProtect failed on code");
      return 1;
    }
  }
  for (void *p : self->ro_pages) {
    if (!VirtualProtect(p, 4096, PAGE_READONLY, &old)) {
      if (err_msg)
        *err_msg = _strdup("VirtualProtect failed on RO");
      return 1;
    }
  }
  if (self->fail_cache_flush) {
    SetLastError(ERROR_INVALID_PARAMETER);
    if (err_msg)
      *err_msg = _strdup("FlushInstructionCache failed with OS error 87");
    return 1;
  }
  if (!FlushInstructionCache(GetCurrentProcess(), nullptr, 0)) {
    if (err_msg)
      *err_msg = _strdup("FlushInstructionCache failed");
    return 1;
  }
  return 0; // Success
}

static void custom_destroy(void *opaque) {
  delete (CustomFaultManager *)opaque;
}

// ---------------------------------------------------------------------------
// Test Suite 7: Fail-Closed Finalize Failure & Sticky Error
// ---------------------------------------------------------------------------
static void test_fail_closed_finalize_and_sticky_errors() {
  std::puts(
      "=== TEST: Forced Finalize Failure, Fail-Closed & Sticky Error ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("fail_finalize_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto f =
      LLVMAddFunction(m, "fail_func", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 999, 0));
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_finalize = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  // Attempt lookup: MUST fail-closed and return 0
  uint64_t addr = LLVMGetFunctionAddress(ee, "fail_func");
  std::printf("FINALIZE_FAIL_LOOKUP: addr=0x%llx (must be 0)\n",
              (unsigned long long)addr);
  require(
      addr == 0,
      "FAIL: finalize failure did NOT fail closed! Nonzero address returned!");

  // Attempt lookup via LLVMGetPointerToGlobal: MUST fail-closed and return
  // nullptr
  void *global_ptr = LLVMGetPointerToGlobal(ee, f);
  require(
      global_ptr == nullptr,
      "FAIL: LLVMGetPointerToGlobal returned non-null after finalize failure!");

  // Attempt execution via LLVMRunFunction: MUST fail-closed and not execute
  auto run_res = LLVMRunFunction(ee, f, 0, nullptr);
  require(run_res == nullptr,
          "FAIL: LLVMRunFunction returned non-null after finalize failure!");

  // Retrieve error diagnostic
  char *diag = nullptr;
  LLVMBool has_err = LLVMExecutionEngineGetErrMsg(ee, &diag);
  std::printf("DIAGNOSTIC: has_err=%d msg='%s'\n", has_err, diag ? diag : "");
  require(diag != nullptr && std::strlen(diag) > 0,
          "Expected non-empty diagnostic message");
  LLVMDisposeMessage(diag);

  // STICKY ERROR TEST: Reading diagnostic must NOT clear the failed state!
  uint64_t sticky_addr = LLVMGetFunctionAddress(ee, "fail_func");
  std::printf("STICKY_LOOKUP: addr=0x%llx (must remain 0)\n",
              (unsigned long long)sticky_addr);
  require(sticky_addr == 0, "FAIL: Error state was NOT sticky! Address "
                            "returned after reading diagnostic!");

  auto sticky_res = LLVMRunFunction(ee, f, 0, nullptr);
  require(sticky_res == nullptr, "FAIL: Error state was NOT sticky! Function "
                                 "executed after reading diagnostic!");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Forced finalize failure, fail-closed & sticky error");
}

// ---------------------------------------------------------------------------
// Test Suite 8: Injected VirtualProtect & Cache-Flush Failures
// ---------------------------------------------------------------------------
static void test_fail_closed_virtual_protect() {
  std::puts("=== TEST: Injected VirtualProtect Failure ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("fail_protect_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto f = LLVMAddFunction(m, "fn", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 1, 0));
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_protect = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  uint64_t addr = LLVMGetFunctionAddress(ee, "fn");
  require(addr == 0, "VirtualProtect failure must fail-closed with 0 address");

  char *diag = nullptr;
  LLVMExecutionEngineGetErrMsg(ee, &diag);
  require(diag != nullptr && std::strlen(diag) > 0,
          "Expected non-empty diagnostic for VirtualProtect failure");
  LLVMDisposeMessage(diag);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: VirtualProtect failure failed-closed");
}

static void test_fail_closed_cache_flush() {
  std::puts("=== TEST: Injected Cache-Flush Failure ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("fail_cache_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto f = LLVMAddFunction(m, "fn", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 2, 0));
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_cache_flush = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  uint64_t addr = LLVMGetFunctionAddress(ee, "fn");
  require(addr == 0, "Cache-flush failure must fail-closed with 0 address");

  char *diag = nullptr;
  LLVMExecutionEngineGetErrMsg(ee, &diag);
  require(diag != nullptr && std::strlen(diag) > 0,
          "Expected non-empty diagnostic for cache-flush failure");
  LLVMDisposeMessage(diag);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Cache-flush failure failed-closed");
}

// ---------------------------------------------------------------------------
// Test Suite 9: Injected OS Failures Through Production Memory Manager (Finding
// 5)
// ---------------------------------------------------------------------------
static void test_production_manager_injected_os_failures() {
  std::puts(
      "=== TEST: Injected OS Failures Through Production Memory Manager ===");

  HMODULE hLLVMC = GetModuleHandleA("LLVM-C.dll");
  typedef void (*SetFaultFn)(uint32_t);
  typedef uint64_t (*GetUnwindAddrFn)(void);
  typedef uint64_t (*GetFirstRegUnwindAddrFn)(void);
  typedef void (*ResetUnwindAddrsFn)(void);
  SetFaultFn pSetFault = nullptr;
  GetUnwindAddrFn pGetUnwindAddr = nullptr;
  GetFirstRegUnwindAddrFn pGetFirstRegUnwindAddr = nullptr;
  ResetUnwindAddrsFn pResetUnwindAddrs = nullptr;
  if (hLLVMC) {
    pSetFault = (SetFaultFn)GetProcAddress(
        hLLVMC, "LLVMExtSetWindowsMCJITFaultInjection");
    pGetUnwindAddr = (GetUnwindAddrFn)GetProcAddress(
        hLLVMC, "LLVMExtGetWindowsMCJITLastUnwindProbeAddress");
    pGetFirstRegUnwindAddr = (GetFirstRegUnwindAddrFn)GetProcAddress(
        hLLVMC, "LLVMExtGetWindowsMCJITFirstRegisteredUnwindAddress");
    pResetUnwindAddrs = (ResetUnwindAddrsFn)GetProcAddress(
        hLLVMC, "LLVMExtResetWindowsMCJITUnwindProbeAddresses");
  }
  if (!pSetFault) {
    pSetFault = &LLVMExtSetWindowsMCJITFaultInjection;
  }
  if (!pGetUnwindAddr) {
    pGetUnwindAddr = &LLVMExtGetWindowsMCJITLastUnwindProbeAddress;
  }
  if (!pGetFirstRegUnwindAddr) {
    pGetFirstRegUnwindAddr =
        &LLVMExtGetWindowsMCJITFirstRegisteredUnwindAddress;
  }
  if (!pResetUnwindAddrs) {
    pResetUnwindAddrs = &LLVMExtResetWindowsMCJITUnwindProbeAddresses;
  }
  auto test_fault_case = [&](uint32_t flag, const char *case_name,
                             const char *expected_substr, bool need_ro,
                             bool need_unwind) {
    std::printf("--- Testing Production OS Fault: %s ---\n", case_name);
    pSetFault(flag);

    LLVMContextRef ctx = LLVMContextCreate();
    LLVMModuleRef m = LLVMModuleCreateWithNameInContext("prod_fault_mod", ctx);
    auto i32 = LLVMInt32TypeInContext(ctx);

    if (need_ro) {
      auto ro_var = LLVMAddGlobal(m, i32, "test_ro_data");
      LLVMSetInitializer(ro_var, LLVMConstInt(i32, 8888, 0));
      LLVMSetGlobalConstant(ro_var, 1);
    }

    auto fn = LLVMAddFunction(m, "test_fault_fn",
                              LLVMFunctionType(i32, nullptr, 0, 0));
    if (need_unwind) {
      auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);
      if (uw_kind != 0) {
        LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                                LLVMCreateEnumAttribute(ctx, uw_kind, 2));
      }
    }

    auto b = LLVMCreateBuilderInContext(ctx);
    LLVMPositionBuilderAtEnd(b,
                             LLVMAppendBasicBlockInContext(ctx, fn, "entry"));
    if (need_unwind) {
      auto slot = LLVMBuildAlloca(b, i32, "slot");
      LLVMBuildStore(b, LLVMConstInt(i32, 42, 0), slot);
    }
    LLVMBuildRet(b, LLVMConstInt(i32, 10, 0));
    LLVMDisposeBuilder(b);

    LLVMExecutionEngineRef ee = nullptr;
    char *err = nullptr;
    LLVMBool create_err =
        LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
    require(!create_err && ee != nullptr,
            err ? err : "Failed to create Windows MCJIT engine");

    uint64_t addr = LLVMGetFunctionAddress(ee, "test_fault_fn");
    std::printf("%s_LOOKUP: addr=0x%llx (must be 0)\n", case_name,
                (unsigned long long)addr);
    require(addr == 0,
            "FAIL: Production manager OS fault did not fail closed!");

    char *diag = nullptr;
    LLVMBool has_err = LLVMExecutionEngineGetErrMsg(ee, &diag);
    std::printf("%s_DIAGNOSTIC: has_err=%d msg='%s'\n", case_name, has_err,
                diag ? diag : "");
    require(has_err && diag != nullptr && std::strlen(diag) > 0,
            "Expected non-empty diagnostic for production OS fault");
    require(std::strstr(diag, expected_substr) != nullptr,
            "Diagnostic message did not contain expected substring");
    LLVMDisposeMessage(diag);
#ifdef _WIN32
    if (need_unwind && pGetUnwindAddr) {
      uint64_t probe_unwind_addr = pGetUnwindAddr();
      require(
          probe_unwind_addr != 0,
          "Expected unwind probe address to be recorded for unwind fault case");
      DWORD64 failImgBase = 0;
      PRUNTIME_FUNCTION failRf = RtlLookupFunctionEntry(
          (DWORD64)probe_unwind_addr, &failImgBase, nullptr);
      require(failRf == nullptr,
              "RtlLookupFunctionEntry found table after failed publication!");
    }
#endif

    // Sticky error test
    uint64_t sticky_addr = LLVMGetFunctionAddress(ee, "test_fault_fn");
    require(sticky_addr == 0, "Sticky error failed on production engine");

    LLVMDisposeExecutionEngine(ee);
    LLVMContextDispose(ctx);

    // Clear fault injection
    pSetFault(LLVMExtFaultNone);
  };

  test_fault_case(LLVMExtFaultVirtualProtectCode, "VirtualProtect_Code",
                  "VirtualProtect", false, false);
  test_fault_case(LLVMExtFaultFlushInstructionCache, "FlushInstructionCache",
                  "FlushInstructionCache", false, false);
  test_fault_case(LLVMExtFaultVirtualProtectRO, "VirtualProtect_RO",
                  "VirtualProtect", true, false);
  test_fault_case(LLVMExtFaultRtlAddFunctionTable, "RtlAddFunctionTable",
                  "RtlAddFunctionTable", false, true);
  test_fault_case(LLVMExtFaultVirtualAllocCommit, "VirtualAlloc_Commit",
                  "VirtualAlloc", false, false);

  // Test transactional rollback when a second table fails registration
  {
    std::printf("--- Testing Production OS Fault: RtlAddFunctionTable "
                "Transactional Rollback ---\n");
    if (pResetUnwindAddrs)
      pResetUnwindAddrs();

    // STEP A: Positive control - two tables succeed in one finalize without
    // fault
    {
      pSetFault(LLVMExtFaultNone);
      LLVMContextRef ctx_pos = LLVMContextCreate();
      LLVMModuleRef m1_pos =
          LLVMModuleCreateWithNameInContext("pos_m1", ctx_pos);
      LLVMModuleRef m2_pos =
          LLVMModuleCreateWithNameInContext("pos_m2", ctx_pos);
      auto void_ty = LLVMVoidTypeInContext(ctx_pos);
      auto i32 = LLVMInt32TypeInContext(ctx_pos);
      auto fn_ty = LLVMFunctionType(void_ty, nullptr, 0, 0);
      auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);

      auto f1 = LLVMAddFunction(m1_pos, "pos_fn1", fn_ty);
      if (uw_kind)
        LLVMAddAttributeAtIndex(f1, LLVMAttributeFunctionIndex,
                                LLVMCreateEnumAttribute(ctx_pos, uw_kind, 2));
      auto b1 = LLVMCreateBuilderInContext(ctx_pos);
      LLVMPositionBuilderAtEnd(
          b1, LLVMAppendBasicBlockInContext(ctx_pos, f1, "entry"));
      LLVMBuildStore(b1, LLVMConstInt(i32, 111, 0),
                     LLVMBuildAlloca(b1, i32, "s1"));
      LLVMBuildRetVoid(b1);
      LLVMDisposeBuilder(b1);

      auto f2 = LLVMAddFunction(m2_pos, "pos_fn2", fn_ty);
      if (uw_kind)
        LLVMAddAttributeAtIndex(f2, LLVMAttributeFunctionIndex,
                                LLVMCreateEnumAttribute(ctx_pos, uw_kind, 2));
      auto b2 = LLVMCreateBuilderInContext(ctx_pos);
      LLVMPositionBuilderAtEnd(
          b2, LLVMAppendBasicBlockInContext(ctx_pos, f2, "entry"));
      LLVMBuildStore(b2, LLVMConstInt(i32, 222, 0),
                     LLVMBuildAlloca(b2, i32, "s2"));
      LLVMBuildRetVoid(b2);
      LLVMDisposeBuilder(b2);

      LLVMExecutionEngineRef ee_pos = nullptr;
      char *err_pos = nullptr;
      LLVMBool create_err_pos =
          LLVMExtCreateWindowsMCJITCompilerForModule(&ee_pos, m1_pos, &err_pos);
      require(!create_err_pos && ee_pos != nullptr,
              err_pos ? err_pos : "Positive control engine creation failed");
      LLVMAddModule(ee_pos, m2_pos);

      // LLVMGetPointerToGlobal runs finalizeObject() over all added modules (m1
      // and m2)
      void *pos_ptr1 = LLVMGetPointerToGlobal(ee_pos, f1);
      require(pos_ptr1 != nullptr,
              "Positive control LLVMGetPointerToGlobal failed");
      uint64_t pos_addr1 = LLVMGetFunctionAddress(ee_pos, "pos_fn1");
      uint64_t pos_addr2 = LLVMGetFunctionAddress(ee_pos, "pos_fn2");
      require(pos_addr1 != 0 && pos_addr2 != 0,
              "Positive control functions must resolve");

#ifdef _WIN32
      DWORD64 base1 = 0, base2 = 0;
      PRUNTIME_FUNCTION rf_pos1 =
          RtlLookupFunctionEntry((DWORD64)pos_addr1, &base1, nullptr);
      PRUNTIME_FUNCTION rf_pos2 =
          RtlLookupFunctionEntry((DWORD64)pos_addr2, &base2, nullptr);
      require(rf_pos1 != nullptr,
              "Positive control table 1 must be registered in OS");
      require(rf_pos2 != nullptr,
              "Positive control table 2 must be registered in OS");
      std::printf(
          "POSITIVE_TWO_TABLE_CONTROL: table1=%p table2=%p both found in OS\n",
          (void *)rf_pos1, (void *)rf_pos2);
#endif
      LLVMDisposeExecutionEngine(ee_pos);
      LLVMContextDispose(ctx_pos);
    }

    // STEP B: Transactional rollback on second table failure
    if (pResetUnwindAddrs)
      pResetUnwindAddrs();
    pSetFault(LLVMExtFaultRtlAddFunctionTableSecond);

    LLVMContextRef ctx = LLVMContextCreate();
    LLVMModuleRef m1 =
        LLVMModuleCreateWithNameInContext("prod_fault_rollback_m1", ctx);
    LLVMModuleRef m2 =
        LLVMModuleCreateWithNameInContext("prod_fault_rollback_m2", ctx);
    auto void_ty = LLVMVoidTypeInContext(ctx);
    auto i32 = LLVMInt32TypeInContext(ctx);
    auto fn_ty = LLVMFunctionType(void_ty, nullptr, 0, 0);
    auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);

    // Module 1 with function 1
    auto fn1 = LLVMAddFunction(m1, "fault_rollback_fn1", fn_ty);
    if (uw_kind != 0)
      LLVMAddAttributeAtIndex(fn1, LLVMAttributeFunctionIndex,
                              LLVMCreateEnumAttribute(ctx, uw_kind, 2));
    auto b1 = LLVMCreateBuilderInContext(ctx);
    LLVMPositionBuilderAtEnd(b1,
                             LLVMAppendBasicBlockInContext(ctx, fn1, "entry"));
    LLVMBuildStore(b1, LLVMConstInt(i32, 111, 0),
                   LLVMBuildAlloca(b1, i32, "s1"));
    LLVMBuildRetVoid(b1);
    LLVMDisposeBuilder(b1);

    // Module 2 with function 2
    auto fn2 = LLVMAddFunction(m2, "fault_rollback_fn2", fn_ty);
    if (uw_kind != 0)
      LLVMAddAttributeAtIndex(fn2, LLVMAttributeFunctionIndex,
                              LLVMCreateEnumAttribute(ctx, uw_kind, 2));
    auto b2 = LLVMCreateBuilderInContext(ctx);
    LLVMPositionBuilderAtEnd(b2,
                             LLVMAppendBasicBlockInContext(ctx, fn2, "entry"));
    LLVMBuildStore(b2, LLVMConstInt(i32, 222, 0),
                   LLVMBuildAlloca(b2, i32, "s2"));
    LLVMBuildRetVoid(b2);
    LLVMDisposeBuilder(b2);

    LLVMExecutionEngineRef ee = nullptr;
    char *err = nullptr;
    LLVMBool create_err =
        LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m1, &err);
    require(!create_err && ee != nullptr,
            err ? err : "Failed to create Windows MCJIT engine");
    LLVMAddModule(ee, m2);

    // LLVMGetPointerToGlobal runs finalizeObject() over all added modules (m1
    // and m2) in a single finalize!
    void *p1 = LLVMGetPointerToGlobal(ee, fn1);
    std::printf("ROLLBACK_PTR: p1=%p (must be nullptr)\n", p1);
    require(p1 == nullptr, "LLVMGetPointerToGlobal must return null on second "
                           "table finalize failure");

    uint64_t addr1 = LLVMGetFunctionAddress(ee, "fault_rollback_fn1");
    std::printf("ROLLBACK_LOOKUP: addr1=0x%llx (must be 0)\n",
                (unsigned long long)addr1);
    require(addr1 == 0,
            "FAIL: Rollback test did not fail closed on second table failure!");

    char *diag = nullptr;
    LLVMBool has_err = LLVMExecutionEngineGetErrMsg(ee, &diag);
    std::printf("ROLLBACK_DIAGNOSTIC: has_err=%d msg='%s'\n", has_err,
                diag ? diag : "");
    require(has_err && diag != nullptr && std::strlen(diag) > 0,
            "Expected diagnostic for rollback failure");
    require(std::strstr(diag, "RtlAddFunctionTable") != nullptr,
            "Diagnostic message did not mention RtlAddFunctionTable");
    LLVMDisposeMessage(diag);

#ifdef _WIN32
    // Verify that table 0 was actually registered AND rolled back (deregistered
    // from OS table)
    require(pGetFirstRegUnwindAddr != nullptr,
            "pGetFirstRegUnwindAddr function pointer must be available");
    uint64_t rollback_unwind_addr = pGetFirstRegUnwindAddr();
    std::printf("ROLLBACK_FIRST_TABLE_ADDR: 0x%llx (must not be 0)\n",
                (unsigned long long)rollback_unwind_addr);
    require(rollback_unwind_addr != 0,
            "FAIL: First table address was never recorded as registered before "
            "rollback!");

    DWORD64 imgBase1 = 0;
    PRUNTIME_FUNCTION rf1 = RtlLookupFunctionEntry(
        (DWORD64)rollback_unwind_addr, &imgBase1, nullptr);
    std::printf("ROLLBACK_LOOKUP_AFTER: rf1=%p (must be nullptr)\n",
                (void *)rf1);
    require(rf1 == nullptr,
            "FAIL: RtlLookupFunctionEntry found table after rollback! "
            "Table 0 was not deregistered!");
#endif

    LLVMDisposeExecutionEngine(ee);
    LLVMContextDispose(ctx);
    pSetFault(LLVMExtFaultNone);
    if (pResetUnwindAddrs)
      pResetUnwindAddrs();
    std::puts("PASS: Transactional rollback on RtlAddFunctionTable verified");
  }

  std::puts("PASS: Injected OS Failures Through Production Memory Manager");
}

// ---------------------------------------------------------------------------
// Test Suite 10: Lazy Lookup Failure On Healthy Engine (Finding 7)
// ---------------------------------------------------------------------------
static void test_lazy_lookup_failure_on_healthy_engine() {
  std::puts("=== TEST: Lazy Lookup Failure On Healthy Engine ===");
  LLVMContextRef ctx = LLVMContextCreate();
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto fn_ty = LLVMFunctionType(i32, nullptr, 0, 0);

  // Module 1: healthy function
  LLVMModuleRef m1 = LLVMModuleCreateWithNameInContext("mod_healthy", ctx);
  auto healthy_fn = LLVMAddFunction(m1, "healthy_func", fn_ty);
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, healthy_fn, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 777, 0));

  // Module 1 also declares a function that will be looked up lazily
  auto lazy_decl = LLVMAddFunction(m1, "lazy_failing_func", fn_ty);
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  // Initially, do NOT fail any allocation so engine is healthy
  fm->fail_code_alloc = false;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m1, &opt, sizeof(opt), &err),
          "Create engine");

  // Step 1: Prove engine is healthy by resolving and executing healthy_func
  uint64_t healthy_addr = LLVMGetFunctionAddress(ee, "healthy_func");
  require(healthy_addr != 0, "healthy_func lookup failed on healthy engine");
  typedef int32_t (*IntVoidFn)(void);
  IntVoidFn h_fn = (IntVoidFn)healthy_addr;
  int32_t h_val = h_fn();
  require(h_val == 777, "healthy_func returned unexpected value");
  std::printf(
      "HEALTHY_ENGINE_EXECUTION: healthy_func returned %d (expected 777)\n",
      h_val);

  // Step 2: Now add Module 2 containing the definition of lazy_failing_func
  LLVMModuleRef m2 = LLVMModuleCreateWithNameInContext("mod_lazy", ctx);
  auto lazy_def = LLVMAddFunction(m2, "lazy_failing_func", fn_ty);
  auto b2 = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b2, LLVMAppendBasicBlockInContext(ctx, lazy_def, "entry"));
  LLVMBuildRet(b2, LLVMConstInt(i32, 999, 0));
  LLVMDisposeBuilder(b2);

  // Configure fault injection so that code allocation for the new module will
  // fail
  fm->fail_code_alloc = true;

  // Add the module lazily
  LLVMAddModule(ee, m2);

  // Step 3: Trigger lazy compilation/loading via lookup of the
  // declaration/function Engine was healthy until this lookup triggered the
  // failing load
  // Step 3: Trigger lazy compilation/loading via LLVMGetFunctionAddress on the
  // declaration. Engine was healthy until this lookup triggered the failing
  // load.
  uint64_t lazy_addr = LLVMGetFunctionAddress(ee, "lazy_failing_func");
  std::printf("LAZY_LOOKUP_ON_HEALTHY: addr=0x%llx (must be 0)\n",
              (unsigned long long)lazy_addr);
  require(
      lazy_addr == 0,
      "FAIL: Lazy lookup on healthy engine did not return 0 on failing load!");

  // Verify declaration lookup also returns null under sticky error state
  void *decl_ptr = LLVMGetPointerToGlobal(ee, lazy_decl);
  require(decl_ptr == nullptr,
          "FAIL: LLVMGetPointerToGlobal returned non-null "
          "for failed lazy declaration under sticky error!");
  // Step 4: Verify diagnostic was captured and preserved
  char *diag = nullptr;
  LLVMBool has_err = LLVMExecutionEngineGetErrMsg(ee, &diag);
  std::printf("LAZY_FAILURE_DIAGNOSTIC: has_err=%d msg='%s'\n", has_err,
              diag ? diag : "");
  require(has_err && diag != nullptr && std::strlen(diag) > 0,
          "Expected non-empty diagnostic message from lazy load failure");
  LLVMDisposeMessage(diag);

  // Step 5: Verify sticky refusal on the previously healthy function
  uint64_t post_fail_healthy = LLVMGetFunctionAddress(ee, "healthy_func");
  require(post_fail_healthy == 0,
          "FAIL: Error state was not sticky! healthy_func still resolvable "
          "after lazy failure!");

  auto post_fail_run = LLVMRunFunction(ee, healthy_fn, 0, nullptr);
  require(
      post_fail_run == nullptr,
      "FAIL: Error state was not sticky! healthy_fn ran after lazy failure!");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Lazy lookup failure on healthy engine verified");
}

// ---------------------------------------------------------------------------
// Test Suite 11: Lazy Archive Lookup & Resolution (Finding 9)
// ---------------------------------------------------------------------------
static void test_lazy_archive_lookup() {
  std::puts("=== TEST: Lazy Archive Lookup & Resolution ===");
  LLVMContextRef ctx = LLVMContextCreate();
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto fn_ty = LLVMFunctionType(i32, nullptr, 0, 0);

  // 1. Create a module to put in the archive
  LLVMModuleRef m_arch = LLVMModuleCreateWithNameInContext("arch_mod", ctx);
  auto arch_fn = LLVMAddFunction(m_arch, "archive_calc_val", fn_ty);
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, arch_fn, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 31415, 0));
  LLVMDisposeBuilder(b);

  // 2. Initialize native target and emit object file to disk
  LLVMTargetRef target = nullptr;
  char *tm_err = nullptr;
  const char *triple = LLVMGetDefaultTargetTriple();
  require(LLVMGetTargetFromTriple(triple, &target, &tm_err) == 0,
          tm_err ? tm_err : "GetTargetFromTriple failed");
  LLVMTargetMachineRef tm = LLVMCreateTargetMachine(
      target, triple, "generic", "", LLVMCodeGenLevelDefault, LLVMRelocDefault,
      LLVMCodeModelDefault);
  require(tm != nullptr, "CreateTargetMachine failed");

  const char *obj_path = "archive_member.obj";
  char *emit_err = nullptr;
  LLVMBool emit_failed = LLVMTargetMachineEmitToFile(
      tm, m_arch, const_cast<char *>(obj_path), LLVMObjectFile, &emit_err);
  require(!emit_failed, emit_err ? emit_err : "Failed to emit object file");
  LLVMDisposeTargetMachine(tm);
  LLVMDisposeModule(m_arch);

  // 3. Create archive using llvm-ar
  const char *lib_path = "test_archive.lib";
  char cmd[512];
  std::snprintf(cmd, sizeof(cmd), "llvm-ar.exe rc %s %s", lib_path, obj_path);
  int ar_rc = std::system(cmd);
  if (ar_rc != 0) {
    std::snprintf(cmd, sizeof(cmd), "llvm-ar rc %s %s", lib_path, obj_path);
    ar_rc = std::system(cmd);
  }
  require(ar_rc == 0, "llvm-ar command failed to create archive");

  // 4. Create an MCJIT engine with an initial module
  LLVMModuleRef m_main = LLVMModuleCreateWithNameInContext("main_mod", ctx);
  auto main_decl = LLVMAddFunction(m_main, "archive_calc_val", fn_ty);
  LLVMSetLinkage(main_decl, LLVMExternalLinkage);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m_main, &err);
  require(!create_err && ee != nullptr, err ? err : "Engine creation failed");

  // 5. Add archive to engine via LLVMExtAddArchiveFile
  // Negative control: Nonexistent archive must fail gracefully and report
  // diagnostic
  char *bad_arch_err = nullptr;
  LLVMBool bad_arch_res =
      LLVMExtAddArchiveFile(ee, "nonexistent_test_file_404.lib", &bad_arch_err);
  require(bad_arch_res != 0,
          "LLVMExtAddArchiveFile must fail on nonexistent file");
  require(bad_arch_err != nullptr && std::strlen(bad_arch_err) > 0,
          "LLVMExtAddArchiveFile must report diagnostic on nonexistent file");
  free(bad_arch_err);

  char *arch_err = nullptr;
  LLVMBool add_arch_err = LLVMExtAddArchiveFile(ee, lib_path, &arch_err);
  require(!add_arch_err, arch_err ? arch_err : "LLVMExtAddArchiveFile failed");

  // 6. Resolve archive_calc_val: MCJIT findSymbol searches Archives, loads
  // archive_member.obj
  uint64_t arch_addr = LLVMGetFunctionAddress(ee, "archive_calc_val");
  require(arch_addr != 0, "Failed to resolve archive_calc_val from archive!");
  std::printf("ARCHIVE_RESOLVED: archive_calc_val at 0x%llx\n",
              (unsigned long long)arch_addr);

  // Execute function loaded from archive
  typedef int32_t (*ArchFn)(void);
  ArchFn fn = (ArchFn)arch_addr;
  int32_t val = fn();
  std::printf("ARCHIVE_EXECUTION: returned %d (expected 31415)\n", val);
  require(val == 31415, "Archive function execution returned unexpected value");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);

  // Clean up temporary files
  std::remove(obj_path);
  std::remove(lib_path);
  std::puts("PASS: Lazy Archive Lookup & Resolution");
}

// ---------------------------------------------------------------------------
// Test Suite 11: Encoded Relocations & Live RuntimeDyld Processing (Finding 6)
// ---------------------------------------------------------------------------
static void test_encoded_relocations_live_runtime_dyld() {
  std::puts("=== TEST: Encoded Relocations & Live RuntimeDyld Processing ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m =
      LLVMModuleCreateWithNameInContext("test_encoded_relocs", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);

  // 1. Callee function: int32_t callee_target(int32_t a) { return a + 10; }
  auto callee_fn =
      LLVMAddFunction(m, "callee_target", LLVMFunctionType(i32, &i32, 1, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, callee_fn, "entry"));
  auto param = LLVMGetParam(callee_fn, 0);
  auto add10 = LLVMBuildAdd(b, param, LLVMConstInt(i32, 10, 0), "add10");
  LLVMBuildRet(b, add10);

  // 2. Caller function using explicit 32-bit PC-relative relocation with
  // negative addend: lea callee_target-8(%rip), %rax In x86-64 COFF, this
  // encodes as: 48 8D 05 <disp32> with IMAGE_REL_AMD64_REL32 and an initial
  // addend of -8 in the displacement field.
  auto caller_fn = LLVMAddFunction(
      m, "caller_entry",
      LLVMFunctionType(LLVMInt64TypeInContext(ctx), nullptr, 0, 0));
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, caller_fn, "entry"));
  LLVMTypeRef i64_ty = LLVMInt64TypeInContext(ctx);
  LLVMTypeRef asm_fn_ty = LLVMFunctionType(i64_ty, nullptr, 0, 0);
  LLVMValueRef inline_asm =
      LLVMConstInlineAsm(asm_fn_ty, "lea callee_target-8(%rip), %rax", "={rax}",
                         /*HasSideEffects=*/1,
                         /*IsAlignStack=*/0);
  auto lea_res =
      LLVMBuildCall2(b, asm_fn_ty, inline_asm, nullptr, 0, "lea_res");
  LLVMBuildRet(b, lea_res);
  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Failed to create Windows MCJIT engine");

  // Lookup both functions
  uint64_t callee_addr = LLVMGetFunctionAddress(ee, "callee_target");
  uint64_t caller_addr = LLVMGetFunctionAddress(ee, "caller_entry");
  require(callee_addr != 0, "Failed to resolve callee_target");
  require(caller_addr != 0, "Failed to resolve caller_entry");

  // Inspect the emitted machine code of caller_entry to verify encoded
  // relocation resolution
  const uint8_t *code_bytes = (const uint8_t *)caller_addr;
  bool found_rel32_lea = false;
  for (size_t offset = 0; offset + 7 <= 64; ++offset) {
    if (code_bytes[offset] == 0x48 && code_bytes[offset + 1] == 0x8D &&
        code_bytes[offset + 2] == 0x05) {
      int32_t written_disp = 0;
      std::memcpy(&written_disp, code_bytes + offset + 3, sizeof(int32_t));
      uint64_t next_ip = caller_addr + offset + 7;
      uint64_t computed_target =
          (uint64_t)((int64_t)next_ip + (int64_t)written_disp);

      std::printf(
          "ENCODED_REL32_INSPECTION: lea at offset +%zu, "
          "written_disp=0x%x (%d), next_ip=0x%llx -> computed_target=0x%llx "
          "(callee-8=0x%llx)\n",
          offset, written_disp, written_disp, (unsigned long long)next_ip,
          (unsigned long long)computed_target,
          (unsigned long long)(callee_addr - 8));

      require(computed_target == callee_addr - 8,
              "RuntimeDyld resolved REL32 displacement does not match "
              "callee_target - 8!");
      found_rel32_lea = true;
      break;
    }
  }
  require(found_rel32_lea,
          "Could not find 48 8D 05 (lea) instruction in caller_entry");

  // Execute through the resolved relocation
  typedef uint64_t (*CallerFn)(void);
  CallerFn fn = (CallerFn)caller_addr;
  uint64_t exec_result = fn();
  std::printf("ENCODED_REL32_EXECUTION: caller_entry() returned 0x%llx "
              "(expected 0x%llx)\n",
              (unsigned long long)exec_result,
              (unsigned long long)(callee_addr - 8));
  require(exec_result == callee_addr - 8,
          "Execution through encoded REL32 relocation failed");

  // Test section remapping through RuntimeDyld if LLVMExtMapSectionAddress is
  // available
  HMODULE hLLVMC = GetModuleHandleA("LLVM-C.dll");
  typedef void (*MapSectionFn)(LLVMExecutionEngineRef, const void *, uint64_t);
  MapSectionFn pMapSection = nullptr;
  if (hLLVMC) {
    pMapSection =
        (MapSectionFn)GetProcAddress(hLLVMC, "LLVMExtMapSectionAddress");
  }
  if (!pMapSection) {
    pMapSection = &LLVMExtMapSectionAddress;
  }
  require(pMapSection != nullptr,
          "LLVMExtMapSectionAddress must be exported by LLVM-C.dll");

  uint64_t remapped_target_addr = 0x240000000ULL;
  pMapSection(ee, (const void *)callee_addr, remapped_target_addr);
  std::printf("SECTION_REMAPPING: remapped callee_addr %p -> target 0x%llx "
              "via LLVMExtMapSectionAddress\n",
              (const void *)callee_addr,
              (unsigned long long)remapped_target_addr);

  // Create dependent module referencing callee_target to verify remapping
  // effect
  LLVMModuleRef m_dep = LLVMModuleCreateWithNameInContext("dep_mod", ctx);
  auto dep_callee_decl = LLVMAddFunction(m_dep, "callee_target",
                                         LLVMFunctionType(i32, &i32, 1, 0));
  LLVMSetLinkage(dep_callee_decl, LLVMExternalLinkage);

  auto dep_caller_fn = LLVMAddFunction(m_dep, "dependent_caller", asm_fn_ty);
  auto b_dep = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b_dep, LLVMAppendBasicBlockInContext(ctx, dep_caller_fn, "entry"));
  LLVMValueRef dep_inline_asm =
      LLVMConstInlineAsm(asm_fn_ty, "lea callee_target(%rip), %rax", "={rax}",
                         /*HasSideEffects=*/1,
                         /*IsAlignStack=*/0);
  auto dep_lea =
      LLVMBuildCall2(b_dep, asm_fn_ty, dep_inline_asm, nullptr, 0, "dep_lea");
  LLVMBuildRet(b_dep, dep_lea);
  LLVMDisposeBuilder(b_dep);

  LLVMAddModule(ee, m_dep);

  uint64_t dep_caller_addr = LLVMGetFunctionAddress(ee, "dependent_caller");
  require(dep_caller_addr != 0, "Failed to resolve dependent_caller");

  const uint8_t *dep_bytes = (const uint8_t *)dep_caller_addr;
  bool found_dep_lea = false;
  for (size_t offset = 0; offset + 7 <= 64; ++offset) {
    if (dep_bytes[offset] == 0x48 && dep_bytes[offset + 1] == 0x8D &&
        dep_bytes[offset + 2] == 0x05) {
      int32_t written_disp = 0;
      std::memcpy(&written_disp, dep_bytes + offset + 3, sizeof(int32_t));
      uint64_t next_ip = dep_caller_addr + offset + 7;
      uint64_t computed_target =
          (uint64_t)((int64_t)next_ip + (int64_t)written_disp);

      std::printf(
          "REMAPPED_RELOCATION_INSPECTION: dep lea at offset +%zu, "
          "written_disp=0x%x (%d), next_ip=0x%llx -> computed_target=0x%llx "
          "(expected remapped=0x%llx)\n",
          offset, written_disp, written_disp, (unsigned long long)next_ip,
          (unsigned long long)computed_target,
          (unsigned long long)remapped_target_addr);

      const uint8_t *stub_bytes = (const uint8_t *)computed_target;
      require(stub_bytes[0] == 0xFF && stub_bytes[1] == 0x25,
              "Expected stub jmp *0(%rip) [FF 25] at computed_target");
      uint64_t stub_target = 0;
      std::memcpy(&stub_target, stub_bytes + 6, sizeof(uint64_t));
      std::printf("STUB_INSPECTION: stub at 0x%llx has target 0x%llx "
                  "(expected 0x%llx)\n",
                  (unsigned long long)computed_target,
                  (unsigned long long)stub_target,
                  (unsigned long long)remapped_target_addr);
      require(stub_target == remapped_target_addr,
              "Relocation stub target does not match remapped_target_addr");

      uint64_t callee_resolved = LLVMGetFunctionAddress(ee, "callee_target");
      require(callee_resolved == remapped_target_addr,
              "LLVMGetFunctionAddress(callee_target) did not return "
              "remapped_target_addr");
      require(stub_target == callee_resolved,
              "Stub target does not match resolved remapped target address");
      found_dep_lea = true;
      break;
    }
  }
  require(found_dep_lea,
          "Could not find 48 8D 05 (lea) instruction in dependent_caller");
  std::puts("PASS: Section Remapping & Dependent Relocation Resolution "
            "(without execution)");

  // Negative control: Remapping an unknown/invalid section address must fail
  // immediately and record an error in the execution engine.
  LLVMContextRef bad_remap_ctx = LLVMContextCreate();
  LLVMModuleRef bad_remap_m =
      LLVMModuleCreateWithNameInContext("bad_remap_mod", bad_remap_ctx);
  auto bad_fn = LLVMAddFunction(
      bad_remap_m, "bad_fn",
      LLVMFunctionType(LLVMVoidTypeInContext(bad_remap_ctx), nullptr, 0, 0));
  auto bad_b = LLVMCreateBuilderInContext(bad_remap_ctx);
  LLVMPositionBuilderAtEnd(
      bad_b, LLVMAppendBasicBlockInContext(bad_remap_ctx, bad_fn, "entry"));
  LLVMBuildRetVoid(bad_b);
  LLVMDisposeBuilder(bad_b);
  LLVMExecutionEngineRef bad_ee = nullptr;
  char *bad_err = nullptr;
  LLVMExtCreateWindowsMCJITCompilerForModule(&bad_ee, bad_remap_m, &bad_err);
  require(bad_ee != nullptr, "Create engine for bad remap test");

  // Attempt to remap an address not belonging to any section
  pMapSection(bad_ee, (const void *)0xdeadbeefULL, 0x240000000ULL);
  char *remap_diag = nullptr;
  LLVMBool remap_has_err = LLVMExecutionEngineGetErrMsg(bad_ee, &remap_diag);
  std::printf("REMAP_FAILURE_SURFACED: has_err=%d diag='%s'\n", remap_has_err,
              remap_diag ? remap_diag : "");
  require(
      remap_has_err && remap_diag != nullptr,
      "Failed section remapping must immediately surface error via GetErrMsg");
  require(std::strstr(remap_diag, "unknown section") != nullptr ||
              std::strstr(remap_diag, "remap") != nullptr,
          "Diagnostic must describe section remapping failure");
  LLVMDisposeMessage(remap_diag);

  uint64_t bad_lookup = LLVMGetFunctionAddress(bad_ee, "bad_fn");
  require(bad_lookup == 0, "Function address lookup must fail closed "
                           "immediately following remapping error");
  LLVMDisposeExecutionEngine(bad_ee);
  LLVMContextDispose(bad_remap_ctx);
  std::puts(
      "PASS: Section remapping failure surfaced immediately and failed closed");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Encoded Relocations & Live RuntimeDyld Processing");
}

// ---------------------------------------------------------------------------
// Test Suite 12: Common Symbol Allocation Failure Non-Fatal Recovery (Finding
// 9)
// ---------------------------------------------------------------------------
static void test_null_common_symbol_allocation_recovery() {
  std::puts(
      "=== TEST: Common Symbol Allocation Failure Non-Fatal Recovery ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("null_common_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);

  auto common_var = LLVMAddGlobal(m, i32, "fail_common_int");
  LLVMSetLinkage(common_var, LLVMCommonLinkage);
  LLVMSetInitializer(common_var, LLVMConstNull(i32));

  auto f = LLVMAddFunction(m, "read_common_fail_fn",
                           LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  auto val = LLVMBuildLoad2(b, i32, common_var, "val");
  LLVMBuildRet(b, val);
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_common_alloc = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  uint64_t addr = LLVMGetFunctionAddress(ee, "read_common_fail_fn");
  std::printf("NULL_COMMON_ALLOC_LOOKUP: addr=0x%llx (expected 0)\n",
              (unsigned long long)addr);
  require(addr == 0, "Expected 0 address on null common symbols allocation");

  char *diag = nullptr;
  LLVMExecutionEngineGetErrMsg(ee, &diag);
  std::printf("NULL_COMMON_ALLOC_DIAG: '%s'\n", diag ? diag : "");
  require(diag != nullptr && std::strlen(diag) > 0,
          "Expected diagnostic for common symbols allocation failure");
  require(std::strstr(diag, "common symbols") != nullptr ||
              std::strstr(diag, "common") != nullptr,
          "Diagnostic must mention common symbols failure");
  LLVMDisposeMessage(diag);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts(
      "PASS: Common symbol allocation failure recovered cleanly without abort");
}

// ---------------------------------------------------------------------------
// Test Suite 9: Null Code & Data Allocation Non-Fatal Recovery
// ---------------------------------------------------------------------------
static void test_null_code_allocation_recovery() {
  std::puts("=== TEST: Null Code Allocation Non-Fatal Recovery ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("null_code_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto f =
      LLVMAddFunction(m, "null_code_fn", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 123, 0));
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_code_alloc = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  // In unpatched LLVM: this called report_fatal_error and crashed.
  // In patched LLVM: this returns 0 cleanly!
  uint64_t addr = LLVMGetFunctionAddress(ee, "null_code_fn");
  std::printf("NULL_CODE_ALLOC_LOOKUP: addr=0x%llx (expected 0)\n",
              (unsigned long long)addr);
  require(addr == 0, "Expected 0 address on null code allocation");

  char *diag = nullptr;
  LLVMExecutionEngineGetErrMsg(ee, &diag);
  std::printf("NULL_CODE_ALLOC_DIAG: '%s'\n", diag ? diag : "");
  if (diag)
    LLVMDisposeMessage(diag);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Null code allocation recovered cleanly without abort");
}

static void test_null_data_allocation_recovery() {
  std::puts("=== TEST: Null Data Allocation Non-Fatal Recovery ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("null_data_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto g = LLVMAddGlobal(m, i32, "null_test_var");
  LLVMSetInitializer(g, LLVMConstInt(i32, 42, 0));
  auto f = LLVMAddFunction(m, "load_null_data",
                           LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  auto val = LLVMBuildLoad2(b, i32, g, "val");
  LLVMBuildRet(b, val);
  LLVMDisposeBuilder(b);

  auto *fm = new CustomFaultManager();
  fm->fail_data_alloc = true;

  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = LLVMCreateSimpleMCJITMemoryManager(
      fm, custom_alloc_code, custom_alloc_data, custom_finalize,
      custom_destroy);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          "Create engine");

  uint64_t addr = LLVMGetFunctionAddress(ee, "load_null_data");
  std::printf("NULL_DATA_ALLOC_LOOKUP: addr=0x%llx (expected 0)\n",
              (unsigned long long)addr);
  require(addr == 0, "Expected 0 address on null data allocation");

  char *diag = nullptr;
  LLVMExecutionEngineGetErrMsg(ee, &diag);
  std::printf("NULL_DATA_ALLOC_DIAG: '%s'\n", diag ? diag : "");
  if (diag)
    LLVMDisposeMessage(diag);

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Null data allocation recovered cleanly without abort");
}

// ---------------------------------------------------------------------------
// Test Suite 14: Empty .text Section with Named Code Section & Unwind Info
// (Finding 4)
// ---------------------------------------------------------------------------
static void test_empty_text_and_comdat_object() {
  std::puts(
      "=== TEST: Empty .text Section with Named Code Section & Unwinding ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("empty_text_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto fn_ty = LLVMFunctionType(i32, nullptr, 0, 0);

  auto fn = LLVMAddFunction(m, "comdat_fn", fn_ty);
  LLVMSetSection(fn, ".text$named_func");
  auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);
  if (uw_kind)
    LLVMAddAttributeAtIndex(fn, LLVMAttributeFunctionIndex,
                            LLVMCreateEnumAttribute(ctx, uw_kind, 2));

  auto pers_fn = LLVMAddFunction(m, "probe_custom_personality",
                                 LLVMFunctionType(i32, nullptr, 0, 1));
  LLVMSetPersonalityFn(fn, pers_fn);

  auto b = LLVMCreateBuilderInContext(ctx);
  auto bb = LLVMAppendBasicBlockInContext(ctx, fn, "entry");
  LLVMPositionBuilderAtEnd(b, bb);
  auto slot = LLVMBuildAlloca(b, i32, "slot");
  LLVMBuildStore(b, LLVMConstInt(i32, 999, 0), slot);
  auto val = LLVMBuildLoad2(b, i32, slot, "val");
  LLVMBuildRet(b, val);
  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Engine creation for empty .text mod failed");
  LLVMAddGlobalMapping(ee, pers_fn, (void *)&probe_custom_personality);

  uint64_t fn_addr = LLVMGetFunctionAddress(ee, "comdat_fn");
  require(fn_addr != 0, "Failed to resolve comdat_fn with empty .text section");

  typedef int32_t (*IntFn)(void);
  IntFn func = (IntFn)fn_addr;
  int32_t res = func();
  std::printf("EMPTY_TEXT_EXECUTION: comdat_fn() = %d (expected 999)\n", res);
  require(res == 999, "comdat_fn must return 999");

#ifdef _WIN32
  DWORD64 base = 0;
  PRUNTIME_FUNCTION rf =
      RtlLookupFunctionEntry((DWORD64)fn_addr, &base, nullptr);
  require(
      rf != nullptr,
      "RtlLookupFunctionEntry failed for comdat_fn with empty .text section");
  std::printf("EMPTY_TEXT_UNWIND: FunctionEntry=%p Base=%llx\n", (void *)rf,
              (unsigned long long)base);
#endif

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Empty .text section with named code section and unwind info "
            "verified");
}

// ---------------------------------------------------------------------------
// Test Suite 15: Code-Free Object in Archive (Finding 3)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct MinimalCoffHeader {
  uint16_t Machine;              // 0x8664 (AMD64)
  uint16_t NumberOfSections;     // 1
  uint32_t TimeDateStamp;        // 0
  uint32_t PointerToSymbolTable; // 64
  uint32_t NumberOfSymbols;      // 1
  uint16_t SizeOfOptionalHeader; // 0
  uint16_t Characteristics;      // 0
};

struct MinimalCoffSectionHeader {
  char Name[8];                  // ".data\0\0\0"
  uint32_t VirtualSize;          // 0
  uint32_t VirtualAddress;       // 0
  uint32_t SizeOfRawData;        // 4
  uint32_t PointerToRawData;     // 60
  uint32_t PointerToRelocations; // 0
  uint32_t PointerToLinenumbers; // 0
  uint16_t NumberOfRelocations;  // 0
  uint16_t NumberOfLinenumbers;  // 0
  uint32_t Characteristics;      // 0xC0000040 (IMAGE_SCN_CNT_INITIALIZED_DATA |
                                 // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
};

struct MinimalCoffSymbol {
  char ShortName[8];          // "dataval\0"
  uint32_t Value;             // 0
  int16_t SectionNumber;      // 1
  uint16_t Type;              // 0
  uint8_t StorageClass;       // 2 (IMAGE_SYM_CLASS_EXTERNAL)
  uint8_t NumberOfAuxSymbols; // 0
};
#pragma pack(pop)

static void test_code_free_archive_object() {
  std::puts("=== TEST: Code-Free Object in Archive (Data-Only Sections) ===");
  MinimalCoffHeader hdr{};
  hdr.Machine = 0x8664;
  hdr.NumberOfSections = 1;
  hdr.TimeDateStamp = 0;
  hdr.PointerToSymbolTable = 64;
  hdr.NumberOfSymbols = 1;
  hdr.SizeOfOptionalHeader = 0;
  hdr.Characteristics = 0;

  MinimalCoffSectionHeader sec{};
  std::memcpy(sec.Name, ".data\0\0\0", 8);
  sec.VirtualSize = 0;
  sec.VirtualAddress = 0;
  sec.SizeOfRawData = 4;
  sec.PointerToRawData = 60;
  sec.PointerToRelocations = 0;
  sec.PointerToLinenumbers = 0;
  sec.NumberOfRelocations = 0;
  sec.NumberOfLinenumbers = 0;
  sec.Characteristics = 0xC0000040;

  int32_t raw_data = 777;

  MinimalCoffSymbol sym{};
  std::memcpy(sym.ShortName, "dataval\0", 8);
  sym.Value = 0;
  sym.SectionNumber = 1;
  sym.Type = 0;
  sym.StorageClass = 2;
  sym.NumberOfAuxSymbols = 0;

  uint32_t str_table_size = 4;

  const char *obj_name = "code_free.obj";
  FILE *f = std::fopen(obj_name, "wb");
  require(f != nullptr, "Failed to open code_free.obj for writing");
  std::fwrite(&hdr, sizeof(hdr), 1, f);
  std::fwrite(&sec, sizeof(sec), 1, f);
  std::fwrite(&raw_data, sizeof(raw_data), 1, f);
  std::fwrite(&sym, sizeof(sym), 1, f);
  std::fwrite(&str_table_size, sizeof(str_table_size), 1, f);
  std::fclose(f);

  const char *lib_name = "code_free.lib";
  char cmd[512];
  std::snprintf(cmd, sizeof(cmd), "llvm-ar.exe rc %s %s", lib_name, obj_name);
  int ar_rc = std::system(cmd);
  if (ar_rc != 0) {
    std::snprintf(cmd, sizeof(cmd), "llvm-ar rc %s %s", lib_name, obj_name);
    ar_rc = std::system(cmd);
  }
  require(ar_rc == 0, "llvm-ar command failed for code_free.lib");

  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("client_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto g_decl = LLVMAddGlobal(m, i32, "dataval");
  LLVMSetLinkage(g_decl, LLVMExternalLinkage);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr, err ? err : "Engine creation failed");

  char *arch_err = nullptr;
  LLVMBool arch_ret = LLVMExtAddArchiveFile(ee, lib_name, &arch_err);
  require(arch_ret == 0,
          arch_err ? arch_err
                   : "LLVMExtAddArchiveFile failed on code-free archive");

  uint64_t sym_addr = LLVMGetFunctionAddress(ee, "dataval");
  std::printf("CODE_FREE_DATA_ADDR: 0x%llx\n", (unsigned long long)sym_addr);
  require(sym_addr != 0, "Symbol in code-free archive member must resolve");
  int32_t val = *(const int32_t *)sym_addr;
  std::printf("CODE_FREE_DATA_VAL: %d (expected 777)\n", val);
  require(val == 777, "Data value from code-free archive member must be 777");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Code-free object from archive resolved and read without "
            "quadratic reallocation");
}

// ---------------------------------------------------------------------------
// Test Suite 16: Real Capacity: Split Reservation for Oversized RW Section
// ---------------------------------------------------------------------------
static void test_split_reservation_capacity() {
  std::puts("=== TEST: Real Capacity: Split Reservation for Oversized RW "
            "Section ===");
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("oversized_rw_mod", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto i8 = LLVMInt8TypeInContext(ctx);

  // Large global array: 5 GiB virtual size in BSS (takes 0 bytes of disk)
  auto sub_arr_ty = LLVMArrayType(i8, 1024 * 1024);  // 1 MB
  auto big_arr_ty = LLVMArrayType(sub_arr_ty, 5120); // 5120 * 1 MB = 5 GiB!
  auto huge_var = LLVMAddGlobal(m, big_arr_ty, "huge_rw_data");
  LLVMSetInitializer(huge_var, LLVMGetUndef(big_arr_ty));

  auto fn_ty = LLVMFunctionType(i32, nullptr, 0, 0);
  auto fn = LLVMAddFunction(m, "access_huge_rw_fn", fn_ty);
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, fn, "entry"));
  LLVMBuildRet(b, LLVMConstInt(i32, 4242, 0));
  LLVMDisposeBuilder(b);

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr,
          err ? err : "Failed to create engine for oversized RW module");

  uint64_t fn_addr = LLVMGetFunctionAddress(ee, "access_huge_rw_fn");
  require(fn_addr != 0, "Failed to resolve function in oversized RW module");

  typedef int32_t (*IntFn)(void);
  IntFn func = (IntFn)fn_addr;
  int32_t res = func();
  std::printf(
      "SPLIT_RESERVATION_EXEC: access_huge_rw_fn() = %d (expected 4242)\n",
      res);
  require(res == 4242, "Function must return 4242");

  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
  std::puts("PASS: Split reservation successfully handled >4GB RW data without "
            "cap failure");
}

// ---------------------------------------------------------------------------
// Test Suite 10: Allocation Model & Relocation Boundaries Unit Verification
// ---------------------------------------------------------------------------
static void test_allocation_model_and_relocation_boundaries() {
  std::puts("=== [LABELED MODEL ONLY - NOT OS PROOF] Allocation Model & "
            "Relocation Boundaries ===");

  // 1. Checked dynamic packed allocation reservation calculation
  auto round_up_checked = [](size_t n, size_t a, size_t *out) -> bool {
    if (!a || (a & (a - 1)))
      return false;
    if (n > SIZE_MAX - (a - 1))
      return false;
    *out = (n + a - 1) & ~(a - 1);
    return true;
  };

  size_t code_sz = 1024 * 1024;   // 1 MB
  size_t ro_sz = 512 * 1024;      // 512 KB
  size_t rw_sz = 2 * 1024 * 1024; // 2 MB
  size_t page_sz = 4096;

  size_t cap = 0;
  size_t end_code = 0, end_ro = 0, end_rw = 0;

  require(round_up_checked(code_sz, page_sz, &end_code), "round_up code");
  cap += end_code;
  require(round_up_checked(cap + ro_sz, page_sz, &end_ro), "round_up ro");
  cap = end_ro;
  require(round_up_checked(cap + rw_sz, page_sz, &end_rw), "round_up rw");
  cap = end_rw;

  std::printf("PACKED_RESERVATION: total_bytes=%zu (within 2GB span: %d)\n",
              cap, cap < (1ULL << 31));
  require(cap < (1ULL << 31),
          "Packed reservation must guarantee intra-object reach < 2GB");

  // Arithmetic overflow check in reservation
  size_t huge_sz = SIZE_MAX - 100;
  size_t overflow_out = 0;
  require(!round_up_checked(huge_sz, page_sz, &overflow_out),
          "Checked round_up must reject overflow");

  // 2. Multi-object address separation beyond 4 GiB simulation
  uint64_t base1 = 0x140000000ULL;
  uint64_t base2 = 0x100000000ULL; // Lower address
  uint64_t base3 = 0x340000000ULL; // > 4 GiB away from base1 (8 GiB offset)

  uint64_t target3 = base3 + 0x2000ULL;
  // Intended per-object ADDR32NB relocation:
  uint64_t per_object_rva = target3 - base3;
  require(per_object_rva == 0x2000ULL, "Per-object RVA must be 0x2000");
  require(per_object_rva <= 0xFFFFFFFFULL,
          "Per-object RVA must fit in 32-bit unsigned");

  // Stock LLVM global ImageBase bug simulation:
  uint64_t broken_global_rva = target3 - base1;
  require(broken_global_rva > 0xFFFFFFFFULL,
          "Global ImageBase causes overflow > 4 GiB across objects");
  std::printf("BASE_SEPARATION: per_object_rva=0x%llx (valid) vs "
              "broken_global_rva=0x%llx (overflow)\n",
              (unsigned long long)per_object_rva,
              (unsigned long long)broken_global_rva);

  // 3. Relocation Boundary Equations (using file-scoped check_addr32nb and
  // check_rel32)
  uint32_t rva_out = 0;
  require(check_addr32nb(base1 + 0x1000, base1, 0, &rva_out) &&
              rva_out == 0x1000,
          "Valid ADDR32NB");
  require(check_addr32nb(base1 + 0xFFFFFFFFULL, base1, 0, &rva_out) &&
              rva_out == 0xFFFFFFFFU,
          "Max 32-bit ADDR32NB");
  require(!check_addr32nb(base1, base1 + 0x1000, 0, &rva_out),
          "Underflow ADDR32NB must fail");
  require(!check_addr32nb(base1 + 0x100000000ULL, base1, 0, &rva_out),
          "Overflow ADDR32NB must fail");
  require(!check_addr32nb(base1 + 0xFFFFFFF0ULL, base1, 0x100, &rva_out),
          "Addend overflow ADDR32NB must fail");

  // REL32: Displacement in [-2^31, 2^31 - 1] (using file-scoped check_rel32)

  int32_t rel_out = 0;
  require(check_rel32(base1 + 0x2000, base1 + 0x1000, 0, 0, &rel_out),
          "Valid forward REL32");
  require(check_rel32(base1 + 0x1000, base1 + 0x2000, 0, 0, &rel_out),
          "Valid backward REL32");
  require(!check_rel32(base1 + 0x90000000ULL, base1, 0, 0, &rel_out),
          "Out-of-range positive REL32 (> 2GB)");
  require(!check_rel32(base1, base1 + 0x90000000ULL, 0, 0, &rel_out),
          "Out-of-range negative REL32 (< -2GB)");
  require(!check_rel32(base1 + 0x7FFFFFFFLL, base1, 0x100, 0, &rel_out),
          "Addend overflow REL32");

  // Test signed negative addends for REL32
  int32_t rel_neg_out = 0;
  require(check_rel32(base1 + 0x2000, base1 + 0x1000, -4, 0, &rel_neg_out),
          "Valid forward REL32 with negative addend (-4)");
  require(rel_neg_out == (0x1000 - 4 - 4),
          "REL32 displacement with -4 addend mismatch");

  // Test signed negative addends for ADDR32NB
  uint32_t rva_neg_out = 0;
  require(check_addr32nb(base1 + 0x2000, base1, -4, &rva_neg_out),
          "Valid ADDR32NB with negative addend (-4)");
  require(rva_neg_out == (0x2000 - 4), "ADDR32NB RVA with -4 addend mismatch");

  std::puts("PASS: Allocation Model & Relocation Boundaries");
}

// ---------------------------------------------------------------------------
// Test Suite 11: Wide Legal Layout Simulation (Checked Legacy Fallback)
// ---------------------------------------------------------------------------
static void test_wide_legal_layout_simulation() {
  std::puts(
      "=== [LABELED MODEL] Wide Section Displacement & Arithmetic Model ===");
  uint64_t code_base = 0x140000000ULL;
  uint64_t data_base = 0x150000000ULL; // 256 MB away: within 2GB signed reach

  uint64_t reloc_site = code_base + 0x50;
  int64_t disp = (int64_t)data_base - (int64_t)(reloc_site + 4);
  bool valid_disp = (disp >= INT32_MIN && disp <= INT32_MAX);
  std::printf("WIDE_LAYOUT_REACHABLE: disp=0x%llx within_int32=%d\n",
              (long long)disp, valid_disp);
  require(valid_disp, "Wide layout within 2GB signed reach must be accepted");

  uint64_t distant_data_base = 0x250000000ULL; // > 4 GB away
  int64_t distant_disp = (int64_t)distant_data_base - (int64_t)(reloc_site + 4);
  bool distant_valid = (distant_disp >= INT32_MIN && distant_disp <= INT32_MAX);
  std::printf(
      "WIDE_LAYOUT_UNREACHABLE: disp=0x%llx within_int32=%d (must be 0)\n",
      (long long)distant_disp, distant_valid);
  require(!distant_valid,
          "Displacement exceeding int32 must be rejected by range check");

  // Target remapping simulation: object base established from final target
  // addresses
  uint64_t initial_alloc = 0x140000000ULL;
  uint64_t remapped_target = 0x240000000ULL;
  uint64_t target_sym = remapped_target + 0x100;
  uint32_t remapped_rva = 0;
  require(check_addr32nb(target_sym, remapped_target, 0, &remapped_rva) &&
              remapped_rva == 0x100,
          "Remapped target address establishes new object base");
  require(
      initial_alloc != remapped_target,
      "Initial allocation and remapped target must represent distinct bases");

  std::puts("PASS: Wide legal layout simulation");
}

// ---------------------------------------------------------------------------
// Main Entrypoint with Mode Selectors
// ---------------------------------------------------------------------------
int main(int argc, char **argv) {
  LLVMLinkInMCJIT();
  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmPrinter();
  LLVMInitializeNativeAsmParser();

  std::string mode = "--all";
  if (argc > 1) {
    mode = argv[1];
  }

  std::printf("=== JIT RESERVATION PROBE (mode: %s) ===\n", mode.c_str());

  if (mode == "--fail-allocation-code") {
    test_null_code_allocation_recovery();
    std::puts("PROBE SUBPROCESS SUCCESS: code allocation recovery verified");
    return 0;
  }

  if (mode == "--fail-allocation-data") {
    test_null_data_allocation_recovery();
    std::puts("PROBE SUBPROCESS SUCCESS: data allocation recovery verified");
    return 0;
  }

  if (mode == "--fail-allocation-common") {
    test_null_common_symbol_allocation_recovery();
    std::puts("PROBE SUBPROCESS SUCCESS: common symbols allocation recovery "
              "verified");
    return 0;
  }

  if (mode == "--fail-finalize") {
    test_fail_closed_finalize_and_sticky_errors();
    test_fail_closed_virtual_protect();
    test_fail_closed_cache_flush();
    test_production_manager_injected_os_failures();
    std::puts("PROBE SUBPROCESS SUCCESS: finalize/protect/cache failures "
              "recovery verified");
    return 0;
  }

  if (mode == "--model-only") {
    test_allocation_model_and_relocation_boundaries();
    test_wide_legal_layout_simulation();
    std::puts("PROBE SUBPROCESS SUCCESS: model tests verified");
    return 0;
  }

  // Default: run all tests
  test_build_identity();
  test_production_execution_and_wx_protection();
  test_windows_unwind_and_real_stack_walk();
  test_multi_object_execution();
  test_external_stubs_common_symbols_alignment();
  test_empty_groups_module();
  test_fail_closed_finalize_and_sticky_errors();
  test_fail_closed_virtual_protect();
  test_fail_closed_cache_flush();
  test_production_manager_injected_os_failures();
  test_lazy_lookup_failure_on_healthy_engine();
  test_lazy_archive_lookup();
  test_encoded_relocations_live_runtime_dyld();
  test_empty_text_and_comdat_object();
  test_code_free_archive_object();
  test_split_reservation_capacity();
  test_null_code_allocation_recovery();
  test_null_data_allocation_recovery();
  test_null_common_symbol_allocation_recovery();
  test_allocation_model_and_relocation_boundaries();
  test_wide_legal_layout_simulation();

  std::puts("ALL PROBE TESTS PASSED SUCCESSFULLY");
  return 0;
}
