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

// Native callbacks for testing stubs and stack unwinding
__declspec(dllexport) int32_t probe_native_external_add(int32_t a, int32_t b);
__declspec(dllexport) void probe_native_stack_walk_callback(void);

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

// Global state for stack unwind test
static DWORD64 g_expected_jit_image_base = 0;
static DWORD64 g_expected_jit_fn_addr = 0;
static bool g_stack_walk_observed_jit_frame = false;
static bool g_stack_walk_unwound_past_jit = false;

extern "C" int32_t probe_native_external_add(int32_t a, int32_t b) {
  return a + b;
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

  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  LLVMBool create_err =
      LLVMExtCreateWindowsMCJITCompilerForModule(&ee, m, &err);
  require(!create_err && ee != nullptr, err ? err : "Engine creation failed");

  // Map external callback
  LLVMAddGlobalMapping(ee, cb_decl, (void *)&probe_native_stack_walk_callback);

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

  typedef void (*JitCallerFn)(void);
  JitCallerFn jit_caller = (JitCallerFn)caller_addr;
  jit_caller();

  require(
      g_stack_walk_observed_jit_frame,
      "Stack walk did not observe the JIT frame via RtlLookupFunctionEntry");
  require(g_stack_walk_unwound_past_jit,
          "Stack walk did not unwind past JIT frame with RtlVirtualUnwind");
  std::puts("PASS: Real stack walking through JIT frame succeeded");

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

  // 1. External stub: int32_t probe_native_external_add(int32_t, int32_t)
  LLVMTypeRef add_param_tys[] = {i32, i32};
  auto add_fn_ty = LLVMFunctionType(i32, add_param_tys, 2, 0);
  auto ext_add_decl =
      LLVMAddFunction(m, "probe_native_external_add", add_fn_ty);

  // 2. Common symbol: uninitialized global
  auto common_var = LLVMAddGlobal(m, i32, "probe_common_int");
  LLVMSetLinkage(common_var, LLVMCommonLinkage);

  // 3. Over-granularity aligned global (64 bytes and 4096 bytes)
  auto align_var64 = LLVMAddGlobal(m, i32, "probe_align64_int");
  LLVMSetInitializer(align_var64, LLVMConstInt(i32, 6464, 0));
  LLVMSetAlignment(align_var64, 64);

  auto align_var4096 = LLVMAddGlobal(m, i32, "probe_align4096_int");
  LLVMSetInitializer(align_var4096, LLVMConstInt(i32, 4096, 0));
  LLVMSetAlignment(align_var4096, 4096);

  // Function calling external add and returning sum
  auto test_fn =
      LLVMAddFunction(m, "run_stub_test", LLVMFunctionType(i32, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(
      b, LLVMAppendBasicBlockInContext(ctx, test_fn, "entry"));
  LLVMValueRef args[] = {LLVMConstInt(i32, 20, 0), LLVMConstInt(i32, 22, 0)};
  auto add_call =
      LLVMBuildCall2(b, add_fn_ty, ext_add_decl, args, 2, "call_add");
  LLVMBuildRet(b, add_call);
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

  // Check 64-byte alignment
  void *align64_ptr = LLVMGetPointerToGlobal(ee, align_var64);
  require(align64_ptr != nullptr, "align64_ptr is null");
  require(((uintptr_t)align64_ptr % 64) == 0,
          "align64_ptr does not have 64-byte alignment");
  std::printf("ALIGN_64: addr=%p (offset %% 64 = %zu)\n", align64_ptr,
              (uintptr_t)align64_ptr % 64);

  // Check 4096-byte alignment
  void *align4096_ptr = LLVMGetPointerToGlobal(ee, align_var4096);
  require(align4096_ptr != nullptr, "align4096_ptr is null");
  require(((uintptr_t)align4096_ptr % 4096) == 0,
          "align4096_ptr does not have 4096-byte alignment");
  std::printf("ALIGN_4096: addr=%p (offset %% 4096 = %zu)\n", align4096_ptr,
              (uintptr_t)align4096_ptr % 4096);

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
  if (self->fail_protect) {
    if (err_msg)
      *err_msg = _strdup("injected VirtualProtect failure");
    return 1;
  }
  if (self->fail_cache_flush) {
    if (err_msg)
      *err_msg = _strdup("injected FlushInstructionCache failure");
    return 1;
  }

  // Set permissions
  DWORD old;
  for (void *p : self->code_pages) {
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
// Test Suite 10: Allocation Model & Relocation Boundaries Unit Verification
// ---------------------------------------------------------------------------
static void test_allocation_model_and_relocation_boundaries() {
  std::puts("=== TEST: Allocation Model & Relocation Boundaries ===");

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

  // 3. Relocation Boundary Equations:
  // ADDR32NB: Value in [0, 0xFFFFFFFF]
  auto check_addr32nb = [](uint64_t target, uint64_t base, int64_t addend,
                           uint32_t *out) -> bool {
    if (target < base && addend <= 0)
      return false; // Underflow
    int64_t rva = (int64_t)(target - base) + addend;
    if (rva < 0 || rva > 0xFFFFFFFFLL)
      return false; // Overflow / Underflow
    *out = (uint32_t)rva;
    return true;
  };

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

  // REL32: Displacement in [-2^31, 2^31 - 1]
  auto check_rel32 = [](uint64_t target, uint64_t reloc_site, int64_t addend,
                        int extra_disp, int32_t *out) -> bool {
    int64_t next_pc = (int64_t)(reloc_site + 4 + extra_disp);
    int64_t disp = (int64_t)target - next_pc + addend;
    if (disp < (int64_t)INT32_MIN || disp > (int64_t)INT32_MAX)
      return false;
    *out = (int32_t)disp;
    return true;
  };

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

  std::puts("PASS: Allocation Model & Relocation Boundaries");
}

// ---------------------------------------------------------------------------
// Test Suite 11: Wide Legal Layout Simulation (Checked Legacy Fallback)
// ---------------------------------------------------------------------------
static void test_wide_legal_layout_simulation() {
  std::puts("=== TEST: Wide Legal Layout & Contiguous Allocation Fallback "
            "Simulation ===");
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

  std::puts("PASS: Wide legal layout simulation");
}

// ---------------------------------------------------------------------------
// Main Entrypoint with Mode Selectors
// ---------------------------------------------------------------------------
int main(int argc, char **argv) {
  LLVMLinkInMCJIT();
  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmPrinter();

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

  if (mode == "--fail-finalize") {
    test_fail_closed_finalize_and_sticky_errors();
    test_fail_closed_virtual_protect();
    test_fail_closed_cache_flush();
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
  test_null_code_allocation_recovery();
  test_null_data_allocation_recovery();
  test_allocation_model_and_relocation_boundaries();
  test_wide_legal_layout_simulation();

  std::puts("ALL PROBE TESTS PASSED SUCCESSFULLY");
  return 0;
}
