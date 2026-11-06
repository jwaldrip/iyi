#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <llvm-c/Core.h>
#include <llvm-c/ExecutionEngine.h>
#include <llvm-c/Target.h>
#include <llvm/ExecutionEngine/SectionMemoryManager.h>
#include <string>
#include <vector>
#define NOMINMAX
#include <windows.h>

using namespace llvm;
static bool fail_allocation = false;
static void require(bool b, const char *s) {
  if (!b) {
    std::fprintf(stderr, "FAIL %s\n", s);
    std::exit(1);
  }
}
static size_t round_up(size_t n, size_t a) {
  require(a && !(a & (a - 1)) && n <= SIZE_MAX - (a - 1), "alignment/overflow");
  return (n + a - 1) & ~(a - 1);
}
struct Page {
  void *p;
  size_t n;
  DWORD protection;
  std::string name;
};
struct Manager final : SectionMemoryManager {
  unsigned char *base = nullptr;
  size_t capacity = 0;
  size_t cursor[3] = {};
  size_t end[3] = {};
  size_t page = 0;
  bool fail_finalize = false;
  bool finalized = false;
  bool failed = false;
  unsigned calls = 0;
  std::vector<Page> pages;
  explicit Manager(bool f) : fail_finalize(f) {
    SYSTEM_INFO i;
    GetSystemInfo(&i);
    page = i.dwPageSize;
  }
  ~Manager() override {
    if (base)
      VirtualFree(base, 0, MEM_RELEASE);
  }
  bool needsToReserveAllocationSpace() override { return true; }
  void reserveAllocationSpace(uintptr_t c, Align ca, uintptr_t ro, Align ra,
                              uintptr_t rw, Align wa) override {
    require(!base, "multiple objects not supported by this experiment");
    std::printf(
        "RESERVE code=%zu align=%zu ro=%zu align=%zu rw=%zu align=%zu\n",
        size_t(c), size_t(ca.value()), size_t(ro), size_t(ra.value()),
        size_t(rw), size_t(wa.value()));
    size_t sizes[] = {size_t(c), size_t(ro), size_t(rw)},
           aligns[] = {size_t(ca.value()), size_t(ra.value()),
                       size_t(wa.value())};
    for (int i = 0; i < 3; i++) {
      size_t a = std::max(page, aligns[i]);
      capacity = round_up(capacity, a);
      cursor[i] = capacity;
      require(sizes[i] <= SIZE_MAX - capacity, "capacity overflow");
      capacity = round_up(capacity + sizes[i], page);
      end[i] = capacity;
    }
    require(capacity, "empty object");
    base = (unsigned char *)VirtualAlloc(
        nullptr, capacity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    require(base, "VirtualAlloc");
    std::printf("WINDOW base=%p bytes=%zu\n", base, capacity);
  }
  uint8_t *alloc(int group, uintptr_t size, unsigned align, StringRef name) {
    require(base, "reserve callback missing");
    if (fail_allocation) {
      std::fprintf(stderr, "INJECTED_NULL_SECTION\n");
      return nullptr;
    }
    size_t a = std::max<size_t>(align ? align : 16, 1);
    size_t pos = round_up(cursor[group], a);
    require(pos <= end[group] && size <= end[group] - pos,
            "LLVM totals exhausted");
    cursor[group] = pos + size;
    auto *p = base + pos;
    calls++;
    std::printf("SECTION group=%d name=%s size=%zu align=%u offset=%zu\n",
                group, name.str().c_str(), size_t(size), align, pos);
    return p;
  }
  uint8_t *allocateCodeSection(uintptr_t s, unsigned a, unsigned,
                               StringRef n) override {
    return alloc(0, s, a, n);
  }
  uint8_t *allocateDataSection(uintptr_t s, unsigned a, unsigned, StringRef n,
                               bool ro) override {
    return alloc(ro ? 1 : 2, s, a, n);
  }
  bool finalizeMemory(std::string *err = nullptr) override {
    std::printf("FINALIZE injected_failure=%d already_finalized=%d\n",
                fail_finalize, finalized);
    if (fail_finalize) {
      failed = true;
      if (err)
        *err = "injected failure";
      return true;
    }
    if (finalized)
      return false;
    for (int i = 0; i < 3; i++) {
      size_t start = (i ? end[i - 1] : 0), n = end[i] - start;
      if (!n)
        continue;
      DWORD old, prot = i == 0 ? PAGE_EXECUTE_READ
                               : (i == 1 ? PAGE_READONLY : PAGE_READWRITE);
      if (!VirtualProtect(base + start, n, prot, &old)) {
        failed = true;
        if (err)
          *err = "VirtualProtect";
        return true;
      }
      MEMORY_BASIC_INFORMATION info{};
      require(VirtualQuery(base + start, &info, sizeof(info)) != 0,
              "VirtualQuery");
      std::printf("PROTECT group=%d got=%lu expected=%lu\n", i, info.Protect,
                  prot);
      require(info.Protect == prot, "wrong protection");
    }
    if (!FlushInstructionCache(GetCurrentProcess(), base, capacity)) {
      failed = true;
      if (err)
        *err = "FlushInstructionCache";
      return true;
    }
    finalized = true;
    return false;
  }
};
static void run(bool fail) {
  LLVMContextRef ctx = LLVMContextCreate();
  LLVMModuleRef m = LLVMModuleCreateWithNameInContext("probe", ctx);
  auto i32 = LLVMInt32TypeInContext(ctx);
  auto p = LLVMPointerTypeInContext(ctx, 0);
  auto global = LLVMAddGlobal(m, i32, "mutable_value");
  LLVMSetInitializer(global, LLVMConstInt(i32, 41, 0));
  LLVMSetLinkage(global, LLVMInternalLinkage);
  auto readonly = LLVMAddGlobal(m, i32, "readonly_value");
  LLVMSetInitializer(readonly, LLVMConstInt(i32, 1, 0));
  LLVMSetGlobalConstant(readonly, 1);
  LLVMSetLinkage(readonly, LLVMInternalLinkage);
  auto f =
      LLVMAddFunction(m, "get_pointer", LLVMFunctionType(p, nullptr, 0, 0));
  auto b = LLVMCreateBuilderInContext(ctx);
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, f, "entry"));
  LLVMBuildRet(b, global);
  auto g = LLVMAddFunction(m, "evaluate", LLVMFunctionType(i32, nullptr, 0, 0));
  auto uw_kind = LLVMGetEnumAttributeKindForName("uwtable", 7);
  require(uw_kind != 0, "uwtable attribute");
  LLVMAddAttributeAtIndex(g, LLVMAttributeFunctionIndex,
                          LLVMCreateEnumAttribute(ctx, uw_kind, 2));
  LLVMPositionBuilderAtEnd(b, LLVMAppendBasicBlockInContext(ctx, g, "entry"));
  auto pointer_call = LLVMBuildCall2(b, LLVMFunctionType(p, nullptr, 0, 0), f,
                                     nullptr, 0, "pointer");
  auto v = LLVMBuildLoad2(b, i32, pointer_call, "v");
  auto r = LLVMBuildLoad2(b, i32, readonly, "r");
  LLVMSetVolatile(r, 1);
  LLVMBuildRet(b, LLVMBuildAdd(b, v, r, "sum"));
  LLVMDisposeBuilder(b);
  auto *mgr = new Manager(fail);
  LLVMMCJITCompilerOptions opt;
  LLVMInitializeMCJITCompilerOptions(&opt, sizeof(opt));
  opt.MCJMM = reinterpret_cast<LLVMMCJITMemoryManagerRef>(mgr);
  LLVMExecutionEngineRef ee = nullptr;
  char *err = nullptr;
  require(!LLVMCreateMCJITCompilerForModule(&ee, m, &opt, sizeof(opt), &err),
          err ? err : "engine creation");
  uint64_t address = LLVMGetFunctionAddress(ee, "evaluate");
  std::printf("LOOKUP address=%llx calls=%u failed=%d\n",
              (unsigned long long)address, mgr->calls, mgr->failed);
  require(mgr->calls, "callbacks not invoked");
  if (fail) {
    require(mgr->failed, "injected failure not observed");
    std::printf("FAILURE_PROPAGATION address_nonzero=%d (not executed)\n",
                address != 0);
  } else {
    require(address && !mgr->failed, "materialization");
    auto result = LLVMRunFunction(ee, g, 0, nullptr);
    require(LLVMGenericValueToInt(result, 0) == 42, "integer result");
    LLVMDisposeGenericValue(result);
    auto pointer = LLVMRunFunction(ee, f, 0, nullptr);
    auto ptr = (int *)LLVMGenericValueToPointer(pointer);
    require(ptr && *ptr == 41, "pointer result");
    *ptr = 100;
    require(((int (*)())(uintptr_t)address)() == 101, "mutable result");
    DWORD64 image = 0;
    auto unwind = RtlLookupFunctionEntry(address, &image, nullptr);
    std::printf("UNWIND lookup=%p image=%llx (observational only)\n",
                (void *)unwind, (unsigned long long)image);
    std::printf("RESULT integer=42 pointer_before=41 pointer_after=%d\n", *ptr);
    LLVMDisposeGenericValue(pointer);
  }
  LLVMDisposeExecutionEngine(ee);
  LLVMContextDispose(ctx);
}
int main(int argc, char **argv) {
  LLVMLinkInMCJIT();
  LLVMInitializeNativeTarget();
  LLVMInitializeNativeAsmPrinter();
  fail_allocation = argc > 1 && std::string(argv[1]) == "--fail-allocation";
  run(false);
  run(true);
  std::puts("PROBE COMPLETE");
}
