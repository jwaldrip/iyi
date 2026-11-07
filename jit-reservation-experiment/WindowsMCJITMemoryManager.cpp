//===- WindowsMCJITMemoryManager.cpp - Memory manager for Windows MCJIT -*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Implementation of WindowsMCJITMemoryManager.
//
//===----------------------------------------------------------------------===//

#include "llvm/ExecutionEngine/WindowsMCJITMemoryManager.h"
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <limits>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
// Non-Windows compatibility definitions for host building/testing
using DWORD = uint32_t;
using DWORD64 = uint64_t;
using BOOLEAN = uint8_t;
struct RUNTIME_FUNCTION {
  DWORD BeginAddress;
  DWORD EndAddress;
  union {
    DWORD UnwindInfoAddress;
    DWORD UnwindData;
  } DUMMYUNIONNAME;
};
using PRUNTIME_FUNCTION = RUNTIME_FUNCTION *;

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000
#define MEM_RELEASE 0x00008000
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20

static inline void *VirtualAlloc(void *lpAddress, size_t dwSize,
                                 DWORD flAllocationType, DWORD flProtect) {
  return nullptr;
}
static inline int VirtualFree(void *lpAddress, size_t dwSize,
                              DWORD dwFreeType) {
  return 1;
}
static inline int VirtualProtect(void *lpAddress, size_t dwSize,
                                 DWORD flNewProtect, DWORD *lpflOldProtect) {
  return 1;
}
static inline int FlushInstructionCache(void *hProcess,
                                        const void *lpBaseAddress,
                                        size_t dwSize) {
  return 1;
}
static inline void *GetCurrentProcess() { return nullptr; }
static inline DWORD GetLastError() { return 0; }
static inline BOOLEAN RtlAddFunctionTable(PRUNTIME_FUNCTION FunctionTable,
                                          DWORD EntryCount,
                                          DWORD64 BaseAddress) {
  return 1;
}
static inline BOOLEAN RtlDeleteFunctionTable(PRUNTIME_FUNCTION FunctionTable) {
  return 1;
}
#endif

namespace llvm {
#ifdef LLVM_ENABLE_TEST_HOOKS
static std::atomic<uint32_t> FaultInjectionFlags{0};
static std::atomic<uint64_t> LastUnwindProbeAddress{0};
static std::atomic<uint64_t> FirstRegisteredUnwindAddress{0};
static std::atomic<uint32_t> SplitReservationCount{0};

void setWindowsMCJITFaultInjection(uint32_t Flags) {
  FaultInjectionFlags.store(Flags, std::memory_order_relaxed);
  LastUnwindProbeAddress.store(0, std::memory_order_relaxed);
  FirstRegisteredUnwindAddress.store(0, std::memory_order_relaxed);
  SplitReservationCount.store(0, std::memory_order_relaxed);
}

uint32_t getWindowsMCJITFaultInjection() {
  return FaultInjectionFlags.load(std::memory_order_relaxed);
}

uint64_t getWindowsMCJITLastUnwindProbeAddress() {
  return LastUnwindProbeAddress.load(std::memory_order_relaxed);
}

uint64_t getWindowsMCJITFirstRegisteredUnwindAddress() {
  return FirstRegisteredUnwindAddress.load(std::memory_order_relaxed);
}

void resetWindowsMCJITUnwindProbeAddresses() {
  LastUnwindProbeAddress.store(0, std::memory_order_relaxed);
  FirstRegisteredUnwindAddress.store(0, std::memory_order_relaxed);
  SplitReservationCount.store(0, std::memory_order_relaxed);
}

uint32_t getWindowsMCJITSplitReservationCount() {
  return SplitReservationCount.load(std::memory_order_relaxed);
}
#endif

static bool checkedAdd(size_t a, size_t b, size_t &result) {
  if (a > SIZE_MAX - b)
    return false;
  result = a + b;
  return true;
}

static bool checkedRoundUp(size_t val, size_t align, size_t &result) {
  if (align == 0) {
    result = val;
    return true;
  }
  size_t mask = align - 1;
  if ((align & mask) != 0) // align must be power of two
    return false;
  if (val > SIZE_MAX - mask)
    return false;
  result = (val + mask) & ~mask;
  return true;
}

WindowsMCJITMemoryManager::WindowsMCJITMemoryManager() {
#ifdef _WIN32
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  PageSize = si.dwPageSize ? si.dwPageSize : 4096;
  AllocGranularity =
      si.dwAllocationGranularity ? si.dwAllocationGranularity : 65536;
#else
  PageSize = 4096;
  AllocGranularity = 65536;
#endif
}

WindowsMCJITMemoryManager::~WindowsMCJITMemoryManager() {
#ifdef _WIN32
  for (auto &Table : ActiveUnwindTables) {
    if (Table.Registered) {
      RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(Table.Addr));
      Table.Registered = false;
    }
  }
#endif
  ActiveUnwindTables.clear();

  for (auto &Res : Reservations) {
    if (Res && Res->Base) {
      VirtualFree(Res->Base, 0, MEM_RELEASE);
      Res->Base = nullptr;
    }
  }
  Reservations.clear();
}

void WindowsMCJITMemoryManager::reserveAllocationSpace(
    uintptr_t CodeSize, Align CodeAlign, uintptr_t RODataSize,
    Align RODataAlign, uintptr_t RWDataSize, Align RWDataAlign) {
  CurrentReservation = nullptr;

  size_t Sizes[3] = {CodeSize, RODataSize, RWDataSize};
  size_t Alignments[3] = {std::max<size_t>(PageSize, CodeAlign.value()),
                          std::max<size_t>(PageSize, RODataAlign.value()),
                          std::max<size_t>(PageSize, RWDataAlign.value())};

  // If object is completely empty, no reservation needed.
  if (Sizes[0] == 0 && Sizes[1] == 0 && Sizes[2] == 0)
    return;

  size_t Offsets[3] = {};
  size_t Ends[3] = {};
  size_t CurrentOffset = 0;

  // Compute packed object span with page separation and checked arithmetic
  for (int i = 0; i < 3; ++i) {
    if (!checkedRoundUp(CurrentOffset, Alignments[i], Offsets[i]))
      return; // Fallback to checked legacy allocation on overflow
    CurrentOffset = Offsets[i];
    if (Sizes[i] > 0) {
      size_t GroupEnd = 0;
      if (!checkedAdd(CurrentOffset, Sizes[i], GroupEnd))
        return;
      if (!checkedRoundUp(GroupEnd, PageSize, Ends[i]))
        return;
      CurrentOffset = Ends[i];
    } else {
      Ends[i] = Offsets[i];
    }
  }

  size_t TotalSpan = 0;
  if (!checkedRoundUp(CurrentOffset, AllocGranularity, TotalSpan))
    return;

  // Reservation span ceiling for x86-64 intra-object relocations:
  // ADDR32NB unsigned 32-bit reach from object base is 4 GiB (0xFFFE0000ULL).
  constexpr size_t MaxReservationSpan = 0xFFFE0000ULL;
  if (TotalSpan > MaxReservationSpan) {
    // If total span exceeds 4 GiB due to large read-write data, but code and
    // read-only data (including unwind tables) fit within 4 GiB, pack groups 0
    // and 1 to guarantee proximity of code and unwind metadata, leaving group 2
    // (RW) for SectionMemoryManager allocation.
    size_t CodeROSpan = 0;
    if (Sizes[2] > 0 && checkedRoundUp(Ends[1], AllocGranularity, CodeROSpan) &&
        CodeROSpan <= MaxReservationSpan) {
      void *BasePtr =
          VirtualAlloc(nullptr, CodeROSpan, MEM_RESERVE, PAGE_NOACCESS);
      if (BasePtr) {
#ifdef LLVM_ENABLE_TEST_HOOKS
        SplitReservationCount.fetch_add(1, std::memory_order_relaxed);
#endif
        auto Res = std::make_unique<PackedReservation>();
        Res->Base = static_cast<uint8_t *>(BasePtr);
        Res->TotalReserved = CodeROSpan;
        for (int i = 0; i < 2; ++i) {
          Res->GroupOffsets[i] = Offsets[i];
          Res->GroupSizes[i] = Sizes[i];
          Res->GroupCursors[i] = Offsets[i];
          Res->GroupEnds[i] = Ends[i];
        }
        Res->GroupOffsets[2] = 0;
        Res->GroupSizes[2] = 0;
        Res->GroupCursors[2] = 0;
        Res->GroupEnds[2] = 0;
        Res->Finalized = false;
        CurrentReservation = Res.get();
        Reservations.push_back(std::move(Res));
        return;
      }
    }
    return; // Fall back to checked legacy allocation for wide layouts
  }
  // Reserve contiguous memory window for this object
  void *BasePtr = VirtualAlloc(nullptr, TotalSpan, MEM_RESERVE, PAGE_NOACCESS);
  if (!BasePtr)
    return; // Fall back to checked legacy allocation if OS cannot provide
            // contiguous reservation

  auto Res = std::make_unique<PackedReservation>();
  Res->Base = static_cast<uint8_t *>(BasePtr);
  Res->TotalReserved = TotalSpan;
  for (int i = 0; i < 3; ++i) {
    Res->GroupOffsets[i] = Offsets[i];
    Res->GroupSizes[i] = Sizes[i];
    Res->GroupCursors[i] = Offsets[i];
    Res->GroupEnds[i] = Ends[i];
  }
  Res->Finalized = false;

  CurrentReservation = Res.get();
  Reservations.push_back(std::move(Res));
}

uint8_t *WindowsMCJITMemoryManager::allocateFromReservation(
    int Group, uintptr_t Size, unsigned Alignment, unsigned SectionID,
    StringRef SectionName) {
  if (!CurrentReservation || !CurrentReservation->Base)
    return nullptr;

  if (Size == 0)
    return CurrentReservation->Base + CurrentReservation->GroupCursors[Group];

  size_t AlignReq = std::max<size_t>(Alignment ? Alignment : 16, 1);
  if ((AlignReq & (AlignReq - 1)) != 0)
    return nullptr; // Alignment must be power of two

  // Align base + offset, not merely offset
  uintptr_t CurrAddr = reinterpret_cast<uintptr_t>(
      CurrentReservation->Base + CurrentReservation->GroupCursors[Group]);
  uintptr_t AlignedAddr =
      (CurrAddr + (AlignReq - 1)) & ~(static_cast<uintptr_t>(AlignReq - 1));
  size_t Pos =
      AlignedAddr - reinterpret_cast<uintptr_t>(CurrentReservation->Base);

  if (Pos > CurrentReservation->GroupEnds[Group] ||
      Size > CurrentReservation->GroupEnds[Group] - Pos) {
    // LLVM allocated beyond the initial reservation accounting; return null so
    // fallback can handle
    return nullptr;
  }

  // Commit used pages RW, including any alignment padding since last cursor
  size_t StartOffset = CurrentReservation->GroupCursors[Group];
  uintptr_t CommitStart =
      (reinterpret_cast<uintptr_t>(CurrentReservation->Base + StartOffset)) &
      ~(PageSize - 1);
  uintptr_t CommitEnd =
      (reinterpret_cast<uintptr_t>(CurrentReservation->Base + Pos + Size +
                                   PageSize - 1)) &
      ~(PageSize - 1);
  size_t CommitBytes = CommitEnd - CommitStart;

  void *CommResult = VirtualAlloc(reinterpret_cast<void *>(CommitStart),
                                  CommitBytes, MEM_COMMIT, PAGE_READWRITE);
  if (!CommResult)
    return nullptr; // Record OS allocation failure without throwing

  CurrentReservation->GroupCursors[Group] = Pos + Size;
  return CurrentReservation->Base + Pos;
}

uint8_t *WindowsMCJITMemoryManager::allocateCodeSection(uintptr_t Size,
                                                        unsigned Alignment,
                                                        unsigned SectionID,
                                                        StringRef SectionName) {
  if (CurrentReservation) {
    if (uint8_t *P =
            allocateFromReservation(0, Size, Alignment, SectionID, SectionName))
      return P;
  }
  return SectionMemoryManager::allocateCodeSection(Size, Alignment, SectionID,
                                                   SectionName);
}

uint8_t *WindowsMCJITMemoryManager::allocateDataSection(uintptr_t Size,
                                                        unsigned Alignment,
                                                        unsigned SectionID,
                                                        StringRef SectionName,
                                                        bool IsReadOnly) {
  if (CurrentReservation) {
    if (uint8_t *P = allocateFromReservation(IsReadOnly ? 1 : 2, Size,
                                             Alignment, SectionID, SectionName))
      return P;
  }
  return SectionMemoryManager::allocateDataSection(Size, Alignment, SectionID,
                                                   SectionName, IsReadOnly);
}

bool WindowsMCJITMemoryManager::finalizeMemory(std::string *ErrMsg) {
  if (FinalizationFailed) {
    if (ErrMsg)
      *ErrMsg =
          FinalizationErrMsg.empty()
              ? "Memory manager is in a permanent failed state after prior "
                "finalization failure"
              : FinalizationErrMsg;
    return true;
  }

  // Step 1: Validate and sort all pending unwind tables in-place while their
  // memory is still PAGE_READWRITE. If any record or table is invalid, fail
  // immediately before modifying any protections.
  for (auto &Entry : PendingUnwindTables) {
    if (Entry.Size == 0)
      continue;

    constexpr size_t RecordSize = sizeof(RUNTIME_FUNCTION);
    if (Entry.Size % RecordSize != 0) {
      if (ErrMsg)
        *ErrMsg = ".pdata section size is not an integral number of "
                  "RUNTIME_FUNCTION records";
      FinalizationFailed = true;
      if (ErrMsg)
        FinalizationErrMsg = *ErrMsg;
      PendingUnwindTables.clear();
      return true;
    }

    size_t Count = Entry.Size / RecordSize;
    if (Count > std::numeric_limits<DWORD>::max()) {
      if (ErrMsg)
        *ErrMsg = ".pdata section record count exceeds 32-bit limit";
      FinalizationFailed = true;
      if (ErrMsg)
        FinalizationErrMsg = *ErrMsg;
      PendingUnwindTables.clear();
      return true;
    }

    auto *Records = reinterpret_cast<PRUNTIME_FUNCTION>(Entry.Addr);
    for (size_t i = 0; i < Count; ++i) {
      if (Records[i].BeginAddress >= Records[i].EndAddress) {
        if (ErrMsg)
          *ErrMsg =
              "Invalid RUNTIME_FUNCTION record: BeginAddress >= EndAddress";
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
    }

    // Sort records in ascending order by BeginAddress while memory is still
    // writable
    std::sort(Records, Records + Count,
              [](const RUNTIME_FUNCTION &a, const RUNTIME_FUNCTION &b) {
                return a.BeginAddress < b.BeginAddress;
              });
  }

  // Step 2: Ensure complete used group prefixes (including alignment gaps) are
  // committed, then apply page protections and instruction cache flushes.
  uint32_t Faults = getWindowsMCJITFaultInjection();
  for (auto &Res : Reservations) {
    if (!Res || Res->Finalized || !Res->Base)
      continue;

    // Apply Code permissions (PAGE_EXECUTE_READ)
    size_t CodeUsed = Res->GroupCursors[0] - Res->GroupOffsets[0];
    if (CodeUsed > 0) {
      size_t AlignedCodeUsed = 0;
      checkedRoundUp(CodeUsed, PageSize, AlignedCodeUsed);
      // Ensure the complete used prefix is committed before calling
      // VirtualProtect
      if ((Faults & FaultVirtualAllocCommit) ||
          !VirtualAlloc(Res->Base + Res->GroupOffsets[0], AlignedCodeUsed,
                        MEM_COMMIT, PAGE_READWRITE)) {
        if (ErrMsg)
          *ErrMsg =
              "VirtualAlloc MEM_COMMIT failed for code section prefix with OS "
              "error " +
              std::to_string(GetLastError());
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
      DWORD OldProt = 0;
      if ((Faults & FaultVirtualProtectCode) ||
          !VirtualProtect(Res->Base + Res->GroupOffsets[0], AlignedCodeUsed,
                          PAGE_EXECUTE_READ, &OldProt)) {
        if (ErrMsg)
          *ErrMsg = "VirtualProtect PAGE_EXECUTE_READ failed with OS error " +
                    std::to_string(GetLastError());
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
      if ((Faults & FaultFlushInstructionCache) ||
          !FlushInstructionCache(GetCurrentProcess(),
                                 Res->Base + Res->GroupOffsets[0],
                                 AlignedCodeUsed)) {
        if (ErrMsg)
          *ErrMsg = "FlushInstructionCache failed with OS error " +
                    std::to_string(GetLastError());
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
    }

    // Apply ROData permissions (PAGE_READONLY)
    size_t ROUsed = Res->GroupCursors[1] - Res->GroupOffsets[1];
    if (ROUsed > 0) {
      size_t AlignedROUsed = 0;
      checkedRoundUp(ROUsed, PageSize, AlignedROUsed);
      // Ensure the complete used prefix is committed before calling
      // VirtualProtect
      if ((Faults & FaultVirtualAllocCommit) ||
          !VirtualAlloc(Res->Base + Res->GroupOffsets[1], AlignedROUsed,
                        MEM_COMMIT, PAGE_READWRITE)) {
        if (ErrMsg)
          *ErrMsg = "VirtualAlloc MEM_COMMIT failed for RO data prefix with OS "
                    "error " +
                    std::to_string(GetLastError());
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
      DWORD OldProt = 0;
      if ((Faults & FaultVirtualProtectRO) ||
          !VirtualProtect(Res->Base + Res->GroupOffsets[1], AlignedROUsed,
                          PAGE_READONLY, &OldProt)) {
        if (ErrMsg)
          *ErrMsg = "VirtualProtect PAGE_READONLY failed with OS error " +
                    std::to_string(GetLastError());
        FinalizationFailed = true;
        if (ErrMsg)
          FinalizationErrMsg = *ErrMsg;
        PendingUnwindTables.clear();
        return true;
      }
    }

    Res->Finalized = true;
  }

  // Also finalize any legacy-allocated sections
  if (SectionMemoryManager::finalizeMemory(ErrMsg)) {
    FinalizationFailed = true;
    if (ErrMsg)
      FinalizationErrMsg = *ErrMsg;
    PendingUnwindTables.clear();
    return true;
  }

  // Step 3: Publish Windows unwind tables with transactional rollback
  std::vector<UnwindTableEntry> NewlyRegistered;
  size_t RegisteredCount = 0;
  for (auto &Entry : PendingUnwindTables) {
    if (Entry.Size == 0)
      continue;

    size_t Count = Entry.Size / sizeof(RUNTIME_FUNCTION);
    auto *Records = reinterpret_cast<PRUNTIME_FUNCTION>(Entry.Addr);

    bool InjectFault =
        (Faults & FaultRtlAddFunctionTable) ||
        ((Faults & FaultRtlAddFunctionTableSecond) && (RegisteredCount >= 1));

#ifdef _WIN32
    BOOLEAN Success =
        InjectFault ? FALSE
                    : RtlAddFunctionTable(Records, static_cast<DWORD>(Count),
                                          Entry.ImageBase);
    if (!Success) {
      if (ErrMsg)
        *ErrMsg = "RtlAddFunctionTable returned error";
      if (!(Faults & FaultSkipRollbackDeregister)) {
        for (auto &R : NewlyRegistered) {
          RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
        }
      }
      NewlyRegistered.clear();
      PendingUnwindTables.clear();
      FinalizationFailed = true;
      if (ErrMsg)
        FinalizationErrMsg = *ErrMsg;
      return true;
    }
#else
    if (InjectFault) {
      if (ErrMsg)
        *ErrMsg = "RtlAddFunctionTable returned error";
      if (!(Faults & FaultSkipRollbackDeregister)) {
        for (auto &R : NewlyRegistered) {
          RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
        }
      }
      NewlyRegistered.clear();
      PendingUnwindTables.clear();
      FinalizationFailed = true;
      if (ErrMsg)
        FinalizationErrMsg = *ErrMsg;
      return true;
    }
#endif

    Entry.Registered = true;
    NewlyRegistered.push_back(Entry);
#ifdef LLVM_ENABLE_TEST_HOOKS
    if (FirstRegisteredUnwindAddress.load(std::memory_order_relaxed) == 0 &&
        Entry.Size >= sizeof(RUNTIME_FUNCTION) && Entry.Addr != nullptr) {
      const auto *RF = reinterpret_cast<const RUNTIME_FUNCTION *>(Entry.Addr);
      FirstRegisteredUnwindAddress.store(Entry.ImageBase + RF[0].BeginAddress,
                                         std::memory_order_relaxed);
    }
#endif
    ++RegisteredCount;
  }

  // Commit successfully registered tables to ActiveUnwindTables
  for (auto &R : NewlyRegistered) {
    ActiveUnwindTables.push_back(R);
  }
  PendingUnwindTables.clear();

  return false;
}

void WindowsMCJITMemoryManager::registerCOFFUnwindInfo(uint8_t *Addr,
                                                       uint64_t LoadAddr,
                                                       size_t Size,
                                                       uint64_t ImageBase) {
  if (FinalizationFailed)
    return;
#ifdef LLVM_ENABLE_TEST_HOOKS
  if (Size >= sizeof(RUNTIME_FUNCTION) && Addr != nullptr) {
    const auto *RF = reinterpret_cast<const RUNTIME_FUNCTION *>(Addr);
    LastUnwindProbeAddress.store(ImageBase + RF[0].BeginAddress,
                                 std::memory_order_relaxed);
  }
#endif
  PendingUnwindTables.push_back({Addr, LoadAddr, Size, ImageBase, false});
}

void WindowsMCJITMemoryManager::registerEHFrames(uint8_t *Addr,
                                                 uint64_t LoadAddr,
                                                 size_t Size) {
  registerCOFFUnwindInfo(Addr, LoadAddr, Size, LoadAddr);
}

void WindowsMCJITMemoryManager::deregisterEHFrames() {
#ifdef _WIN32
  for (auto &Table : ActiveUnwindTables) {
    if (Table.Registered) {
      RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(Table.Addr));
      Table.Registered = false;
    }
  }
#endif
  ActiveUnwindTables.clear();
  SectionMemoryManager::deregisterEHFrames();
}

} // namespace llvm
