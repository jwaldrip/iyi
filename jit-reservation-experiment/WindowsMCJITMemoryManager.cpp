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

  // Max signed 32-bit reach for x86-64 intra-object REL32 relocations (2 GiB)
  constexpr size_t MaxSignedRelativeSpan = 0x7FFF0000ULL;
  if (TotalSpan > MaxSignedRelativeSpan)
    return; // Fall back to checked legacy allocation for wide layouts

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

  // Commit used pages RW
  uintptr_t CommitStart =
      (reinterpret_cast<uintptr_t>(CurrentReservation->Base + Pos)) &
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
  for (auto &Res : Reservations) {
    if (!Res || Res->Finalized || !Res->Base)
      continue;

    // Apply Code permissions (PAGE_EXECUTE_READ)
    size_t CodeUsed = Res->GroupCursors[0] - Res->GroupOffsets[0];
    if (CodeUsed > 0) {
      size_t AlignedCodeUsed = 0;
      checkedRoundUp(CodeUsed, PageSize, AlignedCodeUsed);
      DWORD OldProt = 0;
      if (!VirtualProtect(Res->Base + Res->GroupOffsets[0], AlignedCodeUsed,
                          PAGE_EXECUTE_READ, &OldProt)) {
        if (ErrMsg)
          *ErrMsg = "VirtualProtect PAGE_EXECUTE_READ failed with OS error " +
                    std::to_string(GetLastError());
        return true;
      }
      if (!FlushInstructionCache(GetCurrentProcess(),
                                 Res->Base + Res->GroupOffsets[0],
                                 AlignedCodeUsed)) {
        if (ErrMsg)
          *ErrMsg = "FlushInstructionCache failed with OS error " +
                    std::to_string(GetLastError());
        return true;
      }
    }

    // Apply ROData permissions (PAGE_READONLY)
    size_t ROUsed = Res->GroupCursors[1] - Res->GroupOffsets[1];
    if (ROUsed > 0) {
      size_t AlignedROUsed = 0;
      checkedRoundUp(ROUsed, PageSize, AlignedROUsed);
      DWORD OldProt = 0;
      if (!VirtualProtect(Res->Base + Res->GroupOffsets[1], AlignedROUsed,
                          PAGE_READONLY, &OldProt)) {
        if (ErrMsg)
          *ErrMsg = "VirtualProtect PAGE_READONLY failed with OS error " +
                    std::to_string(GetLastError());
        return true;
      }
    }

    Res->Finalized = true;
  }

  // Also finalize any legacy-allocated sections
  if (SectionMemoryManager::finalizeMemory(ErrMsg))
    return true;

  // Publish Windows unwind tables after memory protections and cache flushes
  // succeed
  std::vector<UnwindTableEntry> NewlyRegistered;
  for (auto &Entry : PendingUnwindTables) {
    if (Entry.Size == 0)
      continue;

    constexpr size_t RecordSize = sizeof(RUNTIME_FUNCTION);
    if (Entry.Size % RecordSize != 0) {
      if (ErrMsg)
        *ErrMsg = ".pdata section size is not an integral number of "
                  "RUNTIME_FUNCTION records";
      for (auto &R : NewlyRegistered) {
#ifdef _WIN32
        RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
#endif
      }
      return true;
    }

    size_t Count = Entry.Size / RecordSize;
    if (Count > std::numeric_limits<DWORD>::max()) {
      if (ErrMsg)
        *ErrMsg = ".pdata section record count exceeds 32-bit limit";
      for (auto &R : NewlyRegistered) {
#ifdef _WIN32
        RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
#endif
      }
      return true;
    }

    auto *Records = reinterpret_cast<PRUNTIME_FUNCTION>(Entry.Addr);
    for (size_t i = 0; i < Count; ++i) {
      if (Records[i].BeginAddress >= Records[i].EndAddress) {
        if (ErrMsg)
          *ErrMsg =
              "Invalid RUNTIME_FUNCTION record: BeginAddress >= EndAddress";
        for (auto &R : NewlyRegistered) {
#ifdef _WIN32
          RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
#endif
        }
        return true;
      }
    }

    // Sort records in ascending order by BeginAddress as required by Windows
    std::sort(Records, Records + Count,
              [](const RUNTIME_FUNCTION &a, const RUNTIME_FUNCTION &b) {
                return a.BeginAddress < b.BeginAddress;
              });

#ifdef _WIN32
    BOOLEAN Success = RtlAddFunctionTable(Records, static_cast<DWORD>(Count),
                                          Entry.ImageBase);
    if (!Success) {
      if (ErrMsg)
        *ErrMsg = "RtlAddFunctionTable returned error";
      for (auto &R : NewlyRegistered) {
        RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(R.Addr));
      }
      return true;
    }
#endif

    Entry.Registered = true;
    NewlyRegistered.push_back(Entry);
    ActiveUnwindTables.push_back(Entry);
  }
  PendingUnwindTables.clear();

  return false;
}

void WindowsMCJITMemoryManager::registerEHFrames(uint8_t *Addr,
                                                 uint64_t LoadAddr,
                                                 size_t Size) {
  registerCOFFUnwindInfo(Addr, LoadAddr, Size, LoadAddr);
}

void WindowsMCJITMemoryManager::registerCOFFUnwindInfo(uint8_t *Addr,
                                                       uint64_t LoadAddr,
                                                       size_t Size,
                                                       uint64_t ImageBase) {
  PendingUnwindTables.push_back({Addr, LoadAddr, Size, ImageBase, false});
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
