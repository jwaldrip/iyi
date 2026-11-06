//===- WindowsMCJITMemoryManager.h - Memory manager for Windows MCJIT -*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Memory manager for Windows x86_64 MCJIT supporting dynamic packed
// reservations without a fixed cap, per-object unwind registration with
// RtlAddFunctionTable, and safe release-mode range validation.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_EXECUTIONENGINE_WINDOWSMCJITMEMORYMANAGER_H
#define LLVM_EXECUTIONENGINE_WINDOWSMCJITMEMORYMANAGER_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/Support/Alignment.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace llvm {

class WindowsMCJITMemoryManager : public SectionMemoryManager {
public:
  WindowsMCJITMemoryManager();
  ~WindowsMCJITMemoryManager() override;

  bool needsToReserveAllocationSpace() override { return true; }

  void reserveAllocationSpace(uintptr_t CodeSize, Align CodeAlign,
                              uintptr_t RODataSize, Align RODataAlign,
                              uintptr_t RWDataSize, Align RWDataAlign) override;

  uint8_t *allocateCodeSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID,
                               StringRef SectionName) override;

  uint8_t *allocateDataSection(uintptr_t Size, unsigned Alignment,
                               unsigned SectionID, StringRef SectionName,
                               bool IsReadOnly) override;

  bool finalizeMemory(std::string *ErrMsg = nullptr) override;

  void registerEHFrames(uint8_t *Addr, uint64_t LoadAddr, size_t Size) override;

  void registerCOFFUnwindInfo(uint8_t *Addr, uint64_t LoadAddr, size_t Size,
                              uint64_t ImageBase) override;

  void deregisterEHFrames() override;

private:
  struct PackedReservation {
    uint8_t *Base = nullptr;
    size_t TotalReserved = 0;
    size_t GroupOffsets[3] = {};
    size_t GroupSizes[3] = {};
    size_t GroupCursors[3] = {};
    size_t GroupEnds[3] = {};
    bool Finalized = false;
  };

  struct UnwindTableEntry {
    uint8_t *Addr = nullptr;
    uint64_t LoadAddr = 0;
    size_t Size = 0;
    uint64_t ImageBase = 0;
    bool Registered = false;
  };

  size_t PageSize = 4096;
  size_t AllocGranularity = 65536;

  std::vector<std::unique_ptr<PackedReservation>> Reservations;
  PackedReservation *CurrentReservation = nullptr;

  std::vector<UnwindTableEntry> PendingUnwindTables;
  std::vector<UnwindTableEntry> ActiveUnwindTables;

  uint8_t *allocateFromReservation(int Group, uintptr_t Size,
                                   unsigned Alignment, unsigned SectionID,
                                   StringRef SectionName);
};

} // namespace llvm

#endif // LLVM_EXECUTIONENGINE_WINDOWSMCJITMEMORYMANAGER_H
