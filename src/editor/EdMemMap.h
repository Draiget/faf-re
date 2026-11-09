#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

namespace faf::editor::memmap
{
  /**
   * Where the process's committed memory is, read from the address space (board task WPE.16): which
   * Win32 heap, thread stack or direct allocation each committed private page belongs to. Two of these,
   * taken after two plays, show which part a play leaves behind when `/memtrace` (the engine heap) shows
   * nothing. Taking one walks every heap, so it is for the memory check after a play only.
   */
  struct Snapshot
  {
    /** Committed bytes of each Win32 heap, by heap handle. */
    std::map<std::uintptr_t, std::size_t> heaps;
    /** Committed private bytes of each allocation that no heap and no thread stack owns, by its base. */
    std::map<std::uintptr_t, std::size_t> loose;
    /** The page protection of each of those allocations' first committed page. */
    std::map<std::uintptr_t, unsigned long> looseProtect;
    /** The address range each of those allocations reserves, committed or not. */
    std::map<std::uintptr_t, std::size_t> looseReserved;
    std::uintptr_t processHeap = 0;
    std::size_t privateTotal = 0;
    std::size_t stacks = 0;
    std::size_t mapped = 0;
    std::size_t image = 0;
    unsigned long threads = 0;
    unsigned long handles = 0;
    unsigned long gdiObjects = 0;
    unsigned long userObjects = 0;
  };

  [[nodiscard]] Snapshot Take();

  /** Logs `after`'s totals, and what grew or shrank since `before` by heap and by direct allocation. */
  void LogChanges(const Snapshot& before, const Snapshot& after);
} // namespace faf::editor::memmap
