#pragma once
#include <cstdint>

#include "gpg/core/containers/Rect2.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  struct PathTablesImpl;

  /**
   * Recovered placeholder for `Moho::PathQueue` — used by
   * `gpg::RRef_PathQueue` (FUN_005ACCA0) and as a forward-declared type
   * referenced by `gpg::ReadArchive` and several path-finder lanes.
   * The complete-object size and field layout have not yet been
   * confirmed from binary evidence; the class is given a single
   * `std::uintptr_t` body so it remains a complete C++ type for
   * `typeid()` use.
   *
   * Note: the binary's `PathQueue::DirtyClusters` method is currently
   * recovered on the sibling `PathTables::DirtyClusters` slot — those
   * may be the same class with two decompiler-pass names.
   */
  class PathQueue
  {
  public:
    static gpg::RType* sType;

  private:
    std::uintptr_t mPlaceholderState{};
  };

  class PathTables
  {
  public:
    /**
     * Address: 0x0076BAC0 (FUN_0076BAC0, ??1PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases all per-footprint cluster maps, tears down the impl payload, and frees impl storage.
     */
    ~PathTables();

    /**
     * Address: 0x0076BC10 (FUN_0076BC10)
     *
     * int *
     *
     * IDA signature:
     * int __userpurge sub_76BC10@<eax>(int a1@<edi>, int *budget);
     *
     * What it does:
     * Updates path occupation sources using the supplied background budget.
     */
    void UpdateBackground(int* budget);

    /**
     * Address: 0x0076BBD0 (FUN_0076BBD0, Moho::PathQueue::DirtyClusters)
     *
     * gpg::Rect2i *
     *
     * IDA signature:
     * void __userpurge Moho::PathQueue::DirtyClusters(Moho::PathQueue *a1@<ebx>, gpg::Rect2i *a2);
     *
     * What it does:
     * Marks all registered path cluster maps dirty for the supplied rect.
     */
    void DirtyClusters(const gpg::Rect2i& dirtyRect);

  private:
    // Runtime path-table implementation payload (PathTables::Impl).
    PathTablesImpl* mImpl;
  };

  static_assert(sizeof(PathTables) == 0x4, "PathTables size must be 0x4");
} // namespace moho
