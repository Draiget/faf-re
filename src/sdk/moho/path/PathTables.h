#pragma once
#include <cstdint>

#include "gpg/core/containers/Rect2.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  class COGrid;
  struct SRuleFootprintsBlueprint;
  struct PathTablesImpl;

  /**
   * Runtime queue owner used by per-army pathfinder lanes.
   *
   * Layout evidence currently confirms the outer pointer-sized owner and
   * constructor behavior. Deeper `Impl` payload fields are reconstructed in
   * `PathTables.cpp` from the `FUN_00765B20/FUN_00765B90/FUN_00766CE0`
   * constructor chain.
   */
  class PathQueue
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00765D30 (FUN_00765D30, ??0PathQueue@Moho@@QA@Z)
     *
     * What it does:
     * Allocates one `PathQueue::Impl` payload and stores the caller-supplied
     * queue-size lane in the impl header.
     */
    explicit PathQueue(int size);

    /**
     * Address: 0x00701AD0 (FUN_00701AD0, Moho::PathQueue::Move)
     *
     * What it does:
     * Replaces one owner slot with a new queue pointer, then tears down and
     * frees the previous queue payload when present.
     */
    static void Move(PathQueue** slot, PathQueue* replacement) noexcept;

    struct Impl;

  private:
    Impl* mImpl{};
  };
  static_assert(sizeof(PathQueue) == 0x04, "PathQueue size must be 0x04");

  class PathTables
  {
  public:
    /**
     * Address: 0x0076B8C0 (FUN_0076B8C0, ??0PathTables@Moho@@QAE@@Z)
     *
     * What it does:
     * Builds per-footprint occupation-source bindings and cluster-map lanes
     * for one `(width,height)` grid.
     */
    PathTables(const SRuleFootprintsBlueprint& footprints, COGrid* grid, int width, int height);

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
