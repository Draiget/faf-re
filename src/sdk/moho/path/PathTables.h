#pragma once
#include <cstdint>

#include "boost/scoped_ptr.h"
#include "gpg/core/containers/Rect2.h"

namespace gpg
{
  class RRef;
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace gpg::HaStar
{
  class ClusterMap;
} // namespace gpg::HaStar

namespace moho
{
  class COGrid;
  class IPathTraveler;
  class PathTables;
  struct SRuleFootprintsBlueprint;

  /**
   * `Moho::PathQueue` - one army's path-search queue.
   *
   * Travelers queue up on `Impl::mPendingTravelers`; `Work` serves them one at
   * a time through the A* state in `Impl::mBase`, a slice of CPU budget per
   * sim tick. The queue itself is only the owning pointer: `Impl` is private
   * to PathTables.cpp.
   */
  class PathQueue
  {
  public:
    static gpg::RType* sType;

    struct Impl;
    struct ImplBase;

    /**
     * What it does:
     * An empty queue with no `Impl`: the form reflection builds before a load
     * installs one. Inlined into `PathQueueTypeInfo::NewRef` (0x007678C0) and
     * `::CtrRef` (0x00767950).
     */
    PathQueue() = default;

    /**
     * Address: 0x00765D30 (FUN_00765D30, ??0PathQueue@Moho@@QA@Z)
     *
     * What it does:
     * Allocates the `Impl` and records the `PathTables` it searches.
     */
    explicit PathQueue(PathTables* owner);

    /**
     * What it does:
     * Deletes the owned `Impl` (its implicit destructor releases the search
     * state, then the pending list). Inlined wherever a queue is deleted:
     * `PathQueue::Move` (0x00701AE1), `PathQueueTypeInfo::Delete`
     * (0x00767900) and `::Destruct` (0x0076799C, which leaves `mImpl` as
     * it was).
     */
    ~PathQueue();

    PathQueue(const PathQueue&) = delete;
    PathQueue& operator=(const PathQueue&) = delete;

    /**
     * Address: 0x0076AD40 (FUN_0076AD40)
     *
     * IDA signature:
     * void __usercall sub_76AD40(int* slot@<eax>, gpg::ReadArchive* archive@<ebx>);
     *
     * What it does:
     * Reads the owned `Impl` and installs it, deleting the one it replaces
     * (`scoped_ptr::reset`: the new pointer is stored before the old one is
     * deleted).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * What it does:
     * Writes the `Impl` as an owned tracked pointer. Inlined into
     * `PathQueueSerializer::Serialize` (0x00766980).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00765ED0 (FUN_00765ED0, Moho::PathQueue::Work)
     *
     * IDA signature:
     * void __usercall Moho::PathQueue::Work(Moho::PathQueue *this@<ebx>, int *budget@<esi>);
     *
     * What it does:
     * Serves queued path travellers until `budget` is spent, decrementing it by
     * the work actually performed.
     */
    void Work(int& budget);

    /**
     * Address: 0x00765DD0 (FUN_00765DD0)
     *
     * IDA signature:
     * void __userpurge sub_765DD0(int *pBudget@<esi>, Moho::PathQueue *arg0, Moho::CAiPathFinder *a2);
     *
     * What it does:
     * Runs one path query for `traveller` to completion right now, on scratch
     * search state, without disturbing the queue's own in-flight work.
     */
    void WorkImmediate(int& budget, IPathTraveler& traveller);

    /**
     * Address: 0x005AA318..0x005AA345 (inlined into Moho::CAiPathFinder::QueueSearch, FUN_005AA310)
     *
     * What it does:
     * Unlinks `traveller`'s path-queue node from wherever it sits and appends
     * it to this queue's pending ring (the `mHeightSentinel` list `Work`
     * drains). Nothing else enqueues a search: without this, `Work` never
     * sees a traveler and every navigator waits at `AIPATHNAVSTATE_PathEvent3`.
     */
    void QueueTraveler(IPathTraveler& traveller);

    /**
     * Address: 0x00701AD0 (FUN_00701AD0, Moho::PathQueue::Move)
     *
     * What it does:
     * Stores `replacement` in the owner's slot, then deletes the queue it
     * replaced.
     */
    static void Move(PathQueue** slot, PathQueue* replacement) noexcept;

  private:
    boost::scoped_ptr<Impl> mImpl;
  };
  static_assert(sizeof(PathQueue) == 0x04, "PathQueue size must be 0x04");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0076A5F0 (FUN_0076A5F0, gpg::RRef_PathQueue_Impl)
   *
   * What it does:
   * Wraps a `PathQueue::Impl*` as a reflected reference. Declared here rather
   * than beside `RRef_PathQueue` in Reflection.h because only this header can
   * name the nested type; defined in gpg/core/containers/ArchiveSerialization.cpp.
   */
  RRef* RRef_PathQueue_Impl(RRef* outRef, moho::PathQueue::Impl* value);
} // namespace gpg

namespace moho
{

  class PathTables
  {
  public:
    struct Impl;

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

    /**
     * Address: 0x00766047 (inlined into the query-setup lane at 0x00765FE0)
     *
     * What it does:
     * Returns the cluster map built for one footprint index. Each distinct
     * footprint gets its own hierarchy, because what counts as passable
     * terrain depends on the unit's size and movement class.
     */
    [[nodiscard]] gpg::HaStar::ClusterMap* ClusterMapForFootprint(std::int32_t footprintIndex) const;

  private:
    Impl* mImpl;
  };

  static_assert(sizeof(PathTables) == 0x4, "PathTables size must be 0x4");
} // namespace moho
