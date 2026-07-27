#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/Rect2.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/containers/TDatList.h"
#include "moho/sim/SFootprint.h"

namespace moho
{
  struct HPathCell;

  /**
   * PathQueue traveler interface used by CAiPathFinder.
   * The intrusive queue node is linked/unlinked by path queue dispatch.
   */
  class IPathTraveler
  {
  public:
    /**
     * Address: 0x005A9F80 (FUN_005A9F80)
     *
     * What it does:
     * Initializes one detached path-traveler queue node.
     */
    IPathTraveler();

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual const SFootprint* GetFootprint() const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual bool CanTraverseCell(const SOCellPos& cellPos) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     *
     * Edge-admission hook, called once per candidate step during expansion.
     * `edgeCost` arrives holding the geometric cost of the step and may be
     * adjusted; returning false drops the edge.
     *
     * The three-parameter shape is pinned by the two dispatch sites in the
     * neighbour enumerator (0x00766350): both pass the cell being expanded,
     * the candidate cell, and a pointer to the running cost. An earlier
     * reconstruction declared this slot as `IsInBounds(const SOCellPos&)`,
     * which silently bound the *source* cell to the parameter the only
     * override actually tests.
     */
    [[nodiscard]]
    virtual bool IsInBounds(const SOCellPos& fromCell, const SOCellPos& toCell, float* edgeCost) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual float GetHeuristicCost(const SOCellPos& cellPos) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    virtual void GetAnchorCell(HPathCell* outCell) const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual bool IsGoalCandidateCell(const SOCellPos& cellPos) const = 0;

    /**
     * Address: 0x005A9C60 (FUN_005A9C60)
     *
     * What it does:
     * Default no-op hook for accepted path payloads.
     */
    virtual void OnPathAccepted(const SNavPath& path);

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual bool ShouldSearchRect(const gpg::Rect2i& rect) const = 0;

    /**
     * Address: 0x005A9C70 (FUN_005A9C70)
     *
     * What it does:
     * Default no-op hook for cancelled path searches.
     */
    virtual void OnPathSearchCancelled();

    /**
     * Address: 0x005A9C80 (FUN_005A9C80)
     *
     * What it does:
     * Default no-op hook for rejected path payloads.
     */
    virtual void OnPathRejected(const SNavPath& path);

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    [[nodiscard]]
    virtual std::int32_t GetPathcap() const = 0;

    /**
     * Address: 0x00A82547 (_purecall in FA binary)
     */
    virtual void GetResultCell(HPathCell* outCell) const = 0;

  public:
    TDatListItem<void, void> mPathQueueNode;
  };

  static_assert(sizeof(IPathTraveler) == 0x0C, "IPathTraveler size must be 0x0C");
  static_assert(offsetof(IPathTraveler, mPathQueueNode) == 0x04, "IPathTraveler::mPathQueueNode offset must be 0x04");
} // namespace moho
