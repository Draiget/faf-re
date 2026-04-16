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
     */
    [[nodiscard]]
    virtual bool IsInBounds(const SOCellPos& cellPos) const = 0;

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
