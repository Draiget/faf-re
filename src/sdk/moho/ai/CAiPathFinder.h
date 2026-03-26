#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/IPathTraveler.h"
#include "moho/sim/SFootprint.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  class COGrid;
  class Sim;
  class Unit;

  struct SRectListRuntime
  {
    void* mAllocatorOrProxy; // +0x00
    void* mHead;             // +0x04 (intrusive sentinel node)
    std::int32_t mSize;      // +0x08
  };

  static_assert(sizeof(SRectListRuntime) == 0x0C, "SRectListRuntime size must be 0x0C");

  /**
   * Runtime path-grid cell payload used by land path callbacks.
   *
   * Evidence:
   * - FUN_005AA9A0 / FUN_005AA9F0 consume path arrays as packed 4-byte cells.
   * - FUN_005A9D50 / FUN_005AA850 copy one dword cell payload by address.
   */
  struct HPathCell
  {
    std::uint16_t x;
    std::uint16_t z;
  };

  /**
   * Recovered request mode latch used by CAiPathFinder.
   */
  enum EAiPathSearchType : std::int32_t
  {
    AIPATHSEARCH_None = 0,
    AIPATHSEARCH_Initial = 1,
    AIPATHSEARCH_Repath = 2,
    AIPATHSEARCH_Leader = 3,
  };

  /**
   * VFTABLE: 0x00E1C338
   * COL:  0x00E72290
   *
   * Recovered complete-object layout size: 0x7C.
   */
  class CAiPathFinder : public IPathTraveler, public Broadcaster
  {
  public:
    /**
     * Address: 0x005A9EC0 (FUN_005A9EC0)
     *
     * What it does:
     * Initializes pathfinder runtime state, broadcaster links, and search-history list sentinel.
     */
    CAiPathFinder();

    /**
     * Address: 0x005AA000 (FUN_005AA000)
     *
     * What it does:
     * Clears runtime search state and releases search-history list nodes/sentinel.
     */
    ~CAiPathFinder();

    /**
     * Address: 0x005AA060 (FUN_005AA060)
     *
     * What it does:
     * Binds owning unit/sim/army pathing sidecars and refreshes footprint + pathcap layer metadata.
     */
    void SetUnit(Unit* unit);

    /**
     * Address: 0x005AA120 (FUN_005AA120)
     *
     * What it does:
     * Replaces the active goal rectangle and recomputes border-probe gate flags.
     */
    void SetGoal(const SAiNavigatorGoal& goal);

    /**
     * Address: 0x005AA220 (FUN_005AA220)
     *
     * What it does:
     * Executes one direct probe step and updates goal/footprint in-bounds flags.
     */
    [[nodiscard]]
    bool RunDirectProbe();

    /**
     * Address: 0x005AA310 (FUN_005AA310)
     *
     * What it does:
     * Queues one path search request and updates short rolling search-rect history.
     */
    void QueueSearch();

    /**
     * Address: 0x005A9D30 (FUN_005A9D30)
     *
     * What it does:
     * Returns active footprint (alternate footprint while unit uses alternate footprint mode).
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    const SFootprint* GetFootprint() const override;

    /**
     * Address: 0x005AA710 (FUN_005AA710)
     *
     * What it does:
     * Tests whether one candidate cell can be traversed for current search constraints.
     *
     * VFTable SLOT: 1
     */
    [[nodiscard]]
    bool CanTraverseCell(const SOCellPos& cellPos) const override;

    /**
     * Address: 0x005AA680 (FUN_005AA680)
     *
     * What it does:
     * Applies playable-rect bounds checks for a candidate cell using active footprint radius.
     *
     * VFTable SLOT: 2
     */
    [[nodiscard]]
    bool IsInBounds(const SOCellPos& cellPos) const override;

    /**
     * Address: 0x005AA590 (FUN_005AA590)
     *
     * What it does:
     * Returns weighted distance from a cell to the current outer goal rectangle.
     */
    [[nodiscard]]
    float GetHeuristicCost(const SOCellPos& cellPos) const override;

    /**
     * Address: 0x005AA850 (FUN_005AA850)
     *
     * What it does:
     * Returns the current anchor cell used by path search.
     */
    void GetAnchorCell(HPathCell* outCell) const override;

    /**
     * Address: 0x005AA960 (FUN_005AA960)
     *
     * What it does:
     * Checks whether a cell lies in the outer goal but outside the inner completion rect.
     */
    [[nodiscard]]
    bool IsGoalCandidateCell(const SOCellPos& cellPos) const override;

    /**
     * Address: 0x005AA9A0 (FUN_005AA9A0)
     *
     * What it does:
     * Accepts an incoming path payload and updates latest result cell + listener broadcast state.
     */
    void OnPathAccepted(const SNavPath& path) override;

    /**
     * Address: 0x005AA860 (FUN_005AA860)
     *
     * What it does:
     * Tests whether a rectangle candidate intersects current goal/search constraints.
     */
    [[nodiscard]]
    bool ShouldSearchRect(const gpg::Rect2i& rect) const override;

    /**
     * Address: 0x005AA9E0 (FUN_005AA9E0)
     *
     * What it does:
     * Clears path-result and queue flags after a cancelled search step.
     */
    void OnPathSearchCancelled() override;

    /**
     * Address: 0x005AA9F0 (FUN_005AA9F0)
     *
     * What it does:
     * Stores latest result cell from a rejected path payload and clears result-ready flag.
     */
    void OnPathRejected(const SNavPath& path) override;

    /**
     * Address: 0x005AAA30 (FUN_005AAA30)
     *
     * What it does:
     * Resolves pathcap mask for current search context.
     */
    [[nodiscard]]
    std::int32_t GetPathcap() const override;

    /**
     * Address: 0x005A9D50 (FUN_005A9D50)
     *
     * What it does:
     * Returns latest result cell payload.
     */
    void GetResultCell(HPathCell* outCell) const override;

  private:
    void ClearRectHistory();
    void PushRectHistory(const gpg::Rect2i& rect);
    void BroadcastPathEvent();
    void UpdatePlayableRectGate();
    [[nodiscard]] bool RectHistoryIntersects(const gpg::Rect2i& rect) const;
    [[nodiscard]] bool IsBlockedByHistory(const SOCellPos& cellPos) const;
    [[nodiscard]] static bool IsStrictRect(const gpg::Rect2i& rect);
    [[nodiscard]] static bool CellInRectInclusiveExclusive(const SOCellPos& cellPos, const gpg::Rect2i& rect);
    [[nodiscard]] static bool RectsOverlapStrict(const gpg::Rect2i& lhs, const gpg::Rect2i& rhs);
    [[nodiscard]] static bool RectInsideRect(const gpg::Rect2i& inner, const gpg::Rect2i& outer);
    [[nodiscard]] static gpg::Rect2i GoalOuterRect(const SAiNavigatorGoal& goal);
    [[nodiscard]] static gpg::Rect2i GoalInnerRect(const SAiNavigatorGoal& goal);
    [[nodiscard]] static HPathCell LastPathCell(const SNavPath& path);

  public:
    static gpg::RType* sType;

    std::uint8_t mIsGoalBoundaryBlocked; // +0x14
    std::uint8_t mIsQueuedOnPathQueue;   // +0x15
    std::uint8_t mUseGoalBoundaryProbe;  // +0x16
    std::uint8_t mPad17;                 // +0x17
    Unit* mUnit;                         // +0x18
    const SFootprint* mFootprint;        // +0x1C
    const SFootprint* mAltFootprint;     // +0x20
    std::int32_t mPathLayerSelector;     // +0x24 (RUnitBlueprintPhysics::MotionType)
    Sim* mSim;                           // +0x28
    void* mPathQueueProxy;               // +0x2C (army path queue/pathfinder object)
    COGrid* mOGrid;                      // +0x30
    HPathCell mAnchorCell;               // +0x34
    HPathCell mResultCell;               // +0x38
    SAiNavigatorGoal mGoal;              // +0x3C
    EAiPathSearchType mSearchType;       // +0x60
    std::uint8_t mHasOccupancyMask;      // +0x64
    std::uint8_t mHasPathResult;         // +0x65
    std::uint8_t mPad66;                 // +0x66
    std::uint8_t mPad67;                 // +0x67
    SRectListRuntime mRecentSearchRects; // +0x68
    std::uint8_t mUseWholeMap;           // +0x74
    std::uint8_t mInsidePlayableRect;    // +0x75
    std::uint8_t mPad76;                 // +0x76
    std::uint8_t mPad77;                 // +0x77
    std::uint32_t mMaxFootprintSpan;     // +0x78
  };

  static_assert(sizeof(HPathCell) == 0x04, "HPathCell size must be 0x04");
  static_assert(sizeof(CAiPathFinder) == 0x7C, "CAiPathFinder size must be 0x7C");
  static_assert(
    offsetof(CAiPathFinder, mIsGoalBoundaryBlocked) == 0x14,
    "CAiPathFinder::mIsGoalBoundaryBlocked offset must be 0x14"
  );
  static_assert(offsetof(CAiPathFinder, mUnit) == 0x18, "CAiPathFinder::mUnit offset must be 0x18");
  static_assert(offsetof(CAiPathFinder, mFootprint) == 0x1C, "CAiPathFinder::mFootprint offset must be 0x1C");
  static_assert(offsetof(CAiPathFinder, mAltFootprint) == 0x20, "CAiPathFinder::mAltFootprint offset must be 0x20");
  static_assert(
    offsetof(CAiPathFinder, mPathLayerSelector) == 0x24,
    "CAiPathFinder::mPathLayerSelector offset must be 0x24"
  );
  static_assert(offsetof(CAiPathFinder, mSim) == 0x28, "CAiPathFinder::mSim offset must be 0x28");
  static_assert(offsetof(CAiPathFinder, mPathQueueProxy) == 0x2C, "CAiPathFinder::mPathQueueProxy offset must be 0x2C");
  static_assert(offsetof(CAiPathFinder, mOGrid) == 0x30, "CAiPathFinder::mOGrid offset must be 0x30");
  static_assert(offsetof(CAiPathFinder, mAnchorCell) == 0x34, "CAiPathFinder::mAnchorCell offset must be 0x34");
  static_assert(offsetof(CAiPathFinder, mResultCell) == 0x38, "CAiPathFinder::mResultCell offset must be 0x38");
  static_assert(offsetof(CAiPathFinder, mGoal) == 0x3C, "CAiPathFinder::mGoal offset must be 0x3C");
  static_assert(offsetof(CAiPathFinder, mSearchType) == 0x60, "CAiPathFinder::mSearchType offset must be 0x60");
  static_assert(
    offsetof(CAiPathFinder, mHasOccupancyMask) == 0x64, "CAiPathFinder::mHasOccupancyMask offset must be 0x64"
  );
  static_assert(
    offsetof(CAiPathFinder, mHasPathResult) == 0x65, "CAiPathFinder::mHasPathResult offset must be 0x65"
  );
  static_assert(
    offsetof(CAiPathFinder, mRecentSearchRects) == 0x68, "CAiPathFinder::mRecentSearchRects offset must be 0x68"
  );
  static_assert(offsetof(CAiPathFinder, mUseWholeMap) == 0x74, "CAiPathFinder::mUseWholeMap offset must be 0x74");
  static_assert(
    offsetof(CAiPathFinder, mInsidePlayableRect) == 0x75, "CAiPathFinder::mInsidePlayableRect offset must be 0x75"
  );
  static_assert(
    offsetof(CAiPathFinder, mMaxFootprintSpan) == 0x78, "CAiPathFinder::mMaxFootprintSpan offset must be 0x78"
  );
} // namespace moho
