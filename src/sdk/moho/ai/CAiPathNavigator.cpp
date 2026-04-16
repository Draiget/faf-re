#include "moho/ai/CAiPathNavigator.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/entity/Entity.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr std::uint64_t kUnitPathFlag = 0x1000000ull;
  constexpr std::uint64_t kUnitPathingBusyFlag = 0x800000ull;
  constexpr std::uint64_t kUnitPatrolStallFlag = 0x2000000ull;

  gpg::RType* gNavigatorStateType = nullptr;
  gpg::RType* gPathFinderType = nullptr;
  gpg::RType* gNavPathType = nullptr;
  gpg::RType* gHPathCellType = nullptr;
  gpg::RType* gNavGoalType = nullptr;
  gpg::RType* gLayerType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gWeakUnitType = nullptr;
  gpg::RType* gVector3Type = nullptr;
  gpg::RType* gSearchType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedNavigatorStateType()
  {
    return CachedType<EAiPathNavigatorState>(gNavigatorStateType);
  }

  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    if (!CAiPathFinder::sType) {
      CAiPathFinder::sType = CachedType<CAiPathFinder>(gPathFinderType);
    }
    return CAiPathFinder::sType;
  }

  [[nodiscard]] gpg::RType* CachedNavPathType()
  {
    return CachedType<SNavPath>(gNavPathType);
  }

  [[nodiscard]] gpg::RType* CachedHPathCellType()
  {
    return CachedType<HPathCell>(gHPathCellType);
  }

  [[nodiscard]] gpg::RType* CachedNavGoalType()
  {
    return CachedType<SAiNavigatorGoal>(gNavGoalType);
  }

  [[nodiscard]] gpg::RType* CachedLayerType()
  {
    return CachedType<ELayer>(gLayerType);
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!Sim::sType) {
      Sim::sType = CachedType<Sim>(gSimType);
    }
    return Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedWeakUnitType()
  {
    return CachedType<WeakPtr<Unit>>(gWeakUnitType);
  }

  [[nodiscard]] gpg::RType* CachedVector3Type()
  {
    return CachedType<Wm3::Vector3f>(gVector3Type);
  }

  [[nodiscard]] gpg::RType* CachedSearchType()
  {
    return CachedType<EAiPathSearchType>(gSearchType);
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(gpg::ReadArchive* const archive, const gpg::RRef& owner, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& owner
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }

  struct UnitLayerTokenView
  {
    std::uint8_t pad[0x120];
    std::uint32_t layerToken;
  };

  static_assert(offsetof(UnitLayerTokenView, layerToken) == 0x120, "UnitLayerTokenView::layerToken offset must be 0x120");

  /**
   * Address: 0x005AD0D0 (FUN_005AD0D0)
   *
   * What it does:
   * Writes one `(x, z)` word pair into a packed path-cell payload.
   */
  [[maybe_unused]] [[nodiscard]] HPathCell* WritePackedPathCellWordPair(
    HPathCell* const outCell,
    const std::uint16_t x,
    const std::uint16_t z
  ) noexcept
  {
    if (!outCell) {
      return nullptr;
    }

    outCell->x = x;
    outCell->z = z;
    return outCell;
  }

  /**
   * Address: 0x005AD190 (FUN_005AD190)
   *
   * What it does:
   * Stores one alt-footprint mode flag byte on a unit/entity object.
   */
  [[maybe_unused]] [[nodiscard]] Unit* WriteUnitAltFootprintFlag(
    Unit* const unit,
    const std::uint8_t enabled
  ) noexcept
  {
    if (!unit) {
      return nullptr;
    }

    unit->mUseAltFootprint = enabled;
    return unit;
  }

  [[nodiscard]] bool HasVectorValue(const Wm3::Vector3f& vec) noexcept
  {
    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    return Wm3::Vector3f::Compare(&vec, &zero);
  }

  [[nodiscard]] bool HasGoalArea(const SAiNavigatorGoal& goal) noexcept
  {
    return goal.minX < goal.maxX && goal.minZ < goal.maxZ;
  }

  [[nodiscard]] SOCellPos ToCellPos(const Wm3::Vector3f& position, const SFootprint& footprint) noexcept
  {
    SOCellPos cell{};
    cell.x = static_cast<std::int16_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    cell.z = static_cast<std::int16_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));
    return cell;
  }

  [[nodiscard]] Wm3::Vector3f ToWorldPos(const SOCellPos& cellPos, const Unit& unit, const SFootprint& footprint) noexcept
  {
    const Wm3::Vector3f unitPos = unit.GetPosition();
    return {
      static_cast<float>(cellPos.x) + (static_cast<float>(footprint.mSizeX) * 0.5f),
      unitPos.y,
      static_cast<float>(cellPos.z) + (static_cast<float>(footprint.mSizeZ) * 0.5f),
    };
  }

  [[nodiscard]] SOCellPos GoalAnchorCell(const SAiNavigatorGoal& goal) noexcept
  {
    return {
      static_cast<std::int16_t>(goal.minX),
      static_cast<std::int16_t>(goal.minZ),
    };
  }

  [[nodiscard]] SOCellPos GoalCenterCell(const SAiNavigatorGoal& goal) noexcept
  {
    return {
      static_cast<std::int16_t>((goal.minX + goal.maxX) / 2),
      static_cast<std::int16_t>((goal.minZ + goal.maxZ) / 2),
    };
  }

  [[nodiscard]] SAiNavigatorGoal BuildSingleCellGoal(const SOCellPos& cell) noexcept
  {
    SAiNavigatorGoal goal{};
    goal.minX = static_cast<std::int32_t>(cell.x);
    goal.minZ = static_cast<std::int32_t>(cell.z);
    goal.maxX = static_cast<std::int32_t>(cell.x) + 1;
    goal.maxZ = static_cast<std::int32_t>(cell.z) + 1;
    return goal;
  }

  [[nodiscard]] std::uint32_t PackCell(const SOCellPos& cell) noexcept
  {
    std::uint32_t packed = 0;
    std::memcpy(&packed, &cell, sizeof(packed));
    return packed;
  }

  /**
   * Address: 0x005B0880 (FUN_005B0880)
   *
   * What it does:
   * Compares one pair of heading-delta lanes and returns true when the lane
   * vectors differ.
   */
  [[nodiscard]] bool HeadingDeltaMismatch(const std::int32_t lhs[2], const std::int32_t rhs[2]) noexcept
  {
    return lhs[0] != rhs[0] || lhs[1] != rhs[1];
  }

  [[nodiscard]] Broadcaster* NavigatorListenerNode(CAiPathNavigator& navigator) noexcept
  {
    return &navigator.mListenerLink;
  }

  [[nodiscard]] Broadcaster* PathFinderListenerHead(CAiPathFinder* pathFinder) noexcept
  {
    if (!pathFinder) {
      return nullptr;
    }
    return static_cast<Broadcaster*>(pathFinder);
  }

  void DetachListenerNode(CAiPathNavigator& navigator) noexcept
  {
    NavigatorListenerNode(navigator)->ListUnlink();
  }

  void AttachListenerNodeToPathFinder(CAiPathNavigator& navigator) noexcept
  {
    Broadcaster* const node = NavigatorListenerNode(navigator);
    node->ListUnlink();

    Broadcaster* const head = PathFinderListenerHead(navigator.mPathFinder);
    if (!head) {
      return;
    }
    head->push_front(node);
  }

  void DetachWeakUnit(WeakPtr<Unit>& link) noexcept
  {
    link.ResetFromObject(nullptr);
  }

  [[nodiscard]] Unit* GetOwningUnit(const CAiPathNavigator& navigator) noexcept
  {
    return navigator.mPathFinder ? navigator.mPathFinder->mUnit : nullptr;
  }

  [[nodiscard]] const COGrid* GetPathingGrid(const CAiPathNavigator& navigator) noexcept
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (pathFinder && pathFinder->mOGrid) {
      return pathFinder->mOGrid;
    }

    return navigator.mSim ? navigator.mSim->mOGrid : nullptr;
  }

  [[nodiscard]] const Sim* GetPathingSim(const CAiPathNavigator& navigator) noexcept
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (pathFinder && pathFinder->mSim) {
      return pathFinder->mSim;
    }
    return navigator.mSim;
  }

  [[nodiscard]] const SFootprint* GetActiveFootprint(const CAiPathNavigator& navigator) noexcept
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (!pathFinder || !pathFinder->mUnit) {
      return nullptr;
    }
    return pathFinder->GetFootprint();
  }

  [[nodiscard]] std::uint32_t ReadUnitLayerToken(const Unit* const unit) noexcept
  {
    if (!unit) {
      return 0;
    }
    const auto* const view = reinterpret_cast<const UnitLayerTokenView*>(unit);
    return view->layerToken;
  }

  void ClearUnitPathBits(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask &= ~(kUnitPathFlag | kUnitPathingBusyFlag | kUnitPatrolStallFlag);
  }

  void ClearUnitPathingBusyBit(Unit* const unit)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask &= ~kUnitPathingBusyFlag;
  }

  void SetUnitPathBits(Unit* const unit, const std::uint64_t bits)
  {
    if (!unit) {
      return;
    }
    unit->UnitStateMask |= bits;
  }

  /**
   * Address: 0x005AD130 (FUN_005AD130)
   *
   * What it does:
   * Resets one nav-path span to empty content while preserving allocated
   * storage and base pointer ownership.
   */
  void ResetPathContent(SNavPath& path) noexcept
  {
    if (path.start != nullptr && path.finish != path.start) {
      path.finish = path.start;
    }
  }

  /**
   * Address: 0x005AD370 (FUN_005AD370)
   *
   * What it does:
   * Computes Euclidean cell-space distance between two packed path cells.
   */
  [[nodiscard]] float CellDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const float dx = static_cast<float>(static_cast<std::int32_t>(a.x) - static_cast<std::int32_t>(b.x));
    const float dz = static_cast<float>(static_cast<std::int32_t>(a.z) - static_cast<std::int32_t>(b.z));
    return std::sqrt((dx * dx) + (dz * dz));
  }

  [[nodiscard]] std::int32_t ManhattanDistance(const SOCellPos a, const SOCellPos b) noexcept
  {
    const std::int32_t dx = std::abs(static_cast<std::int32_t>(a.x) - static_cast<std::int32_t>(b.x));
    const std::int32_t dz = std::abs(static_cast<std::int32_t>(a.z) - static_cast<std::int32_t>(b.z));
    return dx + dz;
  }

  /**
   * Address: 0x005A9CF0 (FUN_005A9CF0)
   *
   * What it does:
   * Returns active path-cell count when path storage is allocated; otherwise
   * returns zero.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t CountPathCellsIfAllocated(const SNavPath& path) noexcept
  {
    if (path.start == nullptr) {
      return 0;
    }
    return static_cast<std::int32_t>(path.finish - path.start);
  }

  /**
   * Address: 0x005AE170 (FUN_005AE170)
   *
   * What it does:
   * Builds one cell projection from `toCell` toward `fromCell` by `distance`
   * units using truncating scalar conversion semantics.
   */
  [[maybe_unused]]
  [[nodiscard]] SOCellPos ProjectCellToward(const SOCellPos fromCell, const SOCellPos toCell, const float distance)
  {
    float deltaX = static_cast<float>(static_cast<std::int32_t>(fromCell.x) - static_cast<std::int32_t>(toCell.x));
    float deltaZ = static_cast<float>(static_cast<std::int32_t>(fromCell.z) - static_cast<std::int32_t>(toCell.z));
    const float lengthSquared = (deltaX * deltaX) + (deltaZ * deltaZ);

    if (lengthSquared != 0.0f) {
      const float scale = distance / std::sqrt(lengthSquared);
      deltaX *= scale;
      deltaZ *= scale;
    }

    SOCellPos out{};
    out.x = static_cast<std::int16_t>(static_cast<std::int32_t>(toCell.x) + static_cast<std::int32_t>(deltaX));
    out.z = static_cast<std::int16_t>(static_cast<std::int32_t>(toCell.z) + static_cast<std::int32_t>(deltaZ));
    return out;
  }

  /**
   * Address: 0x005AD830 (FUN_005AD830)
   *
   * What it does:
   * Removes one consumed prefix from the active path span and updates node-index
   * tracking with the same clamp semantics as the binary.
   */
  std::int32_t ConsumePathPrefix(CAiPathNavigator& navigator, std::int32_t requestedCount)
  {
    SOCellPos* const pathBegin = navigator.mPath.start;
    std::int32_t pathCount = 0;
    if (pathBegin) {
      pathCount = static_cast<std::int32_t>(navigator.mPath.finish - pathBegin);
    }

    std::int32_t consumeCount = requestedCount;
    if (consumeCount >= pathCount) {
      consumeCount = pathCount;
    }
    if (consumeCount < 0) {
      consumeCount = 0;
    }

    SOCellPos* readCursor = pathBegin ? (pathBegin + consumeCount) : nullptr;
    if (pathBegin && readCursor && readCursor != pathBegin) {
      SOCellPos* writeCursor = pathBegin;
      while (readCursor != navigator.mPath.finish) {
        *writeCursor = *readCursor;
        ++writeCursor;
        ++readCursor;
      }
      navigator.mPath.finish = writeCursor;
    }

    if (!navigator.mPath.start || navigator.mPath.finish == navigator.mPath.start) {
      navigator.mPathRetryDelayFrames = 0;
    }

    const std::int32_t updatedIndex = navigator.mLastPathNodeIndex - consumeCount;
    navigator.mLastPathNodeIndex = (updatedIndex <= -1) ? -1 : updatedIndex;
    return updatedIndex;
  }

  /**
   * Address: 0x005AFEC0 (FUN_005AFEC0)
   *
   * What it does:
   * Appends one cell payload to a nav-path span, using the direct-capacity lane
   * when storage is available.
   */
  void AppendPathCellFast(SNavPath& path, const SOCellPos& cell)
  {
    if (!path.start || path.finish >= path.capacity) {
      path.AppendCell(cell);
      return;
    }

    *path.finish = cell;
    ++path.finish;
  }

  /**
   * Address: 0x005AF4E0 (FUN_005AF4E0)
   *
   * What it does:
   * Tests whether the navigator footprint can occupy `toCell` under current
   * occupancy caps/path-layer rules, with the binary's long-step fallback gate.
   */
  [[nodiscard]] bool CanOccupyTargetCell(
    const CAiPathNavigator& navigator, const SOCellPos fromCell, const SOCellPos toCell
  )
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (!pathFinder || !pathFinder->mUnit) {
      return false;
    }

    if (ManhattanDistance(fromCell, toCell) > 1) {
      return pathFinder->CanTraverseCell(toCell);
    }

    const auto* const grid = GetPathingGrid(navigator);
    const auto* const sim = GetPathingSim(navigator);
    if (!grid || !sim || !sim->mMapData) {
      return false;
    }

    const SFootprint& footprint = pathFinder->mUnit->GetFootprint();
    EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(footprint, *sim->mMapData, toCell);
    if (pathFinder->mPathLayerSelector == 8) {
      const std::uint8_t masked = static_cast<std::uint8_t>(occupancyCaps) &
        ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB);
      occupancyCaps = static_cast<EOccupancyCaps>(masked);
    }

    return static_cast<std::uint8_t>(OCCUPY_FootprintFits(*grid, toCell, footprint, occupancyCaps)) != 0u;
  }

  /**
   * Address: 0x005AF670 (FUN_005AF670)
   *
   * What it does:
   * Evaluates one start->end cell transition with the same mode gate lane used
   * by the navigator direct-transition checks.
   */
  [[nodiscard]] bool CanPathCellTransition(
    const CAiPathNavigator& navigator, const SOCellPos fromCell, const SOCellPos toCell
  )
  {
    if (!navigator.mPathFinder) {
      return false;
    }

    const std::int32_t transitionMode = (navigator.mUseExtendedPathProbe != 0u) ? 2 : 1;
    (void)transitionMode;
    return CanOccupyTargetCell(navigator, fromCell, toCell);
  }

  /**
   * Address: 0x005AF5B0 (FUN_005AF5B0)
   *
   * What it does:
   * Projects one target cell into world-space, applies the long-step traversal
   * gate, then validates occupancy at that target.
   */
  [[nodiscard]] bool CanReachCellFromCurrent(const CAiPathNavigator& navigator, const SOCellPos targetCell)
  {
    const auto* const pathFinder = navigator.mPathFinder;
    if (!pathFinder || !pathFinder->mUnit) {
      return false;
    }

    const auto* const sim = GetPathingSim(navigator);
    if (!sim || !sim->mMapData) {
      return false;
    }

    const SFootprint& footprint = pathFinder->mUnit->GetFootprint();
    const Wm3::Vector3f targetWorldPos = COORDS_ToWorldPos(
      sim->mMapData,
      targetCell,
      static_cast<ELayer>(footprint.mOccupancyCaps),
      footprint.mSizeX,
      footprint.mSizeZ
    );
    const Wm3::Vector3f& unitWorldPos = pathFinder->mUnit->GetPosition();
    const bool hasSegment = Wm3::Vector3f::Compare(&unitWorldPos, &targetWorldPos);

    if (hasSegment && ManhattanDistance(navigator.mCurrentPos, targetCell) > 1 &&
        !pathFinder->CanTraverseCell(targetCell)) {
      return false;
    }

    return CanPathCellTransition(navigator, targetCell, targetCell);
  }

  [[nodiscard]] bool UpdateForwardProbeFlag(CAiPathNavigator& navigator)
  {
    if (!navigator.mPathFinder) {
      navigator.mHasForwardProbe = 0;
      return false;
    }

    const bool canOccupyCurrent = CanOccupyTargetCell(navigator, navigator.mCurrentPos, navigator.mCurrentPos);
    const bool canReachForward = CanReachCellFromCurrent(navigator, navigator.mCurrentPos);
    navigator.mHasForwardProbe = (canOccupyCurrent && canReachForward) ? 1u : 0u;
    return navigator.mHasForwardProbe != 0u;
  }

  [[nodiscard]] bool IsUnderwaterRouteCellForUnit(const STIMap& map, const Unit& unit, const SOCellPos& targetCell)
  {
    const Wm3::Vector3f worldPos = COORDS_ToWorldPos(&map, targetCell, unit.GetFootprint());
    return !map.AboveWater(worldPos);
  }

  /**
   * Address: 0x005ADC70 (FUN_005ADC70)
   *
   * What it does:
   * Selects alternate-footprint pathing for FAVORSWATER units when current and
   * queued command destinations remain underwater for the coordinating group.
   */
  void UpdateWaterFavorAltFootprintMode(CAiPathNavigator& navigator)
  {
    constexpr const char* kWaterFavorCategory = "FAVORSWATER";

    CAiPathFinder* const pathFinder = navigator.mPathFinder;
    Unit* const ownerUnit = pathFinder ? pathFinder->mUnit : nullptr;
    if (!ownerUnit || !ownerUnit->IsInCategory(kWaterFavorCategory)) {
      return;
    }

    (void)WriteUnitAltFootprintFlag(ownerUnit, 0u);

    const Sim* const sim = GetPathingSim(navigator);
    const STIMap* const map = sim ? sim->mMapData : nullptr;
    if (!map) {
      return;
    }

    CUnitCommand* const currentCommand =
      (ownerUnit->CommandQueue != nullptr) ? ownerUnit->CommandQueue->GetCurrentCommand() : nullptr;

    if (!currentCommand) {
      if (!map->AboveWater(ownerUnit->GetPosition())) {
        const SOCellPos goalAnchorCell = GoalAnchorCell(navigator.mGoal);
        if (IsUnderwaterRouteCellForUnit(*map, *ownerUnit, goalAnchorCell)) {
          (void)WriteUnitAltFootprintFlag(ownerUnit, 1u);
        }
      }
      return;
    }

    bool hasSurfaceTransitionUnit = false;
    for (CScriptObject* const entry : currentCommand->mUnitSet.mVec) {
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      Unit* const candidateUnit = SCommandUnitSet::UnitFromEntry(entry);
      if (!candidateUnit || candidateUnit->IsDead() || candidateUnit->DestroyQueued()) {
        continue;
      }

      if (!candidateUnit->IsInCategory(kWaterFavorCategory)) {
        continue;
      }

      SOCellPos currentCommandCell{};
      (void)CUnitCommand::GetPosition(currentCommand, candidateUnit, &currentCommandCell);

      const bool unitIsUnderwaterNow = !map->AboveWater(candidateUnit->GetPosition());
      const bool commandCellUnderwater = IsUnderwaterRouteCellForUnit(*map, *candidateUnit, currentCommandCell);

      if (unitIsUnderwaterNow && commandCellUnderwater) {
        CUnitCommand* const nextCommand =
          (candidateUnit->CommandQueue != nullptr) ? candidateUnit->CommandQueue->GetCurrentCommand() : nullptr;
        if (!nextCommand || nextCommand == currentCommand) {
          continue;
        }

        SOCellPos nextCommandCell{};
        (void)CUnitCommand::GetPosition(nextCommand, candidateUnit, &nextCommandCell);
        if (IsUnderwaterRouteCellForUnit(*map, *candidateUnit, nextCommandCell)) {
          continue;
        }
      }

      hasSurfaceTransitionUnit = true;
      break;
    }

    if (!hasSurfaceTransitionUnit) {
      (void)WriteUnitAltFootprintFlag(ownerUnit, 1u);
    }
  }

  /**
   * Address: 0x005AF360 (FUN_005AF360)
   *
   * What it does:
   * Returns the longest direct-reachable prefix index that preserves heading
   * continuity from the current cell into the active path span.
   */
  [[nodiscard]] std::int32_t ComputeDirectPrefixSpan(CAiPathNavigator& navigator)
  {
    if (navigator.mPath.CountInt() <= 0) {
      return 0;
    }

    if (PackCell(navigator.mCurrentPos) == PackCell(navigator.mPath.start[0]) && navigator.mPath.CountInt() > 1) {
      (void)ConsumePathPrefix(navigator, 1);
    }

    const std::int32_t pathSize = navigator.mPath.CountInt();
    if (pathSize <= 0) {
      return 0;
    }

    const SOCellPos firstCell = navigator.mPath.start[0];
    if (std::abs(static_cast<std::int32_t>(firstCell.x) - static_cast<std::int32_t>(navigator.mCurrentPos.x)) > 1 ||
        std::abs(static_cast<std::int32_t>(firstCell.z) - static_cast<std::int32_t>(navigator.mCurrentPos.z)) > 1 ||
        !CanOccupyTargetCell(navigator, navigator.mCurrentPos, firstCell) ||
        !CanReachCellFromCurrent(navigator, firstCell)) {
      return 0;
    }

    std::int32_t bestIndex = 0;
    const std::int32_t headingDelta[2] = {
      static_cast<std::int32_t>(firstCell.x) - static_cast<std::int32_t>(navigator.mCurrentPos.x),
      static_cast<std::int32_t>(firstCell.z) - static_cast<std::int32_t>(navigator.mCurrentPos.z),
    };

    for (std::int32_t idx = 1; idx < pathSize; ++idx) {
      const SOCellPos prev = navigator.mPath.start[idx - 1];
      const SOCellPos cell = navigator.mPath.start[idx];
      const std::int32_t nextDelta[2] = {
        static_cast<std::int32_t>(cell.x) - static_cast<std::int32_t>(prev.x),
        static_cast<std::int32_t>(cell.z) - static_cast<std::int32_t>(prev.z),
      };

      if (HeadingDeltaMismatch(nextDelta, headingDelta)) {
        break;
      }

      if (!CanOccupyTargetCell(navigator, navigator.mCurrentPos, cell) || !CanReachCellFromCurrent(navigator, cell)) {
        break;
      }

      bestIndex = idx;
    }

    return bestIndex;
  }

  [[nodiscard]] EAiPathSearchType AsSearchType(const std::int32_t mode) noexcept
  {
    switch (mode) {
    case 1:
      return AIPATHSEARCH_Initial;
    case 2:
      return AIPATHSEARCH_Repath;
    case 3:
      return AIPATHSEARCH_Leader;
    default:
      return AIPATHSEARCH_None;
    }
  }
} // namespace

gpg::RType* CAiPathNavigator::sType = nullptr;

CAiPathNavigator* CAiPathNavigator::FromListenerLink(Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<CAiPathNavigator, Broadcaster, &CAiPathNavigator::mListenerLink>(link);
}

const CAiPathNavigator* CAiPathNavigator::FromListenerLink(const Broadcaster* const link) noexcept
{
  return Broadcaster::owner_from_member<CAiPathNavigator, Broadcaster, &CAiPathNavigator::mListenerLink>(link);
}

/**
 * Address: 0x005AD5A0 (FUN_005AD5A0)
 *
 * What it does:
 * Initializes one detached listener-link lane on `CAiPathNavigator`
 * construction storage.
 */
[[maybe_unused]] CAiPathNavigator* InitializePathNavigatorListenerLane(
  CAiPathNavigator* const navigatorStorage
) noexcept
{
  if (navigatorStorage == nullptr) {
    return nullptr;
  }

  navigatorStorage->mListenerLink.ListResetLinks();
  return navigatorStorage;
}

/**
 * Address: 0x005AD5C0 (FUN_005AD5C0, default ctor used by RTTI NewRef/CtrRef)
 *
 * What it does:
 * Initializes one detached navigator object for reflection construction paths.
 */
CAiPathNavigator::CAiPathNavigator()
  : mListenerLink{}
  , mState(AIPATHNAVSTATE_Idle)
  , mPathFinder(nullptr)
  , mPath{}
  , mCurrentPos{0, 0}
  , mTargetPos{0, 0}
  , mLastBlockedCell(0)
  , mGoal{}
  , mLastPathLayerToken(0u)
  , mSim(nullptr)
  , mLastPathNodeIndex(-1)
  , mPathSearchFailCount(0)
  , mPathRetryDelayFrames(0)
  , mNoForwardDistanceFailCount(0)
  , mRepathDistanceThreshold(std::numeric_limits<float>::infinity())
  , mLastRepathTick(0)
  , mNoProgressTickCount(0)
  , mLastFormationSyncTick(0)
  , mLeaderLink{}
  , mLeaderTargetPos(Wm3::Vector3f::Zero())
  , mIsInFormation(0)
  , mLeaderBusy(0)
  , mHasLeaderTargetPos(0)
  , mHasForwardProbe(0)
  , mRepathRequested(0)
  , mUseExtendedPathProbe(0)
  , mTargetWithinOneCell(0)
  , mPad97(0)
  , mPathRequestMode(0)
  , mPathRequestCountdown(0)
  , mTickBucket7(0)
  , mTickBucket13(0)
{
  mListenerLink.ListResetLinks();
  mPath.reserved0 = 0;
  mPath.start = nullptr;
  mPath.finish = nullptr;
  mPath.capacity = nullptr;
}

/**
 * Address: 0x005AD3E0 (FUN_005AD3E0, unit ctor)
 */
CAiPathNavigator::CAiPathNavigator(Unit* const unit)
  : mListenerLink{}
  , mState(AIPATHNAVSTATE_Idle)
  , mPathFinder(nullptr)
  , mPath{}
  , mCurrentPos{0, 0}
  , mTargetPos{0, 0}
  , mLastBlockedCell(0)
  , mGoal{}
  , mLastPathLayerToken(unit ? ReadUnitLayerToken(unit) : 0u)
  , mSim(unit ? unit->SimulationRef : nullptr)
  , mLastPathNodeIndex(-1)
  , mPathSearchFailCount(0)
  , mPathRetryDelayFrames(0)
  , mNoForwardDistanceFailCount(0)
  , mRepathDistanceThreshold(std::numeric_limits<float>::infinity())
  , mLastRepathTick(0)
  , mNoProgressTickCount(0)
  , mLastFormationSyncTick(0)
  , mLeaderLink{}
  , mLeaderTargetPos(Wm3::Vector3f::Zero())
  , mIsInFormation(0)
  , mLeaderBusy(0)
  , mHasLeaderTargetPos(0)
  , mHasForwardProbe(0)
  , mRepathRequested(0)
  , mUseExtendedPathProbe(0)
  , mTargetWithinOneCell(0)
  , mPad97(0)
  , mPathRequestMode(0)
  , mPathRequestCountdown(0)
  , mTickBucket7(unit ? (unit->GetEntityId() % 7) : 0)
  , mTickBucket13(unit ? (unit->GetEntityId() % 13) : 0)
{
  mListenerLink.ListResetLinks();

  mPath.reserved0 = 0;
  mPath.start = nullptr;
  mPath.finish = nullptr;
  mPath.capacity = nullptr;

  mPathFinder = new CAiPathFinder();
  mPathFinder->SetUnit(unit);
}

/**
 * Address: 0x005A44B0 (FUN_005A44B0, core dtor body)
 * Address: 0x005A44C0 (FUN_005A44C0, duplicated thunked entry)
 */
CAiPathNavigator::~CAiPathNavigator()
{
  DetachListenerNode(*this);
  DetachWeakUnit(mLeaderLink);
  mPath.FreeStorage();

  if (mPathFinder) {
    delete mPathFinder;
    mPathFinder = nullptr;
  }

  mListenerLink.ListResetLinks();
}

/**
 * Address: 0x005AEEB0 (FUN_005AEEB0)
 */
bool CAiPathNavigator::OnEvent(const SNavPath& path)
{
  DetachListenerNode(*this);

  Unit* const unit = GetOwningUnit(*this);
  const std::int32_t incomingCount = path.CountInt();

  if (mState == AIPATHNAVSTATE_PathEvent3) {
    mPath.AssignCopy(path);
    ClearUnitPathingBusyBit(unit);

    if (mPath.CountInt() == 0) {
      mState = AIPATHNAVSTATE_Failed;
      mPathRetryDelayFrames = 0;
      SetUnitPathBits(unit, kUnitPathFlag);
      if (unit && unit->IsUnitState(UNITSTATE_Patrolling)) {
        SetUnitPathBits(unit, kUnitPatrolStallFlag);
      }
      return false;
    }

    const SOCellPos tailCell = mPath.finish[-1];
    if (!IsCellInGoal(tailCell)) {
      SetUnitPathBits(unit, kUnitPathFlag);
      const SOCellPos centerCell = GoalCenterCell(mGoal);
      if (CanPathCellTransition(*this, centerCell, centerCell)) {
        AppendPathCellFast(mPath, centerCell);
      }
    }

    mPathSearchFailCount = 0;
    mPathRetryDelayFrames = 0;
    mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
    mState = AIPATHNAVSTATE_HasPath;
    if (mPathFinder) {
      mPathFinder->mSearchType = AIPATHSEARCH_None;
    }
    return true;
  }

  if (mState != AIPATHNAVSTATE_PathEvent4) {
    GPG_ASSERT(false);
    return false;
  }

  if (incomingCount == 0) {
    if (mPathSearchFailCount >= 3) {
      ++mNoForwardDistanceFailCount;
      if (mNoForwardDistanceFailCount >= 3) {
        mState = AIPATHNAVSTATE_Failed;
        mPathRetryDelayFrames = 0;
      } else {
        mPathSearchFailCount = 0;
        RequestPath(1);
      }
      return mState != AIPATHNAVSTATE_Failed;
    }

    ++mPathSearchFailCount;
    mPathRetryDelayFrames = 10;
    return true;
  }

  bool mergedWithFront = false;
  if (mPath.CountInt() > 0) {
    const SOCellPos incomingBack = path.finish[-1];
    if (incomingBack.x == mPath.start[0].x && incomingBack.z == mPath.start[0].z) {
      mLastBlockedCell = 0;
      mPathSearchFailCount = 0;

      if (incomingCount > 1) {
        mPath.PrependCells(path.start, path.finish - 1);
      }
      mergedWithFront = true;
    }
  }

  if (!mergedWithFront) {
    if (mPath.CountInt() > 0 && incomingCount <= 2) {
      const SOCellPos firstCell = mPath.start[0];
      const bool canStayOnFirstCell = CanPathCellTransition(*this, firstCell, firstCell) &&
        CanPathCellTransition(*this, firstCell, firstCell);
      if (canStayOnFirstCell) {
        const std::uint32_t packedFirstCell = PackCell(firstCell);
        if (mLastBlockedCell == packedFirstCell) {
          mState = AIPATHNAVSTATE_Failed;
          mPathRetryDelayFrames = 0;
          mPathSearchFailCount = 0;
          return false;
        }
        mLastBlockedCell = packedFirstCell;
      } else {
        if (mPathSearchFailCount < 3) {
          ++mPathSearchFailCount;
          mPathRetryDelayFrames = 10;
          return true;
        }
        mState = AIPATHNAVSTATE_Failed;
        mPathRetryDelayFrames = 0;
        mPathSearchFailCount = 0;
        return false;
      }
    }

    mPath.PrependCells(path.start, path.finish);
  }

  mNoForwardDistanceFailCount = 0;
  mPathRetryDelayFrames = 0;
  mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
  if (mPathFinder) {
    mPathFinder->mSearchType = AIPATHSEARCH_None;
  }

  const std::int32_t mergeAdjust = mergedWithFront ? 1 : 0;
  if (mLastPathNodeIndex < 0) {
    mLastPathNodeIndex = mPath.CountInt() - 1;
  } else {
    mLastPathNodeIndex += incomingCount - mergeAdjust;
  }

  mState = AIPATHNAVSTATE_HasPath;
  return true;
}

/**
 * Address: 0x005AD6E0 (FUN_005AD6E0)
 */
void CAiPathNavigator::ConfigureGoal(const SAiNavigatorGoal& goal, const bool ignoreFormation)
{
  mGoal = goal;
  mLastPathLayerToken = 0;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLeaderBusy = 0;
  mHasLeaderTargetPos = 0;
  mUseExtendedPathProbe = 0;
  mTargetWithinOneCell = 0;
  DetachWeakUnit(mLeaderLink);

  Unit* const unit = GetOwningUnit(*this);
  if (unit) {
    unit->UnitStateMask &= ~kUnitPathFlag;
  }

  mIsInFormation = 0;
  if (!ignoreFormation) {
    // Formation leader chain (`Unit::GetFormation` / `IUnit::AddToChain`) is still
    // pending typed recovery in this pass.
    mIsInFormation = 0;
  }
}

/**
 * Address: 0x005AD9C0 (FUN_005AD9C0)
 */
void CAiPathNavigator::ResetPathState()
{
  mTargetPos = mCurrentPos;
  ResetPathContent(mPath);

  DetachListenerNode(*this);

  if (mPathFinder) {
    mPathFinder->OnPathSearchCancelled();
    mPathFinder->mSearchType = AIPATHSEARCH_None;
  }

  mState = AIPATHNAVSTATE_Idle;
  mPathRetryDelayFrames = 0;
  mPathSearchFailCount = 0;
  mNoForwardDistanceFailCount = 0;
  mLastPathLayerToken = 0;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLeaderBusy = 0;
  mHasLeaderTargetPos = 0;
  mHasForwardProbe = 0;
  mRepathRequested = 0;
  mUseExtendedPathProbe = 0;
  mTargetWithinOneCell = 0;
  mIsInFormation = 0;
  mPathRequestCountdown = 0;
  mLastPathNodeIndex = -1;
  mLastBlockedCell = 0;
  mRepathDistanceThreshold = std::numeric_limits<float>::infinity();
  mNoProgressTickCount = 0;
  mLastRepathTick = 0;
  mLastFormationSyncTick = 0;

  DetachWeakUnit(mLeaderLink);

  Unit* const unit = GetOwningUnit(*this);
  if (unit) {
    ClearUnitPathBits(unit);
    unit->FootprintDown = false;
  }
}

/**
 * Address: 0x005ADBA0 (FUN_005ADBA0)
 */
void CAiPathNavigator::BeginThinking()
{
  mState = AIPATHNAVSTATE_Thinking;
  mPathRequestMode = 0;
  mPathRequestCountdown = 1;
}

/**
 * Address: 0x005ADFE0 (FUN_005ADFE0)
 */
void CAiPathNavigator::RequestPath(const std::int32_t requestMode)
{
  mPathRequestMode = requestMode;
  mLeaderTargetPos = Wm3::Vector3f::Zero();
  mLastBlockedCell = 0;
  mPathRetryDelayFrames = 0;
  mRepathRequested = 0;

  if (!mPathFinder) {
    mHasForwardProbe = 0;
    return;
  }

  UpdateWaterFavorAltFootprintMode(*this);

  (void)WritePackedPathCellWordPair(
    &mPathFinder->mAnchorCell,
    static_cast<std::uint16_t>(mCurrentPos.x),
    static_cast<std::uint16_t>(mCurrentPos.z)
  );
  mPathFinder->SetGoal(mGoal);
  mPathFinder->mSearchType = AsSearchType(requestMode);

  Unit* const unit = GetOwningUnit(*this);
  if (mLeaderBusy == 0u) {
    SetUnitPathBits(unit, kUnitPathingBusyFlag);
    mPathFinder->QueueSearch();
    mState = AIPATHNAVSTATE_PathEvent3;
    AttachListenerNodeToPathFinder(*this);
  } else {
    AppendPathCellFast(mPath, GoalAnchorCell(mGoal));
    mState = AIPATHNAVSTATE_FollowingLeader;
  }

  mTargetWithinOneCell = 0;
  (void)UpdateForwardProbeFlag(*this);
}

/**
 * Address: 0x005AEC70 (FUN_005AEC70)
 */
void CAiPathNavigator::RequestContinuationPath(std::int32_t requestMode)
{
  if (mPath.CountInt() <= 0) {
    ResetPathState();
    return;
  }

  if (PackCell(mPath.start[0]) == PackCell(mCurrentPos)) {
    (void)ConsumePathPrefix(*this, 1);
    if (mPath.CountInt() <= 0) {
      ResetPathState();
      return;
    }
  }

  while (mPath.CountInt() > 1) {
    const SOCellPos firstCell = mPath.start[0];
    const bool canTraverseFirst = CanPathCellTransition(*this, firstCell, firstCell);
    if (!canTraverseFirst || ManhattanDistance(firstCell, mCurrentPos) > 1) {
      break;
    }
    (void)ConsumePathPrefix(*this, 1);
  }

  (void)UpdateForwardProbeFlag(*this);

  Unit* const unit = GetOwningUnit(*this);
  if (unit && unit->IsUnitState(UNITSTATE_Attacking)) {
    requestMode = 3;
    mUseExtendedPathProbe = 1;
  }
  if (requestMode == 3) {
    mUseExtendedPathProbe = 1;
  }

  mTargetWithinOneCell = 0;

  if (!mPathFinder || mPath.CountInt() <= 0) {
    return;
  }

  mPathFinder->mSearchType = AsSearchType(requestMode);
  (void)WritePackedPathCellWordPair(
    &mPathFinder->mAnchorCell,
    static_cast<std::uint16_t>(mCurrentPos.x),
    static_cast<std::uint16_t>(mCurrentPos.z)
  );
  mPathFinder->SetGoal(BuildSingleCellGoal(mPath.start[0]));
  mPathFinder->QueueSearch();

  mState = AIPATHNAVSTATE_PathEvent4;
  AttachListenerNodeToPathFinder(*this);
  mPathRetryDelayFrames = 0;
}

/**
 * Address: 0x005AE210 (FUN_005AE210)
 */
void CAiPathNavigator::SetCurrentPosition(const Wm3::Vector3f& position)
{
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!footprint) {
    return;
  }

  mCurrentPos = ToCellPos(position, *footprint);
}

/**
 * Address: 0x005AF6D0 (FUN_005AF6D0)
 */
void CAiPathNavigator::SetTargetPoint(const std::int32_t targetIndex)
{
  (void)ConsumePathPrefix(*this, targetIndex);
  if (mPath.CountInt() <= 0) {
    return;
  }

  mTargetPos = mPath.start[0];
  mState = AIPATHNAVSTATE_HasPath;
  mPathRetryDelayFrames = 0;
  mTargetWithinOneCell = (ManhattanDistance(mCurrentPos, mTargetPos) <= 1) ? 1u : 0u;
}

/**
 * Address: 0x005AF7E0 (FUN_005AF7E0)
 */
bool CAiPathNavigator::TryAdvanceTargetPoint()
{
  const std::int32_t pathSize = mPath.CountInt();
  if (pathSize <= 0) {
    return false;
  }

  const std::int32_t firstReachableIndex = (mHasForwardProbe != 0u) ? std::max(0, ComputeDirectPrefixSpan(*this)) : 0;
  const std::int32_t furthestCandidateIndex = (mHasForwardProbe != 0u)
    ? std::min(pathSize - 1, std::max(10, firstReachableIndex))
    : std::min(pathSize - 1, 1);

  std::int32_t selectedIndex = -1;
  for (std::int32_t idx = furthestCandidateIndex; idx >= firstReachableIndex; --idx) {
    const SOCellPos candidate = mPath.start[idx];
    if (idx != firstReachableIndex && CellDistance(mCurrentPos, candidate) >= 50.0f) {
      continue;
    }

    const bool canTraverse = CanPathCellTransition(*this, mCurrentPos, candidate);
    const bool canReach = CanReachCellFromCurrent(*this, candidate);
    if (canTraverse && canReach) {
      mHasForwardProbe = 1;
      selectedIndex = idx;
      break;
    }

    if (mHasForwardProbe == 0u && mRepathRequested == 0u) {
      selectedIndex = idx;
      break;
    }
  }

  if (selectedIndex < firstReachableIndex) {
    if (mUseExtendedPathProbe != 0u && furthestCandidateIndex > 0) {
      SetTargetPoint(0);
      mUseExtendedPathProbe = 0;
      return true;
    }

    if (firstReachableIndex > 0) {
      (void)ConsumePathPrefix(*this, firstReachableIndex - 1);
    }
    return false;
  }

  if (selectedIndex == 0 && furthestCandidateIndex > firstReachableIndex && mPath.CountInt() > 1 &&
      !CanPathCellTransition(*this, mPath.start[0], mPath.start[1]) && CellDistance(mCurrentPos, mTargetPos) < 10.0f) {
    (void)ConsumePathPrefix(*this, 1);
    return false;
  }

  if (mNoProgressTickCount <= 30 || selectedIndex > 0) {
    SetTargetPoint(selectedIndex);
    mTargetWithinOneCell = 0;
    return true;
  }

  return false;
}

/**
 * Address: 0x005AE2D0 (FUN_005AE2D0)
 */
void CAiPathNavigator::UpdateCurrentPosition(const Wm3::Vector3f& position)
{
  SetCurrentPosition(position);

  const std::uint32_t currentTick = (mSim != nullptr) ? mSim->mCurTick : 0u;

  if (mPathRequestCountdown > 0) {
    --mPathRequestCountdown;
    if (mPathRequestCountdown == 0) {
      RequestPath(mPathRequestMode);
    }
    mTargetPos = mCurrentPos;
    return;
  }

  if (mPathRetryDelayFrames > 0) {
    --mPathRetryDelayFrames;
    if (mPathRetryDelayFrames == 0) {
      RequestContinuationPath(2);
    }
    return;
  }

  while (mPath.CountInt() > 1) {
    const SOCellPos first = mPath.start[0];
    const SOCellPos second = mPath.start[1];
    if (CellDistance(mCurrentPos, first) < CellDistance(mCurrentPos, second) || !CanReachCellFromCurrent(*this, second)) {
      break;
    }
    (void)ConsumePathPrefix(*this, 1);
  }

  if (mState != AIPATHNAVSTATE_HasPath && mState != AIPATHNAVSTATE_FollowingLeader) {
    mTargetPos = mCurrentPos;
    return;
  }

  if (mPath.CountInt() <= 0) {
    mState = AIPATHNAVSTATE_Failed;
    mPathRetryDelayFrames = 0;
    mTargetPos = mCurrentPos;
    return;
  }

  const SOCellPos pathTail = mPath.finish[-1];
  if (PackCell(mCurrentPos) == PackCell(pathTail)) {
    ResetPathContent(mPath);
    mState = AIPATHNAVSTATE_Idle;
    mPathRetryDelayFrames = 0;
    mTargetPos = mCurrentPos;
    return;
  }

  if (!TryAdvanceTargetPoint()) {
    mTargetPos = mPath.start[0];
  }

  Unit* const unit = GetOwningUnit(*this);
  if (!unit || mLeaderBusy != 0u) {
    return;
  }

  const std::uint32_t layerToken = ReadUnitLayerToken(unit);
  if (layerToken != mLastPathLayerToken) {
    mLastPathLayerToken = layerToken;
    RequestContinuationPath(2);
    return;
  }

  const bool hasMoved = (unit->Position.x != unit->PrevPosition.x) || (unit->Position.y != unit->PrevPosition.y) ||
    (unit->Position.z != unit->PrevPosition.z);
  if (!hasMoved && !unit->IsUnitState(UNITSTATE_Moving)) {
    ++mNoProgressTickCount;
  } else {
    mNoProgressTickCount = 0;
  }

  const float currentTargetDistance = CellDistance(mCurrentPos, mTargetPos);
  if (mRepathDistanceThreshold < currentTargetDistance || mRepathRequested != 0u || mNoProgressTickCount > 30) {
    mLastRepathTick = static_cast<std::int32_t>(currentTick);

    if (TryAdvanceTargetPoint()) {
      mHasLeaderTargetPos = 0;
      mRepathDistanceThreshold = CellDistance(mCurrentPos, mTargetPos) * 0.5f;
      mLeaderTargetPos = Wm3::Vector3f::Zero();
      mRepathRequested = 0;
      return;
    }

    if (mNoProgressTickCount > 30) {
      ResetPathContent(mPath);
      mState = AIPATHNAVSTATE_Idle;
      mPathRetryDelayFrames = 0;
      mTargetPos = mCurrentPos;
      return;
    }

    if (mRepathRequested != 0u) {
      mRepathRequested = 0;
      RequestContinuationPath(3);
      return;
    }

    RequestContinuationPath(2);
  }
}

/**
 * Address: 0x005AD800 (FUN_005AD800)
 */
bool CAiPathNavigator::IsCellInGoal(const SOCellPos& cellPos) const
{
  const int x = static_cast<int>(cellPos.x);
  if (x < mGoal.minX || x >= mGoal.maxX) {
    return false;
  }

  const int z = static_cast<int>(cellPos.z);
  return z >= mGoal.minZ && z < mGoal.maxZ;
}

/**
 * Address: 0x005AD8B0 (FUN_005AD8B0)
 */
Wm3::Vector3f CAiPathNavigator::GetTargetPos() const
{
  if (mHasLeaderTargetPos != 0u && HasVectorValue(mLeaderTargetPos)) {
    return mLeaderTargetPos;
  }

  Unit* const unit = GetOwningUnit(*this);
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!unit || !footprint) {
    return Wm3::Vector3f::Zero();
  }
  return ToWorldPos(mTargetPos, *unit, *footprint);
}

/**
 * Address: 0x005ADAD0 (FUN_005ADAD0 callsite from FUN_005A3CD0)
 */
bool CAiPathNavigator::CanPathTo(const SAiNavigatorGoal& goal, Wm3::Vector3f* const outTargetPos) const
{
  if (!HasGoalArea(goal)) {
    return false;
  }

  if (!outTargetPos) {
    return true;
  }

  Unit* const unit = GetOwningUnit(*this);
  const SFootprint* const footprint = GetActiveFootprint(*this);
  if (!unit || !footprint) {
    *outTargetPos = Wm3::Vector3f::Zero();
    return true;
  }

  const SOCellPos anchor = GoalAnchorCell(goal);
  *outTargetPos = ToWorldPos(anchor, *unit, *footprint);
  return true;
}

/**
 * Address: 0x005B0F10 (FUN_005B0F10, Moho::CAiPathNavigator::MemberDeserialize)
 */
void CAiPathNavigator::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};

  if (version >= 1) {
    archive->Read(CachedNavigatorStateType(), &mState, owner);
  }

  CAiPathFinder* const loadedPathFinder = ReadPointerWithType<CAiPathFinder>(archive, owner, CachedCAiPathFinderType());
  CAiPathFinder* const oldPathFinder = mPathFinder;
  mPathFinder = loadedPathFinder;
  if (oldPathFinder) {
    delete oldPathFinder;
  }

  archive->Read(CachedNavPathType(), &mPath, owner);
  archive->Read(CachedHPathCellType(), &mCurrentPos, owner);
  archive->Read(CachedHPathCellType(), &mTargetPos, owner);

  HPathCell blockedCell{};
  archive->Read(CachedHPathCellType(), &blockedCell, owner);
  std::memcpy(&mLastBlockedCell, &blockedCell, sizeof(blockedCell));

  archive->Read(CachedNavGoalType(), &mGoal, owner);
  archive->Read(CachedLayerType(), &mLastPathLayerToken, owner);
  mSim = ReadPointerWithType<Sim>(archive, owner, CachedSimType());

  archive->ReadInt(&mLastPathNodeIndex);
  archive->ReadInt(&mPathSearchFailCount);
  archive->ReadInt(&mPathRetryDelayFrames);
  archive->ReadInt(&mNoForwardDistanceFailCount);
  archive->ReadFloat(&mRepathDistanceThreshold);

  unsigned int lastRepathTickRaw = 0;
  archive->ReadUInt(&lastRepathTickRaw);
  mLastRepathTick = static_cast<std::int32_t>(lastRepathTickRaw);

  archive->ReadInt(&mNoProgressTickCount);

  unsigned int lastFormationSyncTickRaw = 0;
  archive->ReadUInt(&lastFormationSyncTickRaw);
  mLastFormationSyncTick = static_cast<std::int32_t>(lastFormationSyncTickRaw);

  archive->Read(CachedWeakUnitType(), &mLeaderLink, owner);
  archive->Read(CachedVector3Type(), &mLeaderTargetPos, owner);

  bool boolValue = false;
  archive->ReadBool(&boolValue);
  mIsInFormation = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mLeaderBusy = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mHasLeaderTargetPos = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mHasForwardProbe = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mRepathRequested = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mUseExtendedPathProbe = boolValue ? 1u : 0u;
  archive->ReadBool(&boolValue);
  mTargetWithinOneCell = boolValue ? 1u : 0u;
  archive->Read(CachedSearchType(), &mPathRequestMode, owner);
  archive->ReadInt(&mPathRequestCountdown);
  archive->ReadInt(&mTickBucket7);
  archive->ReadInt(&mTickBucket13);
}

/**
 * Address: 0x005B12A0 (FUN_005B12A0, Moho::CAiPathNavigator::MemberSerialize)
 */
void CAiPathNavigator::MemberSerialize(gpg::WriteArchive* const archive, const int version)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};

  if (version >= 1) {
    archive->Write(CachedNavigatorStateType(), &mState, owner);
  }

  WritePointerWithType(archive, mPathFinder, CachedCAiPathFinderType(), gpg::TrackedPointerState::Owned, owner);
  archive->Write(CachedNavPathType(), &mPath, owner);
  archive->Write(CachedHPathCellType(), &mCurrentPos, owner);
  archive->Write(CachedHPathCellType(), &mTargetPos, owner);

  HPathCell blockedCell{};
  std::memcpy(&blockedCell, &mLastBlockedCell, sizeof(blockedCell));
  archive->Write(CachedHPathCellType(), &blockedCell, owner);

  archive->Write(CachedNavGoalType(), &mGoal, owner);
  archive->Write(CachedLayerType(), &mLastPathLayerToken, owner);
  WritePointerWithType(archive, mSim, CachedSimType(), gpg::TrackedPointerState::Unowned, owner);

  archive->WriteInt(mLastPathNodeIndex);
  archive->WriteInt(mPathSearchFailCount);
  archive->WriteInt(mPathRetryDelayFrames);
  archive->WriteInt(mNoForwardDistanceFailCount);
  archive->WriteFloat(mRepathDistanceThreshold);
  archive->WriteUInt(static_cast<unsigned int>(mLastRepathTick));
  archive->WriteInt(mNoProgressTickCount);
  archive->WriteUInt(static_cast<unsigned int>(mLastFormationSyncTick));
  archive->Write(CachedWeakUnitType(), &mLeaderLink, owner);
  archive->Write(CachedVector3Type(), &mLeaderTargetPos, owner);
  archive->WriteBool(mIsInFormation != 0u);
  archive->WriteBool(mLeaderBusy != 0u);
  archive->WriteBool(mHasLeaderTargetPos != 0u);
  archive->WriteBool(mHasForwardProbe != 0u);
  archive->WriteBool(mRepathRequested != 0u);
  archive->WriteBool(mUseExtendedPathProbe != 0u);
  archive->WriteBool(mTargetWithinOneCell != 0u);
  archive->Write(CachedSearchType(), &mPathRequestMode, owner);
  archive->WriteInt(mPathRequestCountdown);
  archive->WriteInt(mTickBucket7);
  archive->WriteInt(mTickBucket13);
}

