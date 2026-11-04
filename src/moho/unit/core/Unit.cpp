#include "moho/unit/core/UnitPrivate2.h"

namespace moho
{
  /**
   * Address: 0x00720F70 (FUN_00720F70, Moho::COORDS_CanMoveAt)
   *
   * What it does:
   * Validates whether `moveUnit` can occupy/move through `*pos` while filtering
   * nearby collision occupants against movement/attachment/formation rules.
   */
  bool COORDS_CanMoveAt(SOCellPos* pos, COGrid* grid, Unit* moveUnit, bool disallowAttached, Unit* ignoreUnit)
  {
    if (moveUnit == nullptr) {
      return false;
    }

    // Movement-rule category sets, resolved once up front (order preserved).
    RRuleGameRules* const rules = moveUnit->SimulationRef->mRules;
    const EntityCategorySet* const catFerryBeacon = rules->GetEntityCategory("FERRYBEACON");
    const EntityCategorySet* const catPodStagingPlatform = rules->GetEntityCategory("PODSTAGINGPLATFORM");

    const SFootprint& footprint = moveUnit->GetFootprint();
    const ELayer moveLayer = moveUnit->mVarDat.mLayerMask;
    const bool moveUnitHasStorage = moveUnit->AiTransport != nullptr;

    // Footprint-sized query box: horizontal side = max(sizeX, sizeZ); Y spans
    // [-1000, 1000] (effectively unbounded vertical), anchored at the cell.
    const int maxFootprintSide = std::max<int>(footprint.mSizeX, footprint.mSizeZ);
    Wm3::AxisAlignedBox3f box{};
    box.Min.x = static_cast<float>(pos->x);
    box.Max.x = static_cast<float>(pos->x + maxFootprintSide);
    box.Min.y = -1000.0f;
    box.Max.y = 1000.0f;
    box.Min.z = static_cast<float>(pos->z);
    box.Max.z = static_cast<float>(pos->z + maxFootprintSide);

    gpg::core::FastVectorN<CollisionResult, 10> into{};
    GatherUnmarkedUnitsInBox(*grid, box, into);

    for (const CollisionResult& hit : into) {
      Entity* const source = hit.sourceEntity;
      Unit* const curUnit = (source != nullptr) ? source->IsUnit() : nullptr;

      // Ignore the requested unit and any non-unit occupant.
      if (curUnit == ignoreUnit || curUnit == nullptr) {
        continue;
      }

      // Dead / under-construction / self never block.
      if (curUnit->IsDead()) {
        continue;
      }
      if (curUnit->IsBeingBuilt()) {
        continue;
      }
      if (curUnit == moveUnit) {
        continue;
      }

      // Layer filter: air occupants never block ground movement, and a sub mover
      // is only blocked by occupants sharing its exact layer.
      const ELayer curLayer = curUnit->mVarDat.mLayerMask;
      if (curLayer == LAYER_Air || (moveLayer != curLayer && moveLayer == LAYER_Sub)) {
        continue;
      }

      // A ferry-beacon we ourselves created does not block us.
      if (EntityCategory::HasBlueprint(curUnit->GetBlueprint(), catFerryBeacon)) {
        if (curUnit->GetCreator() == moveUnit) {
          continue;
        }
      }

      // Transport-style blocker: has an AiTransport and is not a pod-staging
      // platform (the loop `break` path in the decompiler). Otherwise fall
      // through to the general velocity/attachment logic.
      bool blockedByTransport = false;
      if (curUnit->AiTransport != nullptr) {
        if (!EntityCategory::HasBlueprint(curUnit->GetBlueprint(), catPodStagingPlatform)) {
          blockedByTransport = true;
        }
      }

      // Both the transport-blocker path and the velocity path converge on the
      // same formation/attached decision. `blockOccupant` requests the
      // "this occupant blocks -> return false" outcome (unless it is attached).
      bool blockOccupant = false;

      if (blockedByTransport) {
        if (curUnit->mVarDat.mLayerMask == LAYER_Air) {
          continue;
        }
        if (disallowAttached) {
          blockOccupant = true;
        } else if (!moveUnit->IsSameFormationLayerWith(curUnit)) {
          blockOccupant = true;
        }
        // else same formation layer -> does not block.
      } else {
        // Velocity path: velocity/compare evaluated before the layer test, as in
        // the binary. The binary compares velocity to a static zero vector with
        // Wm3::Vector3<float>::CompareArrays (FUN_004F0A50, a 12-byte memcmp),
        // i.e. WildMagic's own operator!= -- an exact bit compare, so -0.0f
        // counts as moving.
        const Wm3::Vec3f curVel = curUnit->GetVelocity();
        const Wm3::Vec3f kZeroVelocity{0.0f, 0.0f, 0.0f};
        const bool isMoving = curVel != kZeroVelocity;

        if (curUnit->mVarDat.mLayerMask == LAYER_Air) {
          continue;
        }

        if (moveUnitHasStorage) {
          // We are a transport: a moving occupant, or one we are not currently
          // trying to load, does not block us here.
          if (isMoving) {
            continue;
          }
          if (moveUnit->IsUnitState(UNITSTATE_TransportLoading)) {
            continue;
          }
        }

        if (disallowAttached) {
          blockOccupant = true;
        } else if (isMoving) {
          continue;
        } else if (!moveUnit->IsSameFormationLayerWith(curUnit)) {
          blockOccupant = true;
        }
        // else stationary same-formation occupant -> does not block.
      }

      // Shared attachment gate: a blocking occupant still does NOT block if it is
      // itself attached (riding something rather than occupying the cell).
      if (blockOccupant && !curUnit->IsUnitState(UNITSTATE_Attached)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0062ABA0 (FUN_0062ABA0, sub_62ABA0)
   *
   * IDA signature:
   * char __usercall sub_62ABA0@<al>(Wm3::Vector3f *a1@<edi>, Moho::Unit *a2@<esi>, int a3);
   *
   * What it does:
   * Converts `worldPosition` to the unit footprint's origin cell and asks the
   * occupancy grid whether the unit is blocked there under `mode`.
   *
   * The conversion is the same one `SFootprint::ToCellPos` performs, and it
   * rounds: the binary uses two bare fistp stores with no __ftol call.
   */
  bool UnitIsBlockedAt(const Wm3::Vec3f& worldPosition, Unit* const unit, const int mode)
  {
    const SFootprint& footprint = unit->GetFootprint();
    const SOCellPos cellPos = footprint.ToCellPos(worldPosition);
    return COGrid::UnitIsBlocked(cellPos, *unit->SimulationRef->mOGrid, unit, mode);
  }

  /**
   * Address: inlined at 0x00597D33-0x00597D6A and 0x00598031-0x0059807A
   * (Moho::Sim::DoCollisionsFor, FUN_00597CD0)
   *
   * What it does:
   * See the header declaration - density folded over the bounding-box volume.
   */
  float BlueprintCollisionMass(const RUnitBlueprint& blueprint) noexcept
  {
    return blueprint.mAverageDensity * blueprint.mSizeZ * blueprint.mSizeY * blueprint.mSizeX;
  }

  /**
   * Address: inlined at 0x00598086-0x005980B8 and 0x0059813E-0x0059816F
   * (Moho::Sim::DoCollisionsFor, FUN_00597CD0)
   *
   * What it does:
   * See the header declaration - the footprint-flag gate on receiving an
   * impulse.
   */
  bool CollisionImpulseAllowed(const Unit& pushed, const Unit& against) noexcept
  {
    const std::uint8_t pushedFlags = static_cast<std::uint8_t>(pushed.GetFootprint().mFlags);
    const std::uint8_t againstFlags = static_cast<std::uint8_t>(against.GetFootprint().mFlags);
    constexpr std::uint8_t kIgnoreStructures = static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures);
    return pushedFlags == static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_None) ||
      ((pushedFlags & kIgnoreStructures) != 0u && (againstFlags & kIgnoreStructures) != 0u);
  }

  /**
   * FAF divergence from the shipped binary - not a recovered function.
   *
   * What it does:
   * See the header declaration. Every gate below mirrors one the collision
   * resolver applies before it will actually move `obstacle`, so the planner
   * only walks through what the physics really does displace:
   *   - `IsMobile` / `UNITSTATE_Immobile` mirror the two impulse branches'
   *     own immobility tests (asm 0x005980C4, 0x00598177);
   *   - `CollisionImpulseAllowed(obstacle, mover)` is the candidate-impulse
   *     branch's footprint gate, receiver first (asm 0x0059813E);
   *   - the mass comparison is the momentum split, strengthened from the
   *     binary's `share > 0.1` acceptance to a clear-dominance margin.
   */
  bool UnitCanShoveAside(const Unit& mover, const Unit& obstacle) noexcept
  {
    if constexpr (!kBumpThroughSpamEnabled) {
      return false;
    } else {
      if (!obstacle.IsMobile() || obstacle.IsUnitState(UNITSTATE_Immobile)) {
        return false;
      }
      if (!CollisionImpulseAllowed(obstacle, mover)) {
        return false;
      }

      const RUnitBlueprint* const moverBlueprint = mover.GetBlueprint();
      const RUnitBlueprint* const obstacleBlueprint = obstacle.GetBlueprint();
      if (moverBlueprint == nullptr || obstacleBlueprint == nullptr) {
        return false;
      }

      return BlueprintCollisionMass(*moverBlueprint) >
        BlueprintCollisionMass(*obstacleBlueprint) * kBumpThroughMassRatio;
    }
  }

  /**
   * Address: 0x0062AA90 (FUN_0062AA90, func_UnitWontFitAt)
   *
   * What it does:
   * Returns true when `unit` cannot place its footprint at `worldPosition`
   * due to map bounds or occupancy-cap fit checks.
   */
  bool UnitWontFitAt(const Wm3::Vec3f& worldPosition, const Unit* const unit)
  {
    const SFootprint& footprint = unit->GetFootprint();
    const Sim& sim = *unit->SimulationRef;
    const STIMap& mapData = *sim.mMapData;
    const bool useWholeMap = (unit->ArmyRef != nullptr) ? unit->ArmyRef->UseWholeMap() : false;
    if (!mapData.IsWithin(worldPosition, 0.0f, useWholeMap)) {
      return true;
    }

    // The binary converts these with fld/fistp (0x0062AB0D-0x0062AB11 and
    // 0x0062AB32-0x0062AB36), i.e. round-to-nearest under the default FPU
    // control word - not truncation. `SFootprint::ToCellPos` (FUN_00579300) is
    // the same computation and already rounds correctly, so defer to it rather
    // than open-code a second copy.
    const SOCellPos cellPos = footprint.ToCellPos(worldPosition);

    EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(footprint, mapData, cellPos);
    if (unit->mVarDat.mLayerMask == LAYER_Water) {
      occupancyCaps = static_cast<EOccupancyCaps>(
        static_cast<std::uint8_t>(occupancyCaps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)
      );
    }

    return static_cast<std::uint8_t>(OCCUPY_FootprintFits(*sim.mOGrid, cellPos, footprint, occupancyCaps)) == 0u;
  }
}

namespace
{
  // Guard condition recovered from Unit::ToggleScriptBit: state 14 == UNITSTATE_Attached.
  constexpr EUnitState kTransportScriptBitGuardState = UNITSTATE_Attached;
  constexpr std::uint32_t kCommandCapPause = 0x00020000u;  // RULEUCC_Pause
  constexpr std::uint32_t kToggleCapGeneric = 0x00000040u; // RULEUTC_GenericToggle
  constexpr const char* kUnitOnProductionActiveScript = "OnProductionActive";
  constexpr const char* kUnitOnProductionInactiveScript = "OnProductionInActive";

  void ClearGuardFormation(Unit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    IFormationInstance* const guardFormation = unit->GuardFormation;
    unit->GuardFormation = nullptr;
    delete guardFormation;
  }

  [[nodiscard]] const char* UnitStateToDebugLexical(const EUnitState state) noexcept
  {
    switch (state) {
    case UNITSTATE_Immobile:
      return "Immobile";
    case UNITSTATE_Moving:
      return "Moving";
    case UNITSTATE_Attacking:
      return "Attacking";
    case UNITSTATE_Guarding:
      return "Guarding";
    case UNITSTATE_Building:
      return "Building";
    case UNITSTATE_Upgrading:
      return "Upgrading";
    case UNITSTATE_WaitingForTransport:
      return "WaitingForTransport";
    case UNITSTATE_TransportLoading:
      return "TransportLoading";
    case UNITSTATE_TransportUnloading:
      return "TransportUnloading";
    case UNITSTATE_MovingDown:
      return "MovingDown";
    case UNITSTATE_MovingUp:
      return "MovingUp";
    case UNITSTATE_Patrolling:
      return "Patrolling";
    case UNITSTATE_Busy:
      return "Busy";
    case UNITSTATE_Attached:
      return "Attached";
    case UNITSTATE_BeingReclaimed:
      return "BeingReclaimed";
    case UNITSTATE_Repairing:
      return "Repairing";
    case UNITSTATE_Diving:
      return "Diving";
    case UNITSTATE_Surfacing:
      return "Surfacing";
    case UNITSTATE_Teleporting:
      return "Teleporting";
    case UNITSTATE_Ferrying:
      return "Ferrying";
    case UNITSTATE_WaitForFerry:
      return "WaitForFerry";
    case UNITSTATE_AssistMoving:
      return "AssistMoving";
    case UNITSTATE_PathFinding:
      return "PathFinding";
    case UNITSTATE_ProblemGettingToGoal:
      return "ProblemGettingToGoal";
    case UNITSTATE_NeedToTerminateTask:
      return "NeedToTerminateTask";
    case UNITSTATE_Capturing:
      return "Capturing";
    case UNITSTATE_BeingCaptured:
      return "BeingCaptured";
    case UNITSTATE_Reclaiming:
      return "Reclaiming";
    case UNITSTATE_AssistingCommander:
      return "AssistingCommander";
    case UNITSTATE_Refueling:
      return "Refueling";
    case UNITSTATE_GuardBusy:
      return "GuardBusy";
    case UNITSTATE_ForceSpeedThrough:
      return "ForceSpeedThrough";
    case UNITSTATE_UnSelectable:
      return "UnSelectable";
    case UNITSTATE_DoNotTarget:
      return "DoNotTarget";
    case UNITSTATE_LandingOnPlatform:
      return "LandingOnPlatform";
    case UNITSTATE_CannotFindPlaceToLand:
      return "CannotFindPlaceToLand";
    case UNITSTATE_BeingUpgraded:
      return "BeingUpgraded";
    case UNITSTATE_Enhancing:
      return "Enhancing";
    case UNITSTATE_BeingBuilt:
      return "BeingBuilt";
    case UNITSTATE_NoReclaim:
      return "NoReclaim";
    case UNITSTATE_NoCost:
      return "NoCost";
    case UNITSTATE_BlockCommandQueue:
      return "BlockCommandQueue";
    case UNITSTATE_MakingAttackRun:
      return "MakingAttackRun";
    case UNITSTATE_HoldingPattern:
      return "HoldingPattern";
    case UNITSTATE_SiloBuildingAmmo:
      return "SiloBuildingAmmo";
    default:
      return "";
    }
  }

  void AddIntStatCounter(StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    statItem->AddPrimaryBits(delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  /**
   * Address: 0x00593290 (FUN_00593290)
   *
   * What it does:
   * Resolves one army stat lane by name, synchronizes it as a float, and
   * applies one pointed float delta through `StatItem::AddFloat`.
   */
  std::int32_t AddArmyStatFloatByName(
    CArmyStats* const armyStats,
    float* const deltaValue,
    const char* const statPath
  )
  {
    CArmyStatItem* const statItem = armyStats->TraverseTables(statPath, true);
    statItem->SynchronizeAsFloat();
    return statItem->AddFloat(deltaValue);
  }

  void IncrementArmyBlueprintFloatStat(
    CArmyStats* const armyStats,
    const char* const statPath,
    const RUnitBlueprint* const blueprint,
    const float delta
  )
  {
    if (armyStats == nullptr || statPath == nullptr || blueprint == nullptr) {
      return;
    }

    (void)armyStats->AddBlueprintStatDelta(statPath, blueprint, delta);
  }

  void IncrementArmyIntStatByName(CArmyStats* const armyStats, const char* const statPath)
  {
    if (armyStats == nullptr || statPath == nullptr) {
      return;
    }

    CArmyStatItem* const item = armyStats->GetItem(statPath);
    if (item == nullptr) {
      return;
    }

    item->SynchronizeAsInt();
    AddIntStatCounter(item, 1L);
  }

  [[nodiscard]] bool IsWithinPlayableRectOrNotCommander(const Unit& unit)
  {
    static const std::string kCommanderCategory = "COMMAND";
    if (!unit.Entity::IsInCategory(kCommanderCategory.c_str())) {
      return true;
    }

    const Sim* const sim = unit.SimulationRef;
    const STIMap* const mapData = (sim != nullptr) ? sim->mMapData : nullptr;
    if (mapData == nullptr) {
      return true;
    }

    const Wm3::Vec3f& position = unit.GetPosition();
    const gpg::Rect2i playableRect = mapData->mPlayableRect;
    return !(static_cast<float>(playableRect.x0) > position.x || static_cast<float>(playableRect.z0) > position.z ||
             position.x > static_cast<float>(playableRect.x1) || position.z > static_cast<float>(playableRect.z1));
  }

  void IncrementAIDebugStateStat(CArmyStats* const armyStats, const msvc8::string& statPath)
  {
    if (!armyStats || statPath.empty()) {
      return;
    }

    CArmyStatItem* const item = armyStats->TraverseTables(statPath.c_str(), true);
    if (!item) {
      return;
    }

    item->SynchronizeAsInt();
    AddIntStatCounter(item, 1L);
  }

  [[nodiscard]] std::int32_t PickUniformIndexFromU32(const std::uint32_t randomValue, const std::uint32_t count) noexcept
  {
    const std::uint64_t product = static_cast<std::uint64_t>(randomValue) * static_cast<std::uint64_t>(count);
    return static_cast<std::int32_t>(product >> 32u);
  }

  [[nodiscard]] bool HasFootprintFlag(const EFootprintFlags value, const EFootprintFlags flag) noexcept
  {
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
  }

  // Ground truth for both reachable callers (`FUN_0062EAC0.c`,
  // `func_UnitMoreInLineToOther`; `FUN_006A8C20.c`, `Unit::GetFormationVector`)
  // builds the forward vector via `Moho::VAxes3::VAxes3(&result, &orient)`
  // and reads its `.vZ` member -- NOT the generic `Quaternion::Rotate((0,0,
  // 1))` (upstream WildMagic, `.w`-scalar `ToMat3()`) the previous body used.
  // `VAxes3::vZ` is the scalar-first rotation matrix's row 0 (see
  // `VAxes3::VAxes3`'s doc comment in `MathReflection.cpp` for the
  // constructor fix this depends on) -- numerically the same as
  // `Moho::MultQuadVec` against `(0,0,1)` would give, once `VAxes3`'s own
  // constructor is correct.
  //
  // The flattened `(vZ.x, 0, vZ.z)` is normalised by `NormalizeVectorInto`
  // (0x0044F7E0, called at 0x006A8CF3; inlined with the same length-> 0
  // threshold and reciprocal multiply at 0x0062EAD8-0x0062EB4B). There is
  // no near-zero tolerance: any positive length normalises.
  [[nodiscard]] Wm3::Vector3f ForwardXZ(const Unit& unit) noexcept
  {
    const moho::VAxes3 axes(unit.GetTransform().orient_);
    const Wm3::Vector3f flattened{axes.vZ.x, 0.0f, axes.vZ.z};
    Wm3::Vector3f forward{};
    (void)moho::NormalizeVectorInto(&forward, flattened);
    return forward;
  }

  [[nodiscard]] const Wm3::Vector3f& InvalidBombDropSolutionLane() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalidVector{};

    if (!initialized) {
      invalidVector = Wm3::Vector3f::NaN();
      initialized = true;
    }

    return invalidVector;
  }

  /**
   * Address: 0x0062CEF0 (FUN_0062CEF0, func_CalcBombDrop)
   *
   * What it does:
   * Solves one ballistic intercept lane from current/target position,
   * velocity, and gravity; writes NaN-vector lanes when no valid time root
   * exists.
   */
  [[nodiscard]] Wm3::Vector3f* ComputeBombDropAimPoint(
    const Wm3::Vector3f& velocity,
    Wm3::Vector3f* const out,
    const Wm3::Vector3f& gravity,
    const Wm3::Vector3f& targetPosition,
    const Wm3::Vector3f& currentPosition
  ) noexcept
  {
    const float gravityMagnitude = std::sqrt((gravity.x * gravity.x) + (gravity.y * gravity.y) + (gravity.z * gravity.z));

    // 0x0062CF38-0x0062CF83: `-0.0f - g` per lane, then Wm3 `Normalize`
    // (0x00452AF0).
    Wm3::Vector3f oppositeGravityDirection{
      -gravity.x,
      -gravity.y,
      -gravity.z,
    };
    Wm3::Vector3f::Normalize(&oppositeGravityDirection);
    const Wm3::Vector3f& n = oppositeGravityDirection;

    // Every dot product and squared length below accumulates z first, then
    // x (or y for the squared lengths), then the remaining lane, exactly as
    // the SSE chains at 0x0062CF8A-0x0062D0E6 do.
    const float velocityAlongGravity = ((velocity.z * n.z) + (velocity.x * n.x)) + (velocity.y * n.y);
    const float projectedSpeedX = n.x * velocityAlongGravity;
    const float projectedSpeedY = velocityAlongGravity * n.y;
    const float projectedSpeedZ = n.z * velocityAlongGravity;
    const float projectedSpeedMagnitude = std::sqrt(
      ((projectedSpeedZ * projectedSpeedZ) + (projectedSpeedY * projectedSpeedY)) + (projectedSpeedX * projectedSpeedX)
    );

    const float deltaX = currentPosition.x - targetPosition.x;
    const float deltaY = currentPosition.y - targetPosition.y;
    const float deltaZ = currentPosition.z - targetPosition.z;
    const float targetDeltaAlongGravity = ((deltaZ * n.z) + (deltaX * n.x)) + (deltaY * n.y);

    const float projectedDistanceX = n.x * targetDeltaAlongGravity;
    const float projectedDistanceY = targetDeltaAlongGravity * n.y;
    const float projectedDistanceZ = n.z * targetDeltaAlongGravity;
    const float projectedDistanceMagnitude = std::sqrt(
      ((projectedDistanceZ * projectedDistanceZ) + (projectedDistanceY * projectedDistanceY)) +
      (projectedDistanceX * projectedDistanceX)
    );

    // 0x0062D0F0: `comiss 0, dot` / `jbe` -> +2 unless the dot is strictly
    // negative (an unordered dot picks +2).
    const float projectedDistanceDot =
      ((projectedDistanceZ * n.z) + (projectedDistanceX * n.x)) + (projectedDistanceY * n.y);
    const float signedScale = (0.0f > projectedDistanceDot) ? -2.0f : 2.0f;

    const float rootDiscriminant = ((signedScale * projectedDistanceMagnitude) * gravityMagnitude) +
      (projectedSpeedMagnitude * projectedSpeedMagnitude);

    if (rootDiscriminant < 0.0f) {
      *out = InvalidBombDropSolutionLane();
      return out;
    }

    const float root = std::sqrt(rootDiscriminant);
    const float inverseGravityMagnitude = 1.0f / gravityMagnitude;
    float travelTime = -((root - projectedSpeedMagnitude) * inverseGravityMagnitude);
    // 0x0062D1C8 `jb` / 0x0062D28C `jae`: an unordered time counts as
    // negative at both tests.
    if (!(travelTime >= 0.0f)) {
      travelTime = -(((-projectedSpeedMagnitude) - root) * inverseGravityMagnitude);
    }

    if (!(travelTime >= 0.0f)) {
      *out = InvalidBombDropSolutionLane();
      return out;
    }

    // 0x0062D20C-0x0062D231: each gravity lane is `((g * 0.5f) * t) * t`,
    // multiplied left to right, then the `v * t` lane is added to it.
    out->x = targetPosition.x - ((((gravity.x * 0.5f) * travelTime) * travelTime) + (velocity.x * travelTime));
    out->y = targetPosition.y - ((((gravity.y * 0.5f) * travelTime) * travelTime) + (velocity.y * travelTime));
    out->z = targetPosition.z - ((((gravity.z * 0.5f) * travelTime) * travelTime) + (velocity.z * travelTime));
    return out;
  }

  void FillReservedOgridRect(Unit& unit, const bool occupied) noexcept
  {
    if (!unit.SimulationRef || !unit.SimulationRef->mOGrid) {
      return;
    }

    const gpg::Rect2i ogridRect = GetReservedOgridRect(unit);
    if (occupied) {
      unit.SimulationRef->mOGrid->OccupyRect(ogridRect);
    } else {
      unit.SimulationRef->mOGrid->VacateRect(ogridRect);
    }
  }

  [[nodiscard]] Wm3::Box3f BuildAxisAlignedCollisionProbe(
    const Wm3::Vec3f& center,
    const Wm3::Vec3f& extents
  ) noexcept
  {
    Wm3::Box3f probe{};
    probe.Center[0] = center.x;
    probe.Center[1] = center.y;
    probe.Center[2] = center.z;

    probe.Axis[0][0] = 1.0f;
    probe.Axis[0][1] = 0.0f;
    probe.Axis[0][2] = 0.0f;
    probe.Axis[1][0] = 0.0f;
    probe.Axis[1][1] = 1.0f;
    probe.Axis[1][2] = 0.0f;
    probe.Axis[2][0] = 0.0f;
    probe.Axis[2][1] = 0.0f;
    probe.Axis[2][2] = 1.0f;

    probe.Extent[0] = extents.x;
    probe.Extent[1] = extents.y;
    probe.Extent[2] = extents.z;
    return probe;
  }

  // 0x006A7827..0x006A784F: `addss 0.5`, stored to float, then the inlined floor.
  [[nodiscard]] std::int32_t RoundOccupyRectEdge(const float value) noexcept
  {
    return msvc8::FloorToIntX87(value + 0.5f);
  }

  void DrawRaisedPlatformEdge(
    CDebugCanvas& canvas,
    const Wm3::Vector3f& a,
    const Wm3::Vector3f& b
  )
  {
    SDebugLine line{};
    line.p0 = a;
    line.p1 = b;
    line.depth0 = -16711936;
    line.depth1 = -16711936;
    canvas.DebugDrawLine(line);
  }

  /**
   * Address: 0x0062EAC0 (FUN_0062EAC0, func_UnitMoreInLineToOther)
   */
  [[nodiscard]] const Unit* UnitMoreInLineToOther(const Unit* const a1, const Unit* const a2) noexcept
  {
    if (!a1 || !a2) {
      return nullptr;
    }

    // 0x0062EC3C / 0x0062ED0B: the inlined direction normalise sums the
    // squared lanes as `(dz*dz + dy*dy) + dx*dx`, then multiplies by
    // `1/len` when `len > 0` (zero vector otherwise).
    const auto directionTo = [](const Wm3::Vec3f& from, const Wm3::Vec3f& to) noexcept {
      const Wm3::Vector3f delta{to.x - from.x, to.y - from.y, to.z - from.z};
      const float length = std::sqrt(((delta.z * delta.z) + (delta.y * delta.y)) + (delta.x * delta.x));
      if (!(length > 0.0f)) {
        return Wm3::Vector3f{0.0f, 0.0f, 0.0f};
      }
      const float inverse = 1.0f / length;
      return Wm3::Vector3f{inverse * delta.x, delta.y * inverse, delta.z * inverse};
    };

    const Wm3::Vector3f a2Forward = ForwardXZ(*a2);
    const Wm3::Vector3f a1Forward = ForwardXZ(*a1);
    const Wm3::Vector3f a2ToA1 = directionTo(a2->GetPosition(), a1->GetPosition());
    const Wm3::Vector3f a1ToA2 = directionTo(a1->GetPosition(), a2->GetPosition());

    // 0x0062ED8F-0x0062EDD4: dot products accumulate `(y + z) + x` for the
    // first and `(z + y) + x` for the second.
    const float a2Alignment =
      ((a2ToA1.y * a2Forward.y) + (a2ToA1.z * a2Forward.z)) + (a2ToA1.x * a2Forward.x);
    const float a1Alignment =
      ((a1ToA2.z * a1Forward.z) + (a1ToA2.y * a1Forward.y)) + (a1ToA2.x * a1Forward.x);
    if (a2Alignment <= 0.0f && a1Alignment <= 0.0f) {
      return nullptr;
    }
    // 0x0062EDE6: `comiss a2Alignment, a1Alignment` / `ja` picks a1; an
    // unordered compare falls through to a2.
    return (a2Alignment > a1Alignment) ? a1 : a2;
  }
}



/**
  * Alias of FUN_00593970 (non-canonical helper lane).
 *
 * What it does:
 * Public wrapper that mirrors the anonymous-namespace `GetUnitOptional`
 * helper: non-throwing conversion from Lua payload to `Unit*`, returning
 * null when the payload is missing or of a non-unit runtime type.
 */
moho::Unit* moho::SCR_GetUnitOptional(const LuaPlus::LuaObject& unitObject)
{
  static gpg::RType* sUnitType = nullptr;
  if (sUnitType == nullptr) {
    sUnitType = gpg::LookupRType(typeid(Unit));
  }

  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(unitObject);
  if (scriptObject == nullptr) {
    return nullptr;
  }

  const gpg::RRef sourceRef = scriptObject->GetDerivedObjectRef();
  const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, sUnitType);
  return static_cast<Unit*>(unitRef.mObj);
}

CScrLuaMetatableFactory<Unit> CScrLuaMetatableFactory<Unit>::sInstance{};

CScrLuaMetatableFactory<Unit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<Unit>& CScrLuaMetatableFactory<Unit>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject CScrLuaMetatableFactory<Unit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00564660 (FUN_00564660, ?ARMOR_GetArmorDefinations@Moho@@YA?AV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
 *
 * What it does:
 * Loads `/lua/armordefinition.lua`, resolves `armordefinition` table rows for
 * one armor type, and returns raw `<damageType multiplier>` string lanes.
 */
msvc8::list<msvc8::string> moho::ARMOR_GetArmorDefinations(
  LuaPlus::LuaState* const state,
  const gpg::StrArg armorTypeName
)
{
  msvc8::list<msvc8::string> definitions{};

  LuaPlus::LuaObject armorModule = SCR_Import(state, "/lua/armordefinition.lua");
  if (armorModule.IsNil()) {
    gpg::Warnf("can't load the armordefinition module -- no armor for you.");
    return definitions;
  }

  LuaPlus::LuaObject armorTable = armorModule.GetByName("armordefinition");
  if (!armorTable.IsTable()) {
    gpg::Warnf("The armor module didn't define any armors.  Hmm Odd?");
    return definitions;
  }

  const int armorClassCount = armorTable.GetN();
  for (int armorClassIndex = 1; armorClassIndex <= armorClassCount; ++armorClassIndex) {
    LuaPlus::LuaObject armorClass = armorTable.GetByIndex(armorClassIndex);
    if (!armorClass.IsTable()) {
      continue;
    }

    LuaPlus::LuaObject classNameObject = armorClass.GetByIndex(1);
    const char* const className = classNameObject.GetString();
    if (!className || !armorTypeName || _stricmp(className, armorTypeName) != 0) {
      continue;
    }

    const int definitionCount = armorClass.GetN();
    for (int definitionIndex = 2; definitionIndex <= definitionCount; ++definitionIndex) {
      LuaPlus::LuaObject definitionObject = armorClass.GetByIndex(definitionIndex);
      const char* const definitionText = definitionObject.GetString();
      if (definitionText) {
        definitions.push_back(msvc8::string(definitionText));
      }
    }

    break;
  }

  // 0x00564970 is `func_StringLinkedListCpyRange` -- the copy constructor of
  // the return value, emitted because NRVO does not apply to a function with
  // three return statements. The binary has ONE local: the tail at LABEL_14
  // is `func_StringLinkedListCpyRange(dest, &list)` then `func_FreeLinkedList
  // (&list)`, i.e. copy-out then destroy. The source line is just this.
  return definitions;
}

/**
 * Address: 0x006C3A10 (FUN_006C3A10)
 *
 * What it does:
 * Stores one stunned-state tick lane.
 */
void Unit::SetStunnedStateRaw(const std::int32_t stunnedState) noexcept
{
  mUnitVarDat.mStunTicks = stunnedState;
}

/**
 * Address: 0x006C3A20 (FUN_006C3A20)
 *
 * What it does:
 * Stores one overcharge-paused boolean lane.
 */
void Unit::SetOverchargePausedFlag(const bool paused) noexcept
{
  mUnitVarDat.mOverchargePaused = paused;
}

/**
 * Address: 0x006C3A30 (FUN_006C3A30)
 *
 * What it does:
 * Returns the overcharge-paused boolean lane.
 */
bool Unit::IsOverchargePausedFlag() const noexcept
{
  return mUnitVarDat.mOverchargePaused;
}

/**
 * Address: 0x006C3A40 (FUN_006C3A40)
 *
 * What it does:
 * Returns the consumption-active boolean lane.
 */
bool Unit::IsConsumptionActiveFlag() const noexcept
{
  return ConsumptionActive;
}

/**
 * Address: 0x006C3A50 (FUN_006C3A50)
 *
 * What it does:
 * Returns the valid-target boolean lane.
 */
bool Unit::IsValidTargetFlag() const noexcept
{
  return mUnitVarDat.mIsValidTarget;
}

/**
 * Address: 0x006C3A60 (FUN_006C3A60)
 *
 * What it does:
 * Stores one valid-target boolean lane.
 */
void Unit::SetIsValidTargetFlag(const bool validTarget) noexcept
{
  mUnitVarDat.mIsValidTarget = validTarget;
}

/**
 * Address: 0x006C3A70 (FUN_006C3A70)
 *
 * What it does:
 * Returns the shield-ratio float lane.
 */
float Unit::GetShieldRatioRaw() const noexcept
{
  return mUnitVarDat.mShieldRatio;
}

/**
 * Address: 0x006C3A80 (FUN_006C3A80)
 *
 * What it does:
 * Stores one shield-ratio float lane.
 */
void Unit::SetShieldRatioRaw(const float shieldRatio) noexcept
{
  mUnitVarDat.mShieldRatio = shieldRatio;
}

/**
 * Address: 0x006C39F0 (FUN_006C39F0)
 *
 * What it does:
 * Rebinds this unit's creator weak-reference lane and marks game-data sync
 * dirty for replication.
 */
void moho::AssignCreatorWeakRefAndMarkSyncDirty(Unit* const unit, Unit* const creator)
{
  unit->CreatorRef.Set(creator);
  unit->NeedSyncGameData = true;
}

bool Unit::NeedsKillCleanup() const noexcept
{
  return mNeedsKillCleanup;
}

void Unit::ClearBeatResourceAccumulators() noexcept
{
  mUnitVarDat.mProduced = {};
  mUnitVarDat.mResourcesSpent = {};
}

CIntel* Unit::GetIntelManager() noexcept
{
  return mIntelManager;
}

CIntel const* Unit::GetIntelManager() const noexcept
{
  return mIntelManager;
}
namespace
{

  /**
   * Address: 0x006AB960 (FUN_006AB960, sub_6AB960)
   *
   * IDA signature:
   * unsigned int __usercall sub_6AB960@<eax>(
   *   gpg::fastvector_int* snapshot@<eax>,
   *   std::vector<WeakPtr<CUnitCommand>>* source@<ebx>);
   *
   * What it does:
   * Appends the `CmdId` of every live command in `source` (a weak-command
   * vector) onto the `snapshot` lane, in order. Each source slot is resolved
   * through its intrusive weak pointer; dead / cleared slots are skipped. The
   * caller has already reset `snapshot` to its inline storage, so this is the
   * pure append pass that rebuilds the per-sim command-id snapshot from the
   * owning queue's live commands (`command->mConstDat.cmd`).
   */
  void AppendLiveCommandIdsToSnapshot(
    gpg::fastvector_n<moho::CmdId, 8>& snapshot,
    const msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& source
  )
  {
    for (const moho::WeakPtr<moho::CUnitCommand>& commandWeakPtr : source) {
      const moho::CUnitCommand* const command = commandWeakPtr.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }
      snapshot.push_back(command->mConstDat.cmd);
    }
  }

  class UnitWeaponInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "UnitWeaponInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::UnitWeaponInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  class SSTIUnitVariableDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIUnitVariableData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIUnitVariableData);
      gpg::RType::Init();
      Finish();
    }
  };

  /**
   * Address: 0x0055C160 (FUN_0055C160, Moho::UnitWeaponInfoSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `UnitWeaponInfo`. Forwards the
   * reflected object pointer to `UnitWeaponInfo::MemberDeserialize`; `version`
   * and the owner-ref lane are unused by the member (mirrors the binary tail
   * call).
   */
  void DeserializeUnitWeaponInfoSerializerCallback(
    gpg::ReadArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::UnitWeaponInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0055C170 (FUN_0055C170, Moho::UnitWeaponInfoSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `UnitWeaponInfo`. Forwards the
   * reflected object pointer to `UnitWeaponInfo::MemberSerialize`; `version`
   * and the owner-ref lane are unused by the member (mirrors the binary tail
   * call).
   */
  void SerializeUnitWeaponInfoSerializerCallback(
    gpg::WriteArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::UnitWeaponInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x0055C760 (FUN_0055C760, Moho::SSTIUnitVariableDataSerializer::Deserialize)
   *
   * IDA signature:
   * int sub_55C760(); // elided tail-jump: return sub_55E030();
   *
   * What it does:
   * Reflection load-callback facade for `SSTIUnitVariableData`. Forwards the
   * reflected object pointer to the class member load body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump into
   * FUN_0055E030).
   */
  void SSTIUnitVariableDataSerializerDeserialize(
    gpg::ReadArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const data = reinterpret_cast<moho::SSTIUnitVariableData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0055C770 (FUN_0055C770, Moho::SSTIUnitVariableDataSerializer::Serialize)
   *
   * IDA signature:
   * int sub_55C770(); // elided tail-jump: return sub_55E420();
   *
   * What it does:
   * Reflection save-callback facade for `SSTIUnitVariableData`. Forwards the
   * reflected object pointer to the class member save body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump into
   * FUN_0055E420).
   */
  void SSTIUnitVariableDataSerializerSerialize(
    gpg::WriteArchive* const archive,
    const std::intptr_t objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const data = reinterpret_cast<moho::SSTIUnitVariableData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberSerialize(archive);
  }
}

namespace moho
{

/**
 * Address: 0x0055C020 (FUN_0055C020, preregister_UnitWeaponInfoTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `UnitWeaponInfo`.
 */
gpg::RType* preregister_UnitWeaponInfoTypeInfo()
{
  static UnitWeaponInfoTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(UnitWeaponInfo), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0055C620 (FUN_0055C620, preregister_SSTIUnitVariableDataTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `SSTIUnitVariableData`.
 */
gpg::RType* preregister_SSTIUnitVariableDataTypeInfo()
{
  static SSTIUnitVariableDataTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(SSTIUnitVariableData), &typeInfo);
  return &typeInfo;
}
}

namespace
{
  struct UnitTypeInfoPreRegisterBootstrap
  {
    UnitTypeInfoPreRegisterBootstrap()
    {
      (void)moho::preregister_UnitWeaponInfoTypeInfo();
      (void)moho::preregister_SSTIUnitVariableDataTypeInfo();
    }
  };

  [[maybe_unused]] UnitTypeInfoPreRegisterBootstrap gUnitTypeInfoPreRegisterBootstrap;

  /**
   * Address: 0x0055D980 (FUN_0055D980, copy_UnitWeaponInfo_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one half-open `UnitWeaponInfo` range into destination
   * storage using the engine `UnitWeaponInfo(const UnitWeaponInfo&)` copy
   * constructor (`FUN_0055D6F0`), destroying already-constructed entries
   * before rethrowing if a copy step throws.
   */
  UnitWeaponInfo* CopyUnitWeaponInfoRangeWithRollback(
    const UnitWeaponInfo* const sourceBegin,
    const UnitWeaponInfo* const sourceEnd,
    UnitWeaponInfo* const destinationBegin
  )
  {
    if (sourceBegin == sourceEnd) {
      return destinationBegin;
    }

    if (sourceBegin == nullptr || sourceEnd == nullptr || destinationBegin == nullptr) {
      return destinationBegin;
    }

    UnitWeaponInfo* destinationCursor = destinationBegin;
    try {
      for (const UnitWeaponInfo* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        ::new (destinationCursor) UnitWeaponInfo(*sourceCursor);
      }
      return destinationCursor;
    } catch (...) {
      while (destinationCursor != destinationBegin) {
        --destinationCursor;
        destinationCursor->~UnitWeaponInfo();
      }
      throw;
    }
  }
}



/**
 * Address: 0x0055B6E0 (FUN_0055B6E0, ??0UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes both category bitset lanes to empty inline storage and seeds
 * default layer/radius/UI range visual-id values.
 */
UnitWeaponInfo::UnitWeaponInfo()
  : mCat1()
  , mCat2()
  , mLayer(LAYER_None)
  , mMinRadius(0.0f)
  , mMaxRadius(10000.0f)
  , mEffectiveRadius(0.0f)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  mCat1.ResetToEmpty(EntityCategoryHelper{});
  mCat2.ResetToEmpty(EntityCategoryHelper{});
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
}

/**
 * Address: 0x0055D170 (FUN_0055D170, ??1UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Releases both UI visual-id strings and restores category bitset fastvector
 * lanes to their inline storage windows.
 */
UnitWeaponInfo::~UnitWeaponInfo()
{
  mUIMaxRangeVisualId.tidy(true, 0U);
  mUIMinRangeVisualId.tidy(true, 0U);
  mCat2.mBits.mWords.ResetStorageToInline();
  mCat1.mBits.mWords.ResetStorageToInline();
}

/**
 * Address: 0x0055D6F0 (FUN_0055D6F0, ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z)
 * Mangled: ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z
 *
 * IDA signature:
 * int __userpurge sub_55D6F0@<eax>(int source@<edi>, int destination);
 *
 * What it does:
 * Copy-constructs one `UnitWeaponInfo` from `other`. Each `EntityCategorySet`
 * lane is cloned field-wise (mUniverse + mBits.mFirstWordIndex header, then
 * the variable word list via `FastVectorN2RebindAndCopy`). Scalar layer/radius
 * lanes use plain assignment. Both UI range visual-id strings are brought up
 * to inline storage defaults (size 0, capacity 15) and then assigned from the
 * source strings.
 */
UnitWeaponInfo::UnitWeaponInfo(const UnitWeaponInfo& other)
  : mCat1()
  , mCat2()
  , mLayer(other.mLayer)
  , mMinRadius(other.mMinRadius)
  , mMaxRadius(other.mMaxRadius)
  , mEffectiveRadius(other.mEffectiveRadius)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  // --- mCat1: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat1.mBits.mWords, &other.mCat1.mBits.mWords
  );

  // --- mCat2: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat2.mBits.mWords, &other.mCat2.mBits.mWords
  );

  // --- UI range visual-id strings: inline-default then assign from source. ---
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);
}

/**
 * Address: 0x0055F210 (FUN_0055F210, sub_55F210)
 *
 * IDA signature:
 * int __usercall sub_55F210@<eax>(int a1@<eax>, int a2@<esi>);
 *
 * What it does:
 * Copy-assigns one already-constructed `UnitWeaponInfo` over another. Each
 * category lane is updated header-first (`mUniverse`, then
 * `mBits.mFirstWordIndex`) and its word list copy-assigned through the
 * `gpg::fastvector_uint::cpy` lane; layer/radius values are plain stores; both
 * UI range visual-id strings are re-assigned from the source.
 *
 * Unlike the copy constructor this does NOT rebind the word lists to inline
 * storage first - the destination already owns whatever buffer it has, which is
 * why the binary calls the copy lane directly at 0x0055F225 / 0x0055F23D.
 */
UnitWeaponInfo& UnitWeaponInfo::operator=(const UnitWeaponInfo& other)
{
  // No self-assignment guard: the binary has none. Aliasing is absorbed by the
  // fastvector copy lane and by msvc8::string::assign.
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  {
    mCat1.mBits.mWords = other.mCat1.mBits.mWords;
  }

  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  {
    mCat2.mBits.mWords = other.mCat2.mBits.mWords;
  }

  mLayer = other.mLayer;
  mMinRadius = other.mMinRadius;
  mMaxRadius = other.mMaxRadius;
  mEffectiveRadius = other.mEffectiveRadius;

  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);

  return *this;
}

/**
 * Address: 0x0055DA10 (FUN_0055DA10, Moho::UnitWeaponInfo::MemberDeserialize)
 *
 * What it does:
 * Loads category masks, layer/radius lanes, and both UI range visual-id
 * strings from one archive payload.
 */
void UnitWeaponInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(gpg::RTypeOf<EntityCategorySet>(), &mCat1, ownerRef);
  archive->Read(gpg::RTypeOf<EntityCategorySet>(), &mCat2, ownerRef);
  archive->Read(gpg::RTypeOf<ELayer>(), &mLayer, ownerRef);
  archive->ReadFloat(&mMinRadius);
  archive->ReadFloat(&mMaxRadius);
  archive->ReadFloat(&mEffectiveRadius);
  archive->ReadString(&mUIMinRangeVisualId);
  archive->ReadString(&mUIMaxRangeVisualId);
}

/**
 * Address: 0x0055DB00 (FUN_0055DB00, Moho::UnitWeaponInfo::MemberSerialize)
 *
 * What it does:
 * Stores category masks, layer/radius lanes, and both UI range visual-id
 * strings into one archive payload.
 */
void UnitWeaponInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(gpg::RTypeOf<EntityCategorySet>(), &mCat1, ownerRef);
  archive->Write(gpg::RTypeOf<EntityCategorySet>(), &mCat2, ownerRef);
  archive->Write(gpg::RTypeOf<ELayer>(), &mLayer, ownerRef);
  archive->WriteFloat(mMinRadius);
  archive->WriteFloat(mMaxRadius);
  archive->WriteFloat(mEffectiveRadius);
  archive->WriteString(const_cast<msvc8::string*>(&mUIMinRangeVisualId));
  archive->WriteString(const_cast<msvc8::string*>(&mUIMaxRangeVisualId));
}

SSTIUnitVariableData& Unit::VarDat() noexcept
{
  return mUnitVarDat;
}

SSTIUnitVariableData const& Unit::VarDat() const noexcept
{
  return mUnitVarDat;
}

/**
 * Address: 0x006A4920 (FUN_006A4920, Moho::Unit::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::StaticGetClass()
{
  return gpg::RTypeOf<Unit>();
}

/**
 * Address: 0x006A4940 (FUN_006A4940, Moho::Unit::GetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x006A4960 (FUN_006A4960, Moho::Unit::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef Unit::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}
namespace moho
{
  bool sim_DeferBlipUnlinks = true;

  bool sim_ParallelBlipFlush = true;

  int sim_DeferBlipUnlinksTicks = 4;

  TConVar<bool> gTConVar_sim_DeferBlipUnlinks(
    "sim_DeferBlipUnlinks",
    "Take dropped blips-in-range lists off their weak chains in bulk every few ticks (same results, less work).",
    &sim_DeferBlipUnlinks
  );

  TConVar<bool> gTConVar_sim_ParallelBlipFlush(
    "sim_ParallelBlipFlush",
    "Run sim_DeferBlipUnlinks' bulk unlink on sim workers, one weak chain per job (same chains; needs sim_Workers > 0).",
    &sim_ParallelBlipFlush
  );

  TConVar<int> gTConVar_sim_DeferBlipUnlinksTicks(
    "sim_DeferBlipUnlinksTicks",
    "Ticks between the bulk unlinks of sim_DeferBlipUnlinks (at least 1).",
    &sim_DeferBlipUnlinksTicks
  );
}

namespace
{
  using BlipList = gpg::core::FastVectorN<moho::WeakPtr<moho::Entity>, 20>;

  /**
   * Engine addition (`sim_DeferBlipUnlinks`): the replaced (or, as a unit dies, dropped) heap
   * blocks of `Unit::mBlipsInRange`.
   *
   * Every refresh drops the old list, and dropping a weak pointer walks its owner's chain from the
   * head to find it. Every other unit in range linked onto that chain since, ahead of it, so each
   * drop walks nearly the whole chain - in a large fight, most of `UpdateBlipsInRange`.
   *
   * Instead the old heap block is kept, its nodes still on their chains, and every
   * `sim_DeferBlipUnlinksTicks` ticks (or once enough are waiting) every chain they are on is walked
   * once and they are all spliced out. Splicing never reorders the nodes that stay, and a new node
   * always goes in at the head, so each chain holds exactly the live nodes, in exactly the order,
   * the immediate drops leave. Until then the waiting nodes are referenced by nothing: an owner that
   * dies meanwhile blanks them with the rest of its chain, and the walk skips them. Sim thread only,
   * like all chain work.
   */
  class DeferredBlipUnlinks
  {
  public:
    /// Takes over `list`'s heap block, if it has one; the list is left empty either way.
    void Adopt(BlipList& list, const std::uint32_t tick)
    {
      const std::uint32_t interval = static_cast<std::uint32_t>(std::max(moho::sim_DeferBlipUnlinksTicks, 1));
      if (tick - mTick >= interval) {
        Flush();
        mTick = tick;
      }
      Park(list);
    }

    /// `Adopt` without the flush check, for a dying unit's list.
    void Park(BlipList& list)
    {
      const BlipList::ReleasedBlock released = list.ReleaseHeapStorage();
      if (released.begin == nullptr) {
        list.ResetStorageToInline();
        return;
      }
      mBlocks.push_back(released);
      mNodeCount += static_cast<std::size_t>(released.end - released.begin);
      if (mNodeCount >= kFlushNodeCount) {
        Flush();
      }
    }

    /// Splices every waiting node out of its chain and frees the blocks.
    void Flush()
    {
      if (mBlocks.empty()) {
        return;
      }

      mChains.clear();
      for (const BlipList::ReleasedBlock& block : mBlocks) {
        for (const moho::WeakPtr<moho::Entity>* node = block.begin; node != block.end; ++node) {
          if (node->ownerLinkSlot != nullptr) {
            mChains.push_back(node->ownerLinkSlot);
          }
        }
      }
      std::sort(mChains.begin(), mChains.end());
      std::sort(mBlocks.begin(), mBlocks.end(), [](const auto& lhs, const auto& rhs) { return lhs.begin < rhs.begin; });

      const auto isWaiting = [this](const moho::WeakPtrNode* const node) {
        const auto after = std::upper_bound(
          mBlocks.begin(), mBlocks.end(), node, [](const auto* const value, const auto& block) { return value < block.begin; }
        );
        return after != mBlocks.begin() && node < std::prev(after)->end;
      };
      mChainRuns.clear();
      for (auto first = mChains.begin(); first != mChains.end();) {
        const auto last = std::upper_bound(first, mChains.end(), *first);
        mChainRuns.push_back(ChainRun{*first, static_cast<std::size_t>(last - first)});
        first = last;
      }

      // Engine addition (sim_ParallelBlipFlush): every chain is independent - its head lives in
      // its owner and each parked node is on exactly one chain - so the walks can run on the sim
      // workers; each chain ends the same whichever thread walks it.
      constexpr std::size_t kMinParallelChains = 64u;
      constexpr std::size_t kChainGrain = 16u;
      if (moho::sim_ParallelBlipFlush && mChainRuns.size() >= kMinParallelChains && !moho::IsSimWorkerThread()
          && moho::CSimWorkerPool::ParallelEnabled()) {
        moho::CSimWorkerPool::Get().ParallelFor(
          mChainRuns.size(), kChainGrain, [this, &isWaiting](const std::size_t begin, const std::size_t end) {
            for (std::size_t index = begin; index < end; ++index) {
              moho::WeakPtr<moho::Entity>::SpliceOutOfChain(mChainRuns[index].head, mChainRuns[index].count, isWaiting);
            }
          }
        );
      } else {
        for (const ChainRun& run : mChainRuns) {
          moho::WeakPtr<moho::Entity>::SpliceOutOfChain(run.head, run.count, isWaiting);
        }
      }

      for (const BlipList::ReleasedBlock& block : mBlocks) {
        BlipList::FreeReleasedBlock(block);
      }
      mBlocks.clear();
      mNodeCount = 0;
    }

  private:
    static constexpr std::size_t kFlushNodeCount = 1u << 20;

    struct ChainRun
    {
      moho::WeakObject* head;
      std::size_t count;
    };

    std::vector<BlipList::ReleasedBlock> mBlocks;
    std::vector<moho::WeakObject*> mChains;
    std::vector<ChainRun> mChainRuns;
    std::size_t mNodeCount = 0;
    std::uint32_t mTick = 0;
  };

  [[nodiscard]] DeferredBlipUnlinks& BlipListUnlinks()
  {
    static DeferredBlipUnlinks unlinks;
    return unlinks;
  }
  template <class T>
  void DeleteAndNull(T*& object) noexcept
  {
    T* const oldObject = object;
    object = nullptr;
    delete oldObject;
  }

  void DestroyUnitEconomyRequest(CEconRequest*& request) noexcept
  {
    CEconRequest* const oldRequest = request;
    request = nullptr;
    if (oldRequest == nullptr) {
      return;
    }

    oldRequest->mNode.ListUnlink();
    delete oldRequest;
  }

  void DestroyUnitExtraStorage(CEconStorage*& storage) noexcept
  {
    CEconStorage* const oldStorage = storage;
    storage = nullptr;
    // 0x006AD759..0x006AD768 is `delete` with ~CEconStorage inlined: the
    // destructor alone withdraws the contribution, exactly once.
    delete oldStorage;
  }

  void DestroyUnitEconomyEvents(Unit& unit) noexcept
  {
    while (!unit.mEconomyEventListHead.empty()) {
      delete unit.mEconomyEventListHead.front();
    }
  }

  void ClearUnitWeakReferences(Unit& unit) noexcept
  {
    unit.CreatorRef.UnlinkFromOwnerChain();
    unit.TransportedByRef.UnlinkFromOwnerChain();
    unit.AssignedTransportRef.UnlinkFromOwnerChain();
    unit.FocusEntityRef.UnlinkFromOwnerChain();
    unit.TargetBlipEntityRef.UnlinkFromOwnerChain();
    unit.GuardedUnitRef.UnlinkFromOwnerChain();
    unit.mInfoCache.mFormationLeadRef.UnlinkFromOwnerChain();

    // Engine change (sim_DeferBlipUnlinks): a heap-held list joins the deferred bulk unlink
    // instead of walking each blip's chain now; see `DeferredBlipUnlinks`.
    if (sim_DeferBlipUnlinks && !unit.mBlipsInRange.UsesInlineStorage()) {
      BlipListUnlinks().Park(unit.mBlipsInRange);
      return;
    }

    for (WeakPtr<Entity>& blip : unit.mBlipsInRange) {
      blip.UnlinkFromOwnerChain();
    }
    unit.mBlipsInRange.ResetStorageToInline();
  }

  void ClearGuardedByOwners(Unit& unit)
  {
    std::vector<Unit*> guardedByUnits;
    if (!unit.GuardedByList.Empty()) {
      guardedByUnits.reserve(unit.GuardedByList.Size());

      for (Entity* const entry : unit.GuardedByList.mVec) {
        Unit* const guardedByUnit = static_cast<Unit*>(entry);
        if (guardedByUnit != nullptr) {
          guardedByUnits.push_back(guardedByUnit);
        }
      }
    }

    for (Unit* const guardedByUnit : guardedByUnits) {
      guardedByUnit->SetGuardedUnit(nullptr);
    }

    unit.GuardedByList.mVec.ResetStorageToInline();
    unit.GuardedByList.ListUnlinkSelf();
    unit.SetGuardedUnit(nullptr);
  }

  void DecrementUnitArmyLifetimeStats(Unit& unit)
  {
    CArmyImpl* const army = unit.ArmyRef;
    if (army == nullptr) {
      return;
    }

    const RUnitBlueprint* const blueprint = unit.GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats == nullptr) {
      return;
    }

    if (unit.IsBeingBuilt()) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
      return;
    }

    if (blueprint->General.CapCost > 0.0f) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, -1.0f);
      const std::int32_t delta = -1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
    }
  }

  void DetachAndDestroyUnitTransport(Unit& unit)
  {
    if (unit.AiTransport == nullptr) {
      return;
    }

    EntitySetTemplate<Unit> detachedUnits = unit.AiTransport->TransportDetachAllUnits(true);
    (void)detachedUnits;
    DeleteAndNull(unit.AiTransport);
  }

  void ClearUnitOwnedSidecars(Unit& unit)
  {
    DeleteAndNull(unit.AiCommandDispatch);

    if (unit.CommandQueue != nullptr) {
      unit.CommandQueue->ClearCommandQueue();
    }

    DeleteAndNull(unit.AiAttacker);
    DetachAndDestroyUnitTransport(unit);
    DeleteAndNull(unit.AiNavigator);
    DeleteAndNull(unit.AiSteering);
    DeleteAndNull(unit.UnitMotion);
    DeleteAndNull(unit.AiBuilder);
    DeleteAndNull(unit.AiSiloBuild);
    DeleteAndNull(unit.CommandQueue);
    DeleteAndNull(unit.AniActor);
  }
  /**
   * Address: 0x007736A0 (FUN_007736A0, sub_7736A0)
   *
   * IDA signature:
   * float *__userpurge sub_7736A0(
   *     Moho::SEconValue *dest@<eax>, Moho::CEconRequest *request@<edx>, Moho::SEconValue *desired);
   *
   * What it does:
   * Clamps `desired` to what remains in `request.mGranted` (component-wise
   * min), writes the clamped amount into `dest`, then reduces
   * `request.mGranted` by that withdrawn amount (floored at zero).
   */
  SEconValue& WithdrawFromGrantedEconValue(SEconValue& dest, CEconRequest& request, const SEconValue& desired)
  {
    dest.energy = std::min(desired.energy, request.mGranted.energy);
    dest.mass = std::min(desired.mass, request.mGranted.mass);

    request.mGranted.energy = std::max(0.0f, request.mGranted.energy - dest.energy);
    request.mGranted.mass = std::max(0.0f, request.mGranted.mass - dest.mass);

    return dest;
  }
}



/**
 * Address: 0x006AD750 (FUN_006AD750, func_SetExtraStorage)
 *
 * IDA signature:
 * void callcnv_F3 func_SetExtraStorage(Moho::CEconStorage **a1@<eax>, Moho::CEconStorage *a2@<ecx>);
 */
void Unit::SetExtraStorage(CEconStorage* const newStorage)
{
  DestroyUnitExtraStorage(mExtraStorage);
  mExtraStorage = newStorage;
}

/**
 * Address: 0x006AAAC0 (FUN_006AAAC0, ?HandleResourceManagement@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Per-tick economy step. Consumes this unit's request lane (throttling its
 * own production by the consumption fulfillment ratio when it is not a
 * natural producer), then - while alive, not under construction, and
 * production-active - maintains the extra max-storage lane the blueprint's
 * storage economy requires and contributes production output into the
 * owning army's economy and this unit's own beat accumulators. Otherwise
 * (not producing), tears down any owned extra-storage lane.
 */
void Unit::HandleResourceManagement()
{
  ResourceConsumed = 0.0f;
  float productionRate = 1.0f;

  if (!GetBlueprint()->Economy.NaturalProducer && mConsumptionData != nullptr) {
    productionRate = mConsumptionData->LimitingRate();
  }

  if (!IsDead() && ConsumptionActive && mConsumptionData != nullptr) {
    ResourceConsumed = mConsumptionData->LimitingRate();

    SEconValue desiredConsumption = mConsumptionData->mRequested;
    desiredConsumption.energy *= ResourceConsumed;
    desiredConsumption.mass *= ResourceConsumed;

    SEconValue withdrawn{};
    WithdrawFromGrantedEconValue(withdrawn, *mConsumptionData, desiredConsumption);

    mUnitVarDat.mResourcesSpent.ENERGY += withdrawn.energy;
    mUnitVarDat.mResourcesSpent.MASS += withdrawn.mass;
  }

  if (mVarDat.mIsBeingBuilt || IsDead() || !ProductionActive) {
    DestroyUnitExtraStorage(mExtraStorage);
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();

  if (blueprint->Economy.StorageEnergy == 0.0f && blueprint->Economy.StorageMass == 0.0f) {
    DestroyUnitExtraStorage(mExtraStorage);
  } else {
    const SEconValue storageAmount{blueprint->Economy.StorageEnergy, blueprint->Economy.StorageMass};

    if (mExtraStorage != nullptr) {
      mExtraStorage->ChangeAmt(storageAmount);
    } else {
      CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
      SetExtraStorage(new (std::nothrow) CEconStorage(storageAmount, reinterpret_cast<CEconomy*>(economyInfo)));
    }
  }

  SEconValue producedThisTick{
    mUnitVarDat.mAttributes.productionPerSecondEnergy * productionRate, mUnitVarDat.mAttributes.productionPerSecondMass * productionRate
  };
  producedThisTick.energy *= 0.1f;
  producedThisTick.mass *= 0.1f;

  CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  economyInfo->mResources.ENERGY += producedThisTick.energy;
  economyInfo->mResources.MASS += producedThisTick.mass;
  economyInfo->mPendingResources.ENERGY += producedThisTick.energy;
  economyInfo->mPendingResources.MASS += producedThisTick.mass;
  mUnitVarDat.mProduced.ENERGY += producedThisTick.energy;
  mUnitVarDat.mProduced.MASS += producedThisTick.mass;
}

/**
 * Address: 0x006AA7A0 (FUN_006AA7A0, ?UpdateGuardFormation@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * When this unit has no guard formation yet but has guarded units and a
 * blueprint-defined guard-formation script, builds a new
 * `CAiFormationInstance` centered on this unit (oriented along this unit's
 * own transform when mobile, or a zero orientation otherwise), disbands any
 * prior formation, and primes the new one.
 */
void Unit::UpdateGuardFormation()
{
  if (GuardFormation != nullptr || GuardedByList.Empty()) {
    return;
  }

  CAiFormationDBImpl* const formationDB = SimulationRef->mFormationDB;
  const char* const guardFormationScript = GetBlueprint()->AI.GuardFormationName.c_str();
  if (guardFormationScript == nullptr || *guardFormationScript == '\0') {
    return;
  }

  const Wm3::Vec3f& position = GetPosition();
  SCoordsVec2 formationCenter{};
  formationCenter.x = position.x;
  formationCenter.z = position.z;

  const Wm3::Quatf formationOrientation = IsMobile() ? GetTransform().orient_ : Zeroed<Wm3::Quaternionf>();

  CAiFormationInstance* const newFormation = formationDB->NewFormation(
    &GuardedByList,
    guardFormationScript,
    &formationCenter,
    formationOrientation.x,
    formationOrientation.y,
    formationOrientation.z,
    formationOrientation.w,
    15
  );

  IFormationInstance* const previousFormation = GuardFormation;
  GuardFormation = newFormation;
  delete previousFormation;

  newFormation->SetScale(1.0f);
}

/**
 * Address: 0x006A5050 (FUN_006A5050, ??0Unit@Moho@@AAE@PAVSim@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@PAVSim@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Unit::Unit(Moho::Unit *this, Moho::Sim *sim);
 *
 * What it does:
 * Deserialization-construct constructor (private; invoked only by
 * Unit::MemberConstruct). Constructs the IUnit/Entity/InstanceCounter<Unit>
 * bases on `sim`, default-constructs the const/variable stat-data
 * subobjects, and zero-initializes every runtime lane: AI sidecars, weak-ref
 * slots, the guarded-by list, the armor-multiplier map head, the economy-event
 * list, the info cache, the occupancy rect, and the recon/blip vectors.
 */
Unit::Unit(Sim* sim) : IUnit(), Entity(sim, ENTITYTYPE_Unit)
{
  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  // `GuardedByList` constructs as a member: its list node self-linked, its
  // vector on the four inline slots that end at `GuardFormation`.

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = 0;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  // ArmorMultipliers (msvc8::map<msvc8::string,float>) self-constructs its
  // sentinel head via its own default constructor (member init) -- see
  // legacy/containers/RbTree.h's buy_head(), cited for this instantiation
  // (0x006B01C0) exactly where the binary's manual head-alloc-and-self-link
  // used to be modeled by hand here.

  // mEconomyEventListHead self-links via its TDatListItem ctor (member init).

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  // mBlipsInRange (FastVectorN<WeakPtr<Entity>,20>) and mReconBlips
  // (FastVectorN<ReconBlip*,2>) bind to their inline buffers as members.
  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  CaptorCount = 0;
  NeedSyncGameData = true;
}
namespace
{
  /** Half the yaw spread a randomly-facing spawn gets, in radians (~30 degrees). */
  constexpr float kRandomSpawnYawLimit = 0.52359879f;

  /** `SSTIUnitVariableData::mCreator` when the unit was not built by anything. */
  constexpr moho::EntId kNoCreatorEntityId = static_cast<moho::EntId>(0xF0000000);

  /** `UnitStateMask` bit set while a unit is still under construction. */
  constexpr std::uint64_t kUnitStateBeingBuilt = 1ULL << 39;

  /**
   * Floor the two minima and ceil the two maxima of a skirt rectangle onto the
   * occupancy grid, which is what the binary's four `frndint`s plus sign
   * fixups come out to (Unit::Unit, 0x006A618F..0x006A6220).
   */
  [[nodiscard]] gpg::Rect2i SkirtRectToOgridRect(const gpg::Rect2f& skirt) noexcept
  {
    return gpg::Rect2i{
      msvc8::FloorToIntX87(skirt.x0),
      msvc8::FloorToIntX87(skirt.z0),
      msvc8::CeilToIntX87(skirt.x1),
      msvc8::CeilToIntX87(skirt.z1),
    };
  }
}



/**
 * Address: 0x006A53F0 (FUN_006A53F0, ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__stdcall Moho::Unit::Unit(Moho::Unit *unit,
 *     const Moho::SUnitConstructionParams *params);
 *
 * What it does:
 * The gameplay constructor - what `Sim::CreateUnit` calls, and the only way a
 * unit comes into existence outside a savegame load. Reserves an entity id out
 * of the owning army's id family, runs the blueprint-aware `Entity` base
 * constructor, seeds health and attributes from the blueprint, resolves the
 * spawn orientation and elevation, builds the intel manager, attaches every AI
 * sidecar the blueprint calls for (motion/navigator/steering, weapons, builder,
 * silo builder, transport, command queue, command dispatch), publishes the unit
 * into `ArmyPool`, and runs `OnCreate` plus either `OnStartBeingBuilt` or
 * `OnStopBeingBuilt`.
 */
Unit::Unit(const SUnitConstructionParams& params)
  : IUnit()
  , Entity(
      const_cast<REntityBlueprint*>(static_cast<const REntityBlueprint*>(params.mBlueprint)),
      params.mArmy->GetSim(),
      static_cast<EntId>(params.mArmy->GetSim()->mEntityDB->DoReserveId(
        static_cast<std::uint32_t>(params.mArmy->mConstDat.mArmyIndex) << 20
      )),
      ENTITYTYPE_Unit
    )
{
  Sim* const sim = SimulationRef;
  const RUnitBlueprint& blueprint = *params.mBlueprint;

  // --- runtime lanes: the same zeroing the deserialization ctor above does --
  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  CreatorRef.Set(params.mLinkSourceUnit);
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = sim->mCurTick;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  // ArmorMultipliers (msvc8::map<msvc8::string,float>) self-constructs its
  // sentinel head via its own default constructor (member init); see the
  // sibling constructor above for the full citation.

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  NeedSyncGameData = true;
  CaptorCount = 0;

  // 0x006A572F: `mov byte ptr [ebp+1C0h], 1` -- `ebp` is the Unit here (the two
  // neighbouring stores are `NeedSyncGameData` at Unit+0x68E and `CaptorCount`
  // at Unit+0x690, and the next one is `MaxHealth` at Unit+0x9C), so this is
  // `Entity::mQueueRelinkBlocked` at Entity+0x1B8.
  //
  // It pins the unit in `Sim::mCoordEntities` for life. `Entity::Sync`
  // (0x0067A114) unlinks the node it was reached through *unless* this flag is
  // set, and `Sim::Sync` publishes exactly the entities on that run -- so a
  // unit that is never unlinked is republished on every sync, whether or not
  // anything relinked it. That is what makes a value which changes with no
  // other side effect reach the client at all: `Unit::WorkProgress`
  // (Unit+0x2AC) is written by `CBuildTaskHelper::UpdateWorkProgress` and by
  // the `SetWorkProgress` Lua binding (0x006CCC85) as a bare `fstp`, with no
  // dirty mark and no relink anywhere. Without this line a stationary builder
  // published once and then froze: a factory's build bar never moved, and
  // neither did the intel-recharge bar Lua drives the same way. Props,
  // projectiles and blips keep the base default and stay change-driven.
  mQueueRelinkBlocked = 1u;

  // --- blueprint-derived health and attributes ---------------------------
  mVarDat.mMaxHealth = blueprint.Defense.MaxHealth;
  mVarDat.mHealth = params.mComplete != 0 ? blueprint.Defense.Health : 1.0f;
  mVarDat.mFractionComplete = static_cast<float>(params.mComplete);
  mVarDat.mIsBeingBuilt = 0;
  mVarDat.mIntelAttributes.Initialize(&blueprint);

  VarDat().mCreator = params.mLinkSourceUnit != nullptr ? params.mLinkSourceUnit->id_ : kNoCreatorEntityId;
  // Constructed in place over the unit's own attribute lane (unit+0x428).
  new (&mUnitVarDat.mAttributes) UnitAttributes(&blueprint, static_cast<const RRuleGameRulesImpl*>(sim->mRules));
  VarDat().mCreationTick = sim->mCurTick;

  SetAutoMode(blueprint.AI.InitialAutoMode != 0);
  RunScript("OnPreCreate");

  // --- intel manager -----------------------------------------------------
  // The slot was nulled by the Entity base a moment ago, so the binary's
  // release-the-previous-manager branch cannot be taken here.
  mIntelManager = new CIntel(&blueprint.Intel, sim, ArmyRef->GetReconDB());

  // --- spawn transform ---------------------------------------------------
  VTransform spawnTransform = params.mTransform;
  if (params.mUseLayerOverride == 0) {
    // No caller-supplied orientation. Mobile units whose blueprint asks for it
    // get a facing within +/-30 degrees of default so a batch of them does not
    // spawn perfectly aligned; everything else faces the default direction.
    if (blueprint.Display.SpawnRandomRotation != 0 && blueprint.IsMobile()) {
      const float yaw = sim->mRngState->FRand(-kRandomSpawnYawLimit, kRandomSpawnYawLimit);
      const Wm3::Vector3f yawAxis{0.0f, 1.0f, 0.0f};
      Wm3::Quatf spawnRotation{};
      (void)EulerRollToQuat(&yawAxis, &spawnRotation, yaw);
      spawnTransform.orient_ = spawnRotation;
    } else {
      spawnTransform.orient_.w = 1.0f;
      spawnTransform.orient_.x = 0.0f;
      spawnTransform.orient_.y = 0.0f;
      spawnTransform.orient_.z = 0.0f;
    }
  }

  // --- placeholder mesh --------------------------------------------------
  RMeshBlueprint* placeholderMesh = nullptr;
  const msvc8::string placeholderName = gpg::STR_ToLower(blueprint.Display.PlaceholderMeshName.c_str());
  if (!placeholderName.empty()) {
    const msvc8::string meshPath =
      gpg::STR_Printf("/units/%s/%s_mesh", placeholderName.c_str(), placeholderName.c_str());
    msvc8::string meshFileName{};
    (void)gpg::STR_CopyFilename(&meshFileName, &meshPath);

    RResId placeholderId{};
    placeholderId.name.assign_owned(meshFileName.view());
    placeholderMesh = sim->mRules->GetMeshBlueprint(placeholderId);
  }

  // A null pointee means nothing has claimed the mesh lane yet.
  if (!boost::HasSharedResource(mVarDat.mScmResource)) {
    SetMesh(blueprint.Display.MeshBlueprint, placeholderMesh, true);
  }

  // --- layer, terrain type and spawn elevation ---------------------------
  SetCurrentLayer(GetStartingLayer(spawnTransform.pos_, static_cast<ELayer>(params.mLayer)));
  UpdateTerrainType(spawnTransform.pos_);
  if (params.mFixElevation == 0) {
    spawnTransform.pos_.y =
      IUnit::CalcSpawnElevation(sim->mMapData, mVarDat.mLayerMask, spawnTransform, VarDat().mAttributes);
  }

  // Word-for-word copy (0x006A5BF9..0x006A5C23 stores the transform straight
  // into +0x150). Getting the quaternion one lane off rotates it and flips every
  // spawned unit upside-down on the user side (its skinned mesh draws as an
  // unlit black blob), which is what happened while +0x150 was spelled as a
  // `moho::Vector4f` naming (x,y,z,w) over the quaternion's (w,x,y,z) words.
  mPendingTransform = spawnTransform;
  // Twice, as the binary does: the first call publishes the spawn pose into the
  // current lane and the second copies it into the previous-frame lane, so the
  // unit does not interpolate in from wherever that lane happened to point.
  AdvanceCoords();
  AdvanceCoords();

  AniActor->GetPriorPoseShared()->SetWorldTransform(GetTransformWm3());
  AniActor->GetPoseShared()->SetWorldTransform(GetTransformWm3());
  VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();
  VarDat().mSharedPose = AniActor->GetPoseShared();

  // --- motion, navigator, steering ---------------------------------------
  // RULEUMT_None and RULEUMT_Special both leave the unit immobile; every value
  // between them gets a navigator, and only RULEUMT_Air gets the air one.
  const ERuleBPUnitMovementType motionType = blueprint.Physics.MotionType;
  if (motionType >= RULEUMT_Land && motionType <= RULEUMT_AmphibiousFloating) {
    UnitMotion = new CUnitMotion(this);
    AiNavigator =
      motionType == RULEUMT_Air ? AI_CreateAirNavigator(this) : AI_CreatePathingNavigator(this);
    AiSteering = AI_CreateSteering(this, UnitMotion, mVarDat.mLayerMask);
  } else {
    // Immobile units claim their footprint at spawn. Ferry beacons and in-place
    // upgrades are the exceptions: both sit on ground another unit already owns.
    if (!IsInCategory("FERRYBEACON") && !IsInCategory("UPGRADE")) {
      ExecuteOccupyGround();
      FootprintDown = true;
    }
  }

  // --- weapons -----------------------------------------------------------
  for (const RUnitBlueprintWeapon& weaponBlueprint : blueprint.Weapons.WeaponBlueprints) {
    if (weaponBlueprint.DummyWeapon != 0) {
      continue;
    }

    if (AiAttacker == nullptr) {
      AiAttacker = AI_CreateAttacker(this);
      mConstDat.mBuildStateTag = 1;
    }
    AiAttacker->CreateWeapon(const_cast<RUnitBlueprintWeapon*>(&weaponBlueprint));
  }

  // --- builder -----------------------------------------------------------
  if (!blueprint.Economy.BuildableCategories.empty() || IsInCategory("REBUILDER")) {
    AiBuilder = AI_CreateBuilder(this);

    if (IsInCategory("FACTORY")) {
      AiBuilder->BuilderSetIsFactory(true);
      if (UnitMotion == nullptr) {
        const Wm3::Vector3f& position = GetPosition();
        const SCoordsVec2 origin{position.x, position.z};
        ReserveOgridRect(SkirtRectToOgridRect(GetBlueprint()->GetSkirtRect(origin)));
      }
    }
  }

  // --- silo builder and transport ----------------------------------------
  if (IsInCategory("SILO")) {
    AiSiloBuild = static_cast<CAiSiloBuildImpl*>(AI_CreateSiloBuilder(this));
  }

  if ((VarDat().mAttributes.commandCapsMask & RULEUCC_Transport) != 0 || IsInCategory("PODSTAGINGPLATFORM")) {
    AiTransport = AI_CreateTransport(this);
  }

  // --- command plumbing --------------------------------------------------
  CommandQueue = new CUnitCommandQueue(this);
  AiCommandDispatch = static_cast<IAiCommandDispatchImpl*>(AI_CreateCommandDispatch(this));

  // --- publish into the army pool ----------------------------------------
  {
    EntitySetTemplate<Unit> spawnedSet{};
    (void)spawnedSet.Add(this);
    ArmyRef->AssignUnitsToPlatoon(&spawnedSet, "ArmyPool");
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactory()) {
    AiBuilder->BuilderSetUpInitialRally();
  }

  InitializeArmor();
  RunScript("OnCreate");

  // --- being-built vs finished -------------------------------------------
  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  const char* const layerName = LayerToString(mVarDat.mLayerMask);
  // 0x006A6563..0x006A6584 / 0x006A67E5..0x006A6806: with no creator the
  // binary passes a nil LuaObject built on this unit's Lua state (0x00908970),
  // not the unit's own script object.
  const auto makeCreatorObject = [this](Unit* const creator) -> LuaPlus::LuaObject {
    if (creator != nullptr) {
      return creator->GetLuaObject();
    }
    LuaPlus::LuaObject nilObject;
    if (LuaPlus::LuaState* const scriptState = mLuaObj.GetActiveState(); scriptState != nullptr) {
      nilObject = LuaPlus::LuaObject(scriptState);
    }
    return nilObject;
  };

  if (params.mComplete == 0) {
    mUnitVarDat.mUnitStates |= kUnitStateBeingBuilt;
    mVarDat.mIsBeingBuilt = 1;
    if (armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", &blueprint, 1.0f);
    }
    // 0x006A67B3..0x006A6830: creator read from `params.mLinkSourceUnit`
    // (+0x2C), fired through `RunScript_ObjStr` (0x006B07D0).
    RunScriptObjectString("OnStartBeingBuilt", makeCreatorObject(params.mLinkSourceUnit), layerName);
  } else {
    if (UnitMotion == nullptr) {
      EntitySetTemplate<Unit> overlapping{};
      (void)CollectAllOverlapping(&overlapping, this);
      for (Entity* const entry : overlapping.mVec) {
        Unit* const neighbour = static_cast<Unit*>(entry);
        if (neighbour == nullptr) {
          continue;
        }
        // 0x006A64A3..0x006A64C9: `RunScript_OnAdjacentTo` (0x006B0660) as
        // this->(neighbour, this), then neighbour->(this, this) -- both
        // arguments of the second call are this unit.
        RunScriptOnAdjacentTo(neighbour, this);
        neighbour->RunScriptOnAdjacentTo(this, this);
      }
    }

    // 0x006A6522..0x006A65AB: creator read from the `CreatorRef` weak link
    // (+0x4B8), fired through `RunScript_ObjStr` (0x006B07D0).
    RunScriptObjectString("OnStopBeingBuilt", makeCreatorObject(CreatorRef.GetObjectPtr()), layerName);

    if (blueprint.General.CapCost > 0.0f && armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", &blueprint, 1.0f);
      const std::int32_t delta = 1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", &blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &delta);
    }
  }

  if (ArmyRef != nullptr) {
    ArmyRef->AddUnitToCategorySet(this);
  }

  // --- cached category flags ---------------------------------------------
  mIsNotPod = IsInCategory("POD") || IsInCategory("STATIONASSISTPOD");
  mIsEngineer = IsInCategory("ENGINEER");
  mIsNaval = IsInCategory("NAVAL");
  mIsAir = IsInCategory("AIR");
  mIsMelee = IsInCategory("MELEE");
  mUsesGridBasedMotion = IsInCategory("GRIDBASEDMOTION");
}

/**
 * Address: 0x006AD3C0 (FUN_006AD3C0,
 * ?MemberConstruct@Unit@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
 *
 * What it does:
 * Reflection construct-callback. Reads the owning `Sim*` from the archive,
 * allocates and constructs a fresh `Unit` on it, then publishes it to the
 * `SerConstructResult` as unowned.
 */
void Unit::MemberConstruct(
  gpg::ReadArchive& archive,
  const int,
  const gpg::RRef&,
  gpg::SerConstructResult& result
)
{
  Sim* sim = nullptr;
  const gpg::RRef owner{};
  archive.ReadPointer(&sim, &owner);
  result.SetUnowned(gpg::MakeRRef(new Unit(sim)), 0u);
}

/**
 * Address: 0x006A6BF0 (FUN_006A6BF0, ??1Unit@Moho@@UAE@XZ)
 *
 * What it does:
 * Releases unit-owned AI, command, guard, economy, occupancy, recon, and
 * weak-link runtime lanes before base/member teardown.
 */
Unit::~Unit()
{
  if (ArmyRef != nullptr) {
    (void)ArmyRef->ConsumeUnitFromCategorySet(this);
  }

  ClearUnitOwnedSidecars(*this);
  // ArmorMultipliers (msvc8::map<msvc8::string,float>) tears itself down via
  // its own destructor (member teardown, reverse declaration order) -- see
  // legacy/containers/RbTree.h's ~rb_tree()/destroy_subtree, matching the
  // binary's 0x006A5380 teardown shape this used to hand-model.
  ClearGuardFormation(this);
  DestroyUnitEconomyEvents(*this);
  ReleaseOccupyGround();
  DecrementUnitArmyLifetimeStats(*this);
  ClearGuardedByOwners(*this);

  if (ArmyRef != nullptr) {
    ArmyRef->RemoveFromPlatoon(this);
  }

  mReconBlips.ResetStorageToInline();
  ClearUnitWeakReferences(*this);
  DestroyUnitEconomyRequest(mConsumptionData);
  DestroyUnitExtraStorage(mExtraStorage);
  // After the members and `~Entity` (0x006A7369), the `IUnit` base's
  // `WeakObject` drops its weak references (0x006A736E).
}

/**
 * Address: 0x006A4BC0 (FUN_006A4BC0)
 *
 * What it does:
 * Returns this unit pointer through the const RTTI/downcast lane.
 */
Unit const* Unit::IsUnit() const
{
  return this;
}

/**
 * Address: 0x006A4BB0 (FUN_006A4BB0)
 *
 * What it does:
 * Returns this unit pointer through the mutable RTTI/downcast lane.
 */
Unit* Unit::IsUnit()
{
  return this;
}

// Address: 0x006A48E0 (FUN_006A48E0, Unit::IsUserUnit() const)
UserUnit const* Unit::IsUserUnit() const
{
  return nullptr;
}

// Address: 0x006A48D0 (FUN_006A48D0, Unit::IsUserUnit())
UserUnit* Unit::IsUserUnit()
{
  return nullptr;
}

// 0x006A49A0
EntId Unit::GetEntityId() const
{
  return id_;
}

// 0x006A8B20
RUnitBlueprint const* Unit::GetBlueprint() const
{
  const REntityBlueprint* const blueprint = BluePrint;
  return blueprint ? blueprint->IsUnitBlueprint() : nullptr;
}

/**
 * Address: 0x006A7600 (FUN_006A7600)
 * Mangled: ?GetSkirtRect@Unit@Moho@@QBE?AV?$Rect2@M@gpg@@XZ
 *
 * What it does:
 * Projects this unit position to XZ and resolves world-space skirt bounds
 * through the owning unit blueprint.
 */
gpg::Rect2f Unit::GetSkirtRect() const
{
  const Wm3::Vec3f& unitPosition = GetPosition();
  const SCoordsVec2 unitPos2d{unitPosition.x, unitPosition.z};
  const RUnitBlueprint* const blueprint = GetBlueprint();
  return blueprint->GetSkirtRect(unitPos2d);
}

/**
 * Address: 0x006AAEC0 (FUN_006AAEC0, ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one recoil impulse into `UnitMotion` when present.
 */
void Unit::AddRecoilImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddRecoilImpulse(impulse);
  }
}

/**
 * Address: 0x006AAEE0 (FUN_006AAEE0, ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one world impulse to `UnitMotion` when present.
 */
void Unit::AddImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddImpulse(impulse, false);
  }
}

/**
 * Address: 0x006AAF00 (FUN_006AAF00, ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z)
 * Mangled: ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z
 *
 * What it does:
 * Routes local impulse handling by motion type: airborne units use body-local
 * impulse integration, non-air units feed unit-motion impulse blending.
 */
void Unit::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion == nullptr) {
    return;
  }

  const Unit* const motionOwner = unitMotion->mUnit;
  const RUnitBlueprint* const blueprint = motionOwner->GetBlueprint();
  if (blueprint->Physics.MotionType == RULEUMT_Air) {
    SPhysBody* const body = static_cast<Entity*>(unitMotion->mUnit)->GetPhysBody(false);
    body->AddLocalImpulse(localImpulse, localPoint);
    return;
  }

  unitMotion->AddImpulse(localImpulse, false);
}

/**
 * Address: 0x006AAF50 (FUN_006AAF50, ?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
 * the list is empty. Returns true on all paths.
 */
bool Unit::PickTargetPoint(std::int32_t& outTargetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  const std::uint32_t targetBoneCount =
    (blueprint != nullptr) ? static_cast<std::uint32_t>(blueprint->AI.TargetBones.size()) : 0u;

  if (targetBoneCount == 0u || !SimulationRef || !SimulationRef->mRngState) {
    outTargetPoint = -1;
    return true;
  }

  const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
  outTargetPoint = PickUniformIndexFromU32(randomValue, targetBoneCount);
  return true;
}

/**
 * Address: 0x006AAFB0 (FUN_006AAFB0, ?PickTargetPointAboveWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index above current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointAboveWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    msvc8::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y > waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  return GetPosition().y > waterElevation;
}

/**
 * Address: 0x006AB190 (FUN_006AB190, ?PickTargetPointBelowWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index below current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointBelowWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    msvc8::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y < waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  // 0x006AB31D: `comiss water, pos.y` / `ja` -- strictly below the surface.
  return GetPosition().y < waterElevation;
}

/**
 * Address: 0x006AB340 (FUN_006AB340, Moho::Unit::GetTargetPoint)
 *
 * What it does:
 * Resolves one target-bone index to world position, clamping index lanes to
 * blueprint target-bone bounds and falling back to root bone (`-1`) when the
 * request is negative.
 */
Wm3::Vec3f Unit::GetTargetPoint(std::int32_t targetPoint) const
{
  // FAF FA-Binary-Patches #145/#157 (Account for collision offset when picking
  // target point of unit with no target bones): a unit without target bones is
  // aimed at its collision-box centre -- the base `Entity::GetBoneWorldTransform`
  // root anchor, which adds the blueprint's CollisionOffsetX/Y/Z -- instead of
  // `Unit::GetBoneWorldTransform`'s SizeY/2 above the pending position. Only
  // this negative-index entry (0x006AB34D) changes.
  if (targetPoint < 0 && FAF_IsSimFixActive(EFafSimFix::TargetPointCollisionCentre)) {
    return Entity::GetBoneWorldTransform(-1).pos_;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (targetPoint >= 0 && blueprint != nullptr) {
    const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
    const std::int32_t maxIndex = static_cast<std::int32_t>(targetBones.size()) - 1;
    if (targetPoint >= maxIndex) {
      targetPoint = maxIndex;
    }

    if (targetPoint >= 0) {
      const int boneIndex = ResolveBoneIndex(targetBones[static_cast<std::size_t>(targetPoint)].c_str());
      return GetBoneWorldTransform(boneIndex).pos_;
    }
  }

  return GetBoneWorldTransform(-1).pos_;
}

/**
 * Address: 0x006AB9C0 (FUN_006AB9C0, ?SetMesh@Unit@Moho@@UAEXABVRResId@2@PAVRMeshBlueprint@2@_N@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SetMesh(Moho::Unit *this, const Moho::RResId &meshResId,
 *   Moho::RMeshBlueprint *meshBlueprint, char rebuildAniActor);
 *
 * What it does:
 * Forwards to `Entity::SetMesh` with `allowExplicitPlaceholder=true`, then
 * (when `rebuildAniActor` is set) recreates the unit's `CAniPose` and
 * `CAniActor` runtime chain so the visible animation tracks the new mesh's
 * skeleton.
 */
void Unit::SetMesh(const RResId& meshResId, RMeshBlueprint* const meshBlueprint, const bool rebuildAniActor)
{
  Entity::SetMesh(meshResId, meshBlueprint, true);
  if (!rebuildAniActor) {
    return;
  }

  boost::shared_ptr<const CAniSkel> skeleton;
  if (RScmResource* const scmResource = mVarDat.mScmResource.get(); scmResource != nullptr) {
    skeleton = scmResource->GetSkeleton();
  }

  CAniPose* newPose = nullptr;
  if (void* const poseStorage = ::operator new(sizeof(CAniPose)); poseStorage != nullptr) {
    const float scale = GetUniformScale();
    newPose = ::new (poseStorage) CAniPose(skeleton, scale);
  }

  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose.reset(newPose);
  varDat.mSharedPose->SetWorldTransform(GetTransformWm3());
  varDat.mPriorSharedPose = varDat.mSharedPose;

  CAniActor* const newActor = new CAniActor(varDat.mSharedPose, varDat.mPriorSharedPose);

  CAniActor* const oldActor = AniActor;
  AniActor = newActor;
  if (oldActor != nullptr) {
    oldActor->~CAniActor();
    ::operator delete(oldActor);
  }
}

/**
 * Address: 0x006ABB90 (FUN_006ABB90, ?SetPoses@Unit@Moho@@QAEXABV?$shared_ptr@VCAniPose@Moho@@@boost@@0@Z)
 *
 * What it does:
 * Copies prior/current shared animation poses into variable-data lanes and
 * mirrors them into `AniActor::{mPose,mPriorPose}`.
 */
void Unit::SetPoses(
  const boost::shared_ptr<CAniPose>& priorSharedPose,
  const boost::shared_ptr<CAniPose>& sharedPose
)
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose = sharedPose;
  varDat.mPriorSharedPose = priorSharedPose;

  AniActor->AssignPoses(sharedPose, priorSharedPose);
}

/**
 * Address: 0x006A9E50 (FUN_006A9E50, ?CanBuild@Unit@Moho@@QBE_NPBVRUnitBlueprint@2@@Z)
 *
 * What it does:
 * Tests whether `blueprint` is present in this unit's effective build
 * category set after army and per-unit build restrictions are applied.
 */
bool Unit::CanBuild(const RUnitBlueprint* const blueprint) const
{
  // CArmyImpl +0x198 on x86: the IArmy payload at +0x08, `mVarDat` at +0x80,
  // `mCategoryFilterSet` at +0x110.
  const EntityCategorySet& armyBuildCategories = ArmyRef->mVarDat.mCategoryFilterSet;
  const EntityCategorySet& unitBlueprintBuildCategories = GetBlueprint()->Economy.CategoryCache;
  const EntityCategorySet& unitBuildRestrictions = GetAttributes().restrictionCategory;

  const std::uint32_t categoryBitIndex = blueprint->mCategoryBitIndex;
  return armyBuildCategories.ContainsBit(categoryBitIndex) &&
    unitBlueprintBuildCategories.ContainsBit(categoryBitIndex) &&
    !unitBuildRestrictions.ContainsBit(categoryBitIndex);
}

/**
 * Address: 0x0062D780 (FUN_0062D780, Moho::Unit::CanStartBuilding)
 *
 * What it does:
 * Returns true when this unit's army economy can start a build tick from
 * stored resources or by satisfying required income gates.
 */
bool Unit::CanStartBuilding(const float energyCost, const float massCost) const
{
  constexpr float kBuildResourceEpsilon = 0.001f;

  if (ArmyRef == nullptr) {
    return false;
  }

  const CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  if (economyInfo == nullptr) {
    return false;
  }

  // The tests are written the way the binary's branches read (0x0062D7A5..0x0062D7DB), not simplified: its comiss
  // leaves a NaN passing each of them, and an army's income can be NaN (replay 26939667, where a factory waited a tick
  // too long on a NaN mass income).
  const SEconTotals& totals = economyInfo->economy;
  if (!(kBuildResourceEpsilon >= totals.mStored.ENERGY) && !(kBuildResourceEpsilon >= totals.mStored.MASS)) {
    return true;
  }

  const bool hasEnergyBudget = !(energyCost > 0.0f) || !(kBuildResourceEpsilon > totals.mIncome.ENERGY);
  const bool hasMassBudget = !(massCost > 0.0f) || !(kBuildResourceEpsilon > totals.mIncome.MASS);
  return hasEnergyBudget && hasMassBudget;
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

/**
 * Address: 0x00603F10 (FUN_00603F10, Moho::Unit::DecrementCapturers)
 *
 * What it does:
 * Decrements the non-negative captor reference count at `CaptorCount`
 * (+0x690), clamped at zero. Returns the post-decrement count.
 */
std::int32_t Unit::DecrementCapturers()
{
  if (CaptorCount > 0) {
    --CaptorCount;
  }
  return CaptorCount;
}

/**
 * Address: 0x00603F30 (FUN_00603F30)
 *
 * What it does:
 * Returns the current non-negative captor reference count lane.
 */
std::int32_t Unit::GetCapturerCount() const noexcept
{
  return CaptorCount;
}

/**
 * Address: 0x005F24C0 (FUN_005F24C0)
 *
 * What it does:
 * Returns whether this unit belongs to the MELEE category lane.
 */
bool Unit::IsMeleeUnit() const noexcept
{
  return mIsMelee;
}

/**
 * Address: 0x005F5570 (FUN_005F5570)
 *
 * What it does:
 * Returns the current retaliation fire-state lane.
 */
std::int32_t Unit::GetFireStateValue() const noexcept
{
  return mUnitVarDat.mFireState;
}

/**
 * Address: 0x005F5560 (FUN_005F5560)
 *
 * What it does:
 * Stores one upgraded-unit entity id lane and returns that id.
 */
EntId Unit::SetUpgradedToEntityId(const EntId upgradedToEntityId) noexcept
{
  mUnitVarDat.mSelectionInheritorId = upgradedToEntityId;
  return upgradedToEntityId;
}

/**
 * Address: 0x005F5590 (FUN_005F5590)
 *
 * What it does:
 * Returns the current silo-build implementation lane pointer.
 */
CAiSiloBuildImpl* Unit::GetSiloBuildImpl() const noexcept
{
  return AiSiloBuild;
}

/**
 * Address: 0x006A75C0 (FUN_006A75C0, ?GetMaxFootprintSize@Unit@Moho@@QBEHXZ)
 *
 * What it does:
 * Returns the larger side length of this unit's footprint (`sizeX`/`sizeZ`).
 */
int Unit::GetMaxFootprintSize() const
{
  const SFootprint& footprint = GetFootprint();
  const int sizeX = static_cast<int>(footprint.mSizeX);
  const int sizeZ = static_cast<int>(footprint.mSizeZ);
  return (sizeX >= sizeZ) ? sizeX : sizeZ;
}

/**
 * Address: 0x006A7640 (FUN_006A7640, Moho::Unit::SetFocusEntity)
 * Mangled: ?SetFocusEntity@Unit@Moho@@QAEXPAVEntity@2@@Z
 *
 * What it does:
 * Rebinds the focus-entity weak reference at +0x4D0, runs the
 * `OnAssignedFocusEntity` Lua callback when the slot now holds a live
 * target (non-null, non-sentinel), then unconditionally marks the unit
 * dirty for sync replication.
 */
void Unit::SetFocusEntity(Entity* const focusEntity)
{
  FocusEntityRef.ResetFromObject(focusEntity);

  const WeakPtr<Entity>& focusLane = FocusEntityRef;
  if (focusLane.HasValue()) {
    RunScript(kUnitOnAssignedFocusEntityScript);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006A7680 (FUN_006A7680, ?SetTargetBlipEntity@Unit@Moho@@QAEXPAVEntity@2@@Z)
 *
 * What it does:
 * Rebinds target-blip weak-reference ownership and marks unit sync state
 * dirty for replication.
 */
void Unit::SetTargetBlipEntity(Entity* const blipEntity)
{
  TargetBlipEntityRef.Set(blipEntity);
  NeedSyncGameData = true;
}

// 0x006A49F0
bool Unit::IsDead() const
{
  return mVarDat.mIsDead != 0;
}

// 0x006A4A00
bool Unit::DestroyQueued() const
{
  return DestroyQueuedFlag != 0;
}

// 0x006A4A10
bool Unit::IsMobile() const
{
  return UnitMotion != nullptr;
}

// 0x006A4A20
bool Unit::IsBeingBuilt() const
{
  return mVarDat.mIsBeingBuilt != 0;
}

/**
 * Address: 0x006A4BD0 (FUN_006A4BD0, Moho::Unit::GetUniformScale)
 *
 * What it does:
 * Returns display uniform scale from the unit blueprint lane.
 */
float Unit::GetUniformScale() const
{
  return GetBlueprint()->Display.UniformScale;
}

/**
 * Address: 0x006A9C90 (FUN_006A9C90, Moho::Unit::GetVelocity)
 *
 * What it does:
 * Returns motion velocity when a unit-motion lane is active on non-air
 * layers; otherwise computes per-tick position delta scaled by
 * `mVelocityScale`.
 */
Wm3::Vec3f Unit::GetVelocity() const
{
  if (UnitMotion != nullptr && mVarDat.mLayerMask != LAYER_Air) {
    Wm3::Vec3f velocity{};
    (void)UnitMotion->GetVelocity(&velocity);
    return velocity;
  }

  Wm3::Vec3f velocity{};
  velocity.x = (mVarDat.mCurTransform.pos_.x - mVarDat.mLastTransform.pos_.x) * mVarDat.mCurImpactValue;
  velocity.y = (mVarDat.mCurTransform.pos_.y - mVarDat.mLastTransform.pos_.y) * mVarDat.mCurImpactValue;
  velocity.z = (mVarDat.mCurTransform.pos_.z - mVarDat.mLastTransform.pos_.z) * mVarDat.mCurImpactValue;
  return velocity;
}

/**
 * Address: 0x006A9350 (FUN_006A9350, Moho::Unit::AdjustHealth)
 *
 * What it does:
 * Forwards unit health adjustments to the shared `Entity` health mutation
 * path.
 */
void Unit::AdjustHealth(Entity* const instigator, const float delta)
{
  Entity::AdjustHealth(instigator, delta);
}

/**
 * Address: 0x006A9B50 (FUN_006A9B50, Moho::Unit::UpdateTerrainType)
 * Mangled: ?UpdateTerrainType@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Samples terrain type under this unit's footprint-centered cell, updates
 * `CurrentTerrainType`, and dispatches terrain-change script data when it
 * changes.
 */
void Unit::UpdateTerrainType(const Wm3::Vector3f& position)
{
  STIMap* const mapData = SimulationRef->mMapData;
  const SFootprint& footprint = GetFootprint();

  const auto sampleX = static_cast<std::int16_t>(
    static_cast<std::int32_t>(std::lrintf(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f)))
  );
  const auto sampleZ = static_cast<std::int16_t>(
    static_cast<std::int32_t>(std::lrintf(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)))
  );

  const std::uint8_t previousTerrainType = CurrentTerrainType;
  std::uint8_t nextTerrainType = 1u;

  const CHeightField* const heightField = mapData->mHeightField.get();
  if (static_cast<std::uint32_t>(sampleX) < static_cast<std::uint32_t>(heightField->width - 1)
      && static_cast<std::uint32_t>(sampleZ) < static_cast<std::uint32_t>(heightField->height - 1)) {
    const std::size_t index =
      static_cast<std::size_t>(sampleZ) * static_cast<std::size_t>(mapData->mTerrainType.width)
      + static_cast<std::size_t>(sampleX);
    nextTerrainType = mapData->mTerrainType.data[index];
  }

  CurrentTerrainType = nextTerrainType;
  if (nextTerrainType == previousTerrainType) {
    return;
  }

  LuaPlus::LuaObject previousTerrain = mapData->GetTerrainType(previousTerrainType);
  LuaPlus::LuaObject currentTerrain = mapData->GetTerrainType(CurrentTerrainType);
  RunScriptOnTerrainTypeChange(currentTerrain, previousTerrain);
}

/**
 * Address: 0x006A9A40 (FUN_006A9A40, Moho::Unit::HandleTerranEffects)
 *
 * What it does:
 * Reads terrain-type Lua data for this unit, applies periodic
 * `HealthEffectPerSecond` scaling against max health every 10 ticks, and
 * kills the unit when health reaches zero.
 */
void Unit::HandleTerranEffects()
{
  LuaPlus::LuaObject terrainType = SimulationRef->mMapData->GetTerrainType(CurrentTerrainType);
  if (!terrainType.IsTable()) {
    return;
  }

  if ((SimulationRef->mCurTick % 10u) != 0u) {
    return;
  }

  LuaPlus::LuaObject healthEffect = terrainType["HealthEffectPerSecond"];
  if (healthEffect.IsNil()) {
    return;
  }

  const float delta = healthEffect.GetNumber() * mVarDat.mMaxHealth;
  AdjustHealth(nullptr, delta);
  if (mVarDat.mHealth <= 0.0f) {
    Kill(nullptr, "", 0.0f);
  }
}

/**
 * Address: 0x006AB520 (FUN_006AB520, Moho::Unit::UpdateCollision)
 *
 * What it does:
 * Pushes the current transform into the collision primitive. Uses a widened
 * temporary box for skirt bucket membership and preserves the primitive
 * shape when refreshing the cached collision bounds.
 */
void Unit::UpdateCollision()
{
  if (CollisionExtents == nullptr) {
    return;
  }

  CollisionExtents->SetTransform(mVarDat.mCurTransform);
  if (CollisionExtents->GetBox() != nullptr) {
    Wm3::Box3f expandedBox(*CollisionExtents->GetBox());
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint != nullptr) {
      const float skirtExtentX = std::fabs(blueprint->Physics.SkirtOffsetX) + blueprint->Physics.SkirtSizeX;
      const float skirtExtentZ = std::fabs(blueprint->Physics.SkirtOffsetZ) + blueprint->Physics.SkirtSizeZ;
      expandedBox.Extent[0] = 0.5f * std::max(blueprint->mSizeX, skirtExtentX);
      expandedBox.Extent[2] = 0.5f * std::max(blueprint->mSizeZ, skirtExtentZ);
      UpdateRect(moho::AxisAlignedBoundsFromBox(expandedBox));
    } else {
      UpdateRect(CollisionExtents);
    }
  } else {
    UpdateRect(CollisionExtents);
  }
  UpdateAABox();
}

/**
 * Address: 0x006ABC30 (FUN_006ABC30, Moho::Unit::UpdateVisibility)
 *
 * What it does:
 * Recomputes base entity visibility lanes, then keeps unit visibility enabled
 * only for the focused army or when no army is focused.
 */
void Unit::UpdateVisibility()
{
  Entity::UpdateVisibility();
  const std::int32_t focusArmy = SimulationRef->mSyncFilter.focusArmy;
  mVarDat.mVisibilityHidden = static_cast<std::uint8_t>(focusArmy == -1 || focusArmy == ArmyRef->mConstDat.mArmyIndex);
}

/**
 * Address: 0x006AB410 (FUN_006AB410, ?AttachTo@Unit@Moho@@UAE_NABUSEntAttachInfo@2@@Z)
 *
 * What it does:
 * Attaches through `Entity::AttachTo`, then (for mobile units) notifies unit
 * motion and sets attached-state bit; resets cached transport load factor.
 */
bool Unit::AttachTo(const SEntAttachInfo& attachInfo)
{
  if (!Entity::AttachTo(attachInfo)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyAttached(attachInfo);
    mUnitVarDat.mUnitStates |= (1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  return true;
}

/**
 * Address: 0x006AB480 (FUN_006AB480, ?DetachFrom@Unit@Moho@@UAE_NPAVEntity@2@_N@Z)
 *
 * What it does:
 * Detaches through `Entity::DetachFrom`, then (for mobile units) notifies unit
 * motion and clears attached-state bit; resets cached transport load factor
 * and unlinks the transport weak-pointer chain.
 */
bool Unit::DetachFrom(Entity* const parent, const bool skipBallistic)
{
  if (!Entity::DetachFrom(parent, skipBallistic)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyDetached(parent, skipBallistic);
    mUnitVarDat.mUnitStates &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  TransportedByRef.UnlinkFromOwnerChain();
  return true;
}

/**
 * Address: 0x0062CD40 (FUN_0062CD40, Moho::Unit::PredictAheadBomb)
 *
 * What it does:
 * Predicts near-future XZ stop position by repeatedly rotating velocity with
 * impulse-derived roll and integrating over `precision * 10` ticks.
 *
 * Ground truth (`FUN_0062CD40.c`) builds `rollRotation` via
 * `Moho::EulerRollToQuat(&v15, &v17.x, a2a.y * 0.1)`, not
 * `Wm3::Quaternionf::MakeFromAxisAngle` (numerically identical for this
 * axis+angle, but not the function the binary actually calls), and rotates
 * via `Moho::MultQuadVec(&a2a, &v14, &v17)` each iteration, not the generic
 * `Wm3::MultiplyQuaternionVector` -- same quaternion-convention
 * mismatch as the other `MultQuadVec` consumers in this bug class.
 */
Wm3::Vec3f* Unit::PredictAheadBomb(Wm3::Vec3f* const out, const float precision) const
{
  if (!out) {
    return nullptr;
  }

  Wm3::Vec3f predicted = GetPosition();
  if (UnitMotion == nullptr) {
    *out = predicted;
    return out;
  }

  SPhysBody* const physBody = Entity::mPhysBody;
  if (physBody == nullptr) {
    *out = predicted;
    return out;
  }

  Wm3::Vec3f impulse = Wm3::Vec3f::Zero();
  physBody->GetImpulse(&impulse);

  // 0x0062CDDE: a virtual call through the entity vtable (+0x3C), so a unit
  // off the air layer predicts from its motion velocity (Unit::GetVelocity).
  Wm3::Vec3f velocity = GetVelocity();
  const Wm3::Vec3f upAxis(0.0f, 1.0f, 0.0f);
  Wm3::Quaternionf rollRotation{};
  (void)EulerRollToQuat(&upAxis, &rollRotation, impulse.y * 0.1f);

  float stepsRemaining = precision * 10.0f;
  while (stepsRemaining > 0.0f) {
    Wm3::Vec3f rotatedVelocity = Wm3::Vec3f::Zero();
    MultQuadVec(&rotatedVelocity, &velocity, &rollRotation);
    velocity = rotatedVelocity;

    float stepX = rotatedVelocity.x;
    float stepZ = rotatedVelocity.z;
    if (stepsRemaining <= 1.0f) {
      stepX *= stepsRemaining;
      stepZ *= stepsRemaining;
    }

    predicted.x += stepX;
    predicted.z += stepZ;
    stepsRemaining -= 1.0f;
  }

  *out = predicted;
  return out;
}

/**
 * Address: 0x006D3A40 (FUN_006D3A40, Moho::Unit::CalcBombDrop)
 *
 * What it does:
 * Scales current world velocity by ten ticks and resolves one ballistic
 * drop-point lane against `targetPosition` using sim gravity.
 */
Wm3::Vec3f* Unit::CalcBombDrop(Wm3::Vec3f* const out, const Wm3::Vec3f& targetPosition) const
{
  // 0x006D3A67: virtual, like PredictAheadBomb.
  Wm3::Vec3f velocity = GetVelocity();
  velocity.x *= 10.0f;
  velocity.y *= 10.0f;
  velocity.z *= 10.0f;

  return ComputeBombDropAimPoint(
    velocity,
    out,
    SimulationRef->mPhysConstants->mGravity,
    targetPosition,
    GetPosition()
  );
}

/**
 * Address: 0x006A7B90 (FUN_006A7B90, ?InitializeArmor@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Loads armor-definition rows for the blueprint armor type and seeds
 * `ArmorMultipliers` map entries from parsed `<damageType multiplier>` pairs.
 */
void Unit::InitializeArmor()
{
  const LuaPlus::LuaObject unitObject = GetLuaObject();

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const char* const armorTypeName = (blueprint != nullptr) ? blueprint->Defense.ArmorType.c_str() : "";
  const msvc8::list<msvc8::string> armorDefinitions = ARMOR_GetArmorDefinations(unitObject.GetActiveState(), armorTypeName);

  for (const msvc8::string& armorDefinition : armorDefinitions) {
    const char* definitionCursor = armorDefinition.c_str();
    msvc8::string damageTypeName{};
    if (!gpg::STR_GetToken(definitionCursor, " ", damageTypeName)) {
      continue;
    }

    const float armorMultiplier = static_cast<float>(std::atof(definitionCursor));
    ArmorMultipliers[damageTypeName] = armorMultiplier;
  }
}

/**
 * Address: 0x006A9D60 (FUN_006A9D60, ?ProcessArmorOnDamage@Unit@Moho@@QBEMMV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
 *
 * What it does:
 * Applies one armor multiplier lane to incoming damage when the incoming
 * damage-type token exists in `ArmorMultipliers`.
 */
float Unit::ProcessArmorOnDamage(const float amount, const msvc8::string damageType) const
{
  float scaledAmount = amount;
  if (const auto match = ArmorMultipliers.find(damageType); match != ArmorMultipliers.end()) {
    scaledAmount *= match->second;
  }

  return scaledAmount;
}

/**
 * Address: 0x006A9E10 (FUN_006A9E10, Moho::Unit::GetArmorMult)
 *
 * What it does:
 * Returns this unit's armor multiplier for one damage type. A damage type the
 * blueprint never listed returns 1.0, so it passes through unmodified.
 */
float Unit::GetArmorMult(const msvc8::string& damageType) const
{
  if (const auto match = ArmorMultipliers.find(damageType); match != ArmorMultipliers.end()) {
    return match->second;
  }

  return 1.0f;
}

/**
 * Address: 0x006A9F40 (FUN_006A9F40, Moho::Unit::Materialize)
 * Slot: 29 of ??_7Unit@Moho@@6BEntity@Moho@@@ (0x00E2A5EC)
 *
 * What it does:
 * Advances construction by `delta` and scales health to match. See the header
 * for the completion side effects.
 *
 * Returns the change actually applied to the build fraction: 0x006AA03E..
 * 0x006AA042 stores (new fraction - old fraction) into the frame slot the
 * epilogue at 0x006AA2F2 loads, on every path past the zero-delta exit.
 * CUnitReclaimTask credits reclaimed resources in proportion to it.
 */
float Unit::Materialize(const float delta)
{
  SimulationRef->Logf(
    "Unit[0x%08x]->Materialize(%.5f [0x%08x])\n", static_cast<std::uint32_t>(id_), delta,
    std::bit_cast<std::uint32_t>(delta)
  );

  // Any non-reversing step restamps the creation tick, so a unit dates from
  // when it finished rather than when it was placed.
  if (delta >= 0.0f) {
    mCreationTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
  }

  if (delta == 0.0f) {
    return 0.0f;
  }

  const float previousFraction = mVarDat.mFractionComplete;
  const float stepped = previousFraction + delta;
  if (delta <= 0.0f) {
    mVarDat.mFractionComplete = std::clamp(stepped, 0.0f, 1.0f);
  } else {
    float progressed = (stepped < 1.0f) ? stepped : 1.0f;
    if (progressed < 0.0f) {
      progressed = 0.0f;
    }
    // Never report less complete than the health already implies - health runs
    // ahead of the fraction when a part-built unit is repaired.
    const float healthRatio = mVarDat.mHealth / mVarDat.mMaxHealth;
    mVarDat.mFractionComplete = (healthRatio > progressed) ? healthRatio : progressed;
  }

  const float appliedFraction = mVarDat.mFractionComplete - previousFraction;
  AdjustHealth(nullptr, mVarDat.mMaxHealth * delta);

  if (mVarDat.mIsBeingBuilt == 0u || mVarDat.mFractionComplete != 1.0f) {
    return appliedFraction;
  }

  VarDat().mUnitStates &= ~(1ull << UNITSTATE_BeingBuilt);
  mVarDat.mIsBeingBuilt = 0u;

  const char* const layerName = (static_cast<unsigned int>(mVarDat.mLayerMask) > LAYER_Orbit)
                                  ? ""
                                  : Entity::LayerToString(mVarDat.mLayerMask);
  RunScriptOnStopBeingBuilt(CreatorRef, layerName);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint != nullptr && blueprint->General.CapCost > 0.0f) {
    if (CArmyStats* const armyStats = (ArmyRef != nullptr) ? ArmyRef->GetArmyStats() : nullptr;
        armyStats != nullptr) {
      const std::int32_t one = 1;
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_Active", &one);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &one);

      // Booked at blueprint cost, not at what the builder actually spent.
      float massCost = blueprint->Economy.BuildCostMass;
      float energyCost = blueprint->Economy.BuildCostEnergy;
      (void)AddArmyStatFloatByName(armyStats, &massCost, "Units_MassValue_Built");
      (void)AddArmyStatFloatByName(armyStats, &energyCost, "Units_EnergyValue_Built");

      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
    }
  }

  // Adjacency is a structure concept; mobile units never bond to neighbours.
  if (!IsMobile()) {
    EntitySetTemplate<Unit> overlapping{};
    (void)CollectAllOverlapping(&overlapping, this);
    for (Entity* const entry : overlapping.mVec) {
      Unit* const neighbour = static_cast<Unit*>(entry);
      if (neighbour == nullptr) {
        continue;
      }
      // Both directions: each side gets told about the other.
      RunScriptOnAdjacentTo(neighbour, this);
      neighbour->RunScriptOnAdjacentTo(this, this);
    }
  }

  return appliedFraction;
}

/**
 * Address: 0x006A7D10 (FUN_006A7D10, Moho::Unit::IsBusy)
 *
 * What it does:
 * Reports whether the unit currently has active navigation movement or
 * builder-side busy state.
 */
bool Unit::IsBusy() const
{
  const IAiNavigator* const navigator = AiNavigator;
  if (!navigator || !IsMobile() || navigator->GetStatus() == AINAVSTATUS_Idle) {
    const IAiBuilder* const builder = AiBuilder;
    if (builder == nullptr || !builder->BuilderIsBusy()) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x005F0E80 (FUN_005F0E80, Moho::Unit::NeedsPickup)
 *
 * What it does:
 * Estimates whether assisting `task->mUnit` should switch to pickup by
 * comparing this unit's goal ETA against assisted-unit interception ETA.
 */
bool Unit::NeedsPickup(const CUnitAssistMoveTask* const task) const
{
  if (IsUnitState(UNITSTATE_ProblemGettingToGoal)) {
    return true;
  }

  const Unit* const assistedUnit = task ? task->mUnit : nullptr;
  if (assistedUnit == nullptr) {
    return false;
  }

  const RUnitBlueprint* const assistedBlueprint = assistedUnit->GetBlueprint();
  const float assistedMaxSpeed =
    (assistedBlueprint->Air.CanFly != 0u) ? assistedBlueprint->Air.MaxAirspeed : assistedBlueprint->Physics.MaxSpeed;
  if (assistedMaxSpeed < 0.001f) {
    return false;
  }

  const RUnitBlueprint* const selfBlueprint = GetBlueprint();
  const float selfMaxSpeed = (selfBlueprint->Air.CanFly != 0u) ? selfBlueprint->Air.MaxAirspeed : selfBlueprint->Physics.MaxSpeed;
  if (selfMaxSpeed < 0.001f) {
    return false;
  }

  const IAiNavigator* const navigator = AiNavigator;
  if (navigator == nullptr) {
    return false;
  }

  const Wm3::Vec3f& selfPosition = GetPosition();
  const Wm3::Vector3f goalPosition = navigator->GetGoalPos();
  const float goalDx = goalPosition.x - selfPosition.x;
  const float goalDz = goalPosition.z - selfPosition.z;
  const float goalDistance = std::sqrt((goalDz * goalDz) + (goalDx * goalDx));
  // 0x005F0F79-0x005F0F92: `1.0f / selfSpeed` is formed once and multiplied
  // in -- here and again in the near-pickup branch below (0x005F1018).
  const float selfInvSpeed = 1.0f / selfMaxSpeed;
  const float goalTime = selfInvSpeed * goalDistance;

  const Wm3::Vec3f& assistedPosition = assistedUnit->GetPosition();
  const float taskDx = assistedPosition.x - selfPosition.x;
  const float taskDz = assistedPosition.z - selfPosition.z;
  const float taskDistance = std::sqrt((taskDx * taskDx) + (taskDz * taskDz));

  // 0x005F0FE0-0x005F0FFF: x87 `fadd`/`fdiv`/`fadd 5.0` under the sim
  // thread's `_PC_24` control word, i.e. single-precision rounding per step.
  float pickupEta = ((taskDistance + goalDistance) / assistedMaxSpeed) + 5.0f;
  if (assistedUnit->mVarDat.mLayerMask == LAYER_Air || taskDistance > selfBlueprint->AI.GuardScanRadius) {
    pickupEta += 4.0f;
  } else {
    pickupEta = (selfInvSpeed * taskDistance) + pickupEta;
  }

  return goalTime > pickupEta;
}

/**
 * Address: 0x006A7D60 (FUN_006A7D60, ?IsIdleState@Unit@Moho@@QBE_NXZ)
 *
 * What it does:
 * Returns true when the command queue has no valid head command.
 */
bool Unit::IsIdleState() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return true;
  }

  const CUnitCommand* const headCommand = commandQueue->mCommandVec.front().GetObjectPtr();
  return headCommand == nullptr;
}

/**
 * Address: 0x0062F030 (FUN_0062F030, Moho::Unit::FindPlatform)
 *
 * IDA signature:
 * Moho::Unit* __usercall FindPlatform@<eax>(Moho::Unit* this@<ecx>, int @<ebx>);
 *
 * What it does:
 * For an air unit needing refuel/repair (and not its own formation lead),
 * scans the owning army's AIRSTAGINGPLATFORM units for the first idle,
 * in-bounds transport within staging-platform scan radius that can receive
 * this unit. Returns that platform, or null.
 */
Unit* Unit::FindPlatform()
{
  // Guard: alive flying unit, fueled (or no motor), with the refuel-order cap.
  if (IsDead()) {
    return nullptr;
  }
  if (!GetBlueprint()->Air.CanFly) {
    return nullptr;
  }
  if (UnitMotion != nullptr && mUnitVarDat.mFuelRatio < 0.0f) {
    return nullptr;
  }
  if ((GetAttributes().commandCapsMask & 0x400000u) == 0u) {
    return nullptr;
  }

  // Skip if this unit is its own formation lead.
  if (IUnit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
      formationLead != nullptr && formationLead->IsUnit() == this) {
    return nullptr;
  }

  // Need refuel: threshold ratio exceeds current fuel ratio.
  const float fuelRatio = mUnitVarDat.mFuelRatio;
  bool needsService = false;
  if (CSimConVarBase* const needRefuelDef = &moho::gSimConVar_NeedRefuelThresholdRatio;
      needRefuelDef != nullptr) {
    if (CSimConVarInstanceBase* const needRefuel = SimulationRef->GetSimVar(needRefuelDef);
        needRefuel != nullptr) {
      needsService = *static_cast<const float*>(needRefuel->GetValueStorage()) > fuelRatio;
    }
  }
  // Need repair: threshold ratio exceeds the health fraction. 0x0062F10F
  // loads health (+0x98) and 0x0062F14A divides it by max health (+0x9C).
  if (!needsService) {
    const float health = mVarDat.mHealth;
    const float maxHealth = mVarDat.mMaxHealth;
    if (CSimConVarBase* const needRepairDef = &moho::gSimConVar_NeedRepairThresholdRatio;
        needRepairDef != nullptr) {
      if (CSimConVarInstanceBase* const needRepair = SimulationRef->GetSimVar(needRepairDef);
          needRepair != nullptr) {
        needsService = *static_cast<const float*>(needRepair->GetValueStorage()) > (health / maxHealth);
      }
    }
  }
  if (!needsService) {
    return nullptr;
  }

  RRuleGameRules* const rules = SimulationRef->mRules;
  const EntityCategorySet* const stagingPlatformCategory = rules->GetEntityCategory("AIRSTAGINGPLATFORM");
  const EntityCategorySet* const carrierCategory = rules->GetEntityCategory("CARRIER");

  EntitySetTemplate<Entity> stagingPlatforms;
  ArmyRef->GetUnits(&stagingPlatforms, const_cast<EntityCategorySet*>(stagingPlatformCategory));

  for (Entity* const platformEntity : stagingPlatforms) {
    if (platformEntity == nullptr) {
      continue;
    }
    Unit* const platform = static_cast<Unit*>(platformEntity);
    if (platform->IsDead() || platform->IsBeingBuilt() || platform->DestroyQueued()) {
      continue;
    }
    IAiTransport* const transport = platform->AiTransport;
    if (transport == nullptr) {
      continue;
    }

    const Wm3::Vec3f& platformPos = platform->GetPosition();
    const Wm3::Vec3f& selfPos = GetPosition();
    const float dz = selfPos.z - platformPos.z;
    const float dx = selfPos.x - platformPos.x;
    const float distance = std::sqrt(dz * dz + dx * dx);
    if (distance > platform->GetBlueprint()->AI.StagingPlatformScanRadius) {
      continue;
    }
    if (!platform->IsInBounds(ArmyRef->UseWholeMap(), 1.0f)) {
      continue;
    }
    if (!platform->IsIdleState()) {
      continue;
    }
    const ELayer platformLayer = platform->mVarDat.mLayerMask;
    if (platformLayer == LAYER_Seabed || platformLayer == LAYER_Sub) {
      continue;
    }

    if (EntityCategory::HasBlueprint(platform->GetBlueprint(), carrierCategory)) {
      if (transport->TransportHasAvailableStorage()) {
        return platform;
      }
    } else if (transport->TransportHasSpaceFor(GetBlueprint())) {
      return platform;
    }
  }

  return nullptr;
}

/**
 * Address: 0x006AC940 (FUN_006AC940, ?UpdateSpeedThroughStatus@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Recomputes whether pathing should use speed-through-goal mode for this unit
 * from command queue state, formation leader weak-link ownership, and escort
 * movement heuristics.
 */
void Unit::UpdateSpeedThroughStatus()
{
  if (IsBeingBuilt() || IsDead() || DestroyQueued()) {
    return;
  }

  CUnitCommandQueue* const commandQueue = CommandQueue;
  IAiNavigator* const navigator = AiNavigator;
  if (commandQueue == nullptr || navigator == nullptr) {
    return;
  }

  CUnitCommand* const currentCommand = commandQueue->GetCurrentCommand();
  CUnitCommand* const nextCommand = commandQueue->GetNextCommand();

  if (IsUnitState(UNITSTATE_Refueling)) {
    navigator->SetSpeedThroughGoal(false);
    return;
  }

  bool enableSpeedThrough = false;
  if (IsUnitState(UNITSTATE_ForceSpeedThrough) || IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
    enableSpeedThrough = true;
  } else {
    bool isAirEscort = false;
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint->Air.CanFly && IsUnitState(UNITSTATE_Guarding) && !IsUnitState(UNITSTATE_Ferrying)) {
      if (!IsInCategory("EXPERIMENTAL")) {
        isAirEscort = true;
      }
    }

    if (isAirEscort) {
      enableSpeedThrough = true;
    } else if (
      currentCommand != nullptr
      && nextCommand != nullptr
      && nextCommand->GetCoordinatingOrdersSnapshot().empty()
    ) {
      if (IsSpeedThroughBusyCommandType(currentCommand->mVarDat.mCmdType)
          && IsSpeedThroughBusyCommandType(nextCommand->mVarDat.mCmdType) && !IsUnitState(UNITSTATE_AssistMoving)) {
        const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
        if (formationLead == nullptr || formationLead == this) {
          enableSpeedThrough = true;
        }
      }
    }
  }

  navigator->SetSpeedThroughGoal(enableSpeedThrough);
}

/**
 * Address: 0x006AA310 (FUN_006AA310, ?Warp@Unit@Moho@@UAEXVVTransform@2@@Z)
 *
 * What it does:
 * Recomputes spawn elevation/layer for the incoming transform, warps through
 * motion component when present, then refreshes entity layer and terrain type.
 */
void Unit::Warp(const VTransform& transform)
{
  VTransform warpedTransform = transform;
  const ELayer startingLayer = GetStartingLayer(warpedTransform.pos_, LAYER_None);

  const Sim* const sim = SimulationRef;
  const STIMap* const mapData = sim ? sim->mMapData : nullptr;
  warpedTransform.pos_.y = IUnit::CalcSpawnElevation(mapData, startingLayer, warpedTransform, mUnitVarDat.mAttributes);

  if (UnitMotion != nullptr) {
    UnitMotion->Warp(warpedTransform);
    if (AiNavigator != nullptr) {
      AiNavigator->AbortMove();
    }
  } else {
    Entity::Warp(warpedTransform);
  }

  SetCurrentLayer(startingLayer);
  // 0x006AA428: `call Unit::UpdateTerrainType` (0x006A9B50) on the
  // elevation-adjusted warp position.
  UpdateTerrainType(warpedTransform.pos_);
}

// 0x006A7DC0
bool Unit::IsNavigatorIdle() const
{
  return !AiNavigator || AiNavigator->GetStatus() == 0;
}

// 0x006A4AF0
bool Unit::IsUnitState(const EUnitState state) const
{
  const std::uint32_t bit = static_cast<std::uint32_t>(state);
  if (bit >= 64u) {
    return false;
  }
  return (mUnitVarDat.mUnitStates & (1ull << bit)) != 0ull;
}

/**
 * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
 */
Unit* Unit::GetGuardedUnit() const
{
  return GuardedUnitRef.GetObjectPtr();
}

/**
 * Address: 0x006AD060 (FUN_006AD060,
 *   ?GetBlipsInRange@Unit@Moho@@QAEAAV?$fastvector_n@V?$WeakPtr@VEntity@Moho@@@Moho@@$0BE@@gpg@@I@Z)
 *
 * IDA signature:
 * gpg::fastvector_n20_WeakPtr_Entity *__userpurge GetBlipsInRange@<eax>(
 *   Moho::Unit *this@<esi>, unsigned int interval);
 *
 * What it does:
 * Refreshes `mBlipsInRange` via `UpdateBlipsInRange()` when it is at least
 * `maxAgeTicks` ticks stale (current sim tick minus the last update tick, as an
 * unsigned compare), then returns a reference to the cached list.
 */
gpg::core::FastVectorN<WeakPtr<Entity>, 20>& Unit::GetBlipsInRange(const unsigned int maxAgeTicks)
{
  const unsigned int ticksSinceUpdate =
    SimulationRef->mCurTick - static_cast<unsigned int>(mBlipLastUpdateTick);
  if (ticksSinceUpdate >= maxAgeTicks) {
    UpdateBlipsInRange();
  }
  return mBlipsInRange;
}

/**
 * Address: 0x006ACC60 (FUN_006ACC60, ?UpdateBlipsInRange@Unit@Moho@@QAEXXZ)
 *
 * IDA signature:
 * void __stdcall Moho::Unit::UpdateBlipsInRange(Moho::Unit *this);
 *
 * What it does:
 * Rebuilds `mBlipsInRange` (see the field-by-field walk in the header). Computes
 * the effective scan radius (guard-scan blueprint radius when the head command is
 * a guard/patrol command, extended by the attacker's max weapon range), gathers
 * enemy units in that radius via `COGrid::EntitiesAroundPoint`, keeps those the
 * army can see as recon blips and (when set) within the army no-rush radius,
 * records a weak reference to each, and additionally records the jamming-shadow
 * blips of any candidate whose intel manager has active jamming. Finally stamps
 * `mBlipLastUpdateTick` with the current sim tick.
 */
void Unit::UpdateBlipsInRange()
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  CAiAttackerImpl* const attacker = AiAttacker;

  // Guard-scan radius: zero unless the head command passes FAF's patched gate.
  //
  // That gate (0x0128F2B6, jumped to from 0x006ACC95) loads the head of the
  // command queue's weak-pointer vector -- the pointer is the command's weak
  // link slot at `command+4` -- and tests `[slot+94h] & 30h`, i.e. the
  // command's `mCmdType` at `+0x98`.
  float scanRadius = 0.0f;
  CUnitCommand* const headCommand = CommandQueue->GetCurrentCommand();
  if (headCommand != nullptr && (static_cast<std::uint32_t>(headCommand->mVarDat.mCmdType) & 0x30u) != 0u) {
    scanRadius = blueprint->AI.GuardScanRadius;
  }

  // Extend the scan radius by the attacker's max weapon range.
  if (attacker != nullptr) {
    const float maxWeaponRange = attacker->GetMaxWeaponRange();
    if (maxWeaponRange > scanRadius) {
      scanRadius = maxWeaponRange;
    }
  }

  // No-rush centre = army start position + configured no-rush offset; used to
  // reject blips outside the no-rush radius while the no-rush timer is active.
  CArmyImpl* const army = ArmyRef;
  const float noRushOffsetX = army->mVarDat.mNoRushOffset.x;
  const float noRushOffsetY = army->mVarDat.mNoRushOffset.y;
  Wm3::Vector2f armyStartPosition{};
  army->GetArmyStartPos(armyStartPosition);
  const float noRushCenterX = armyStartPosition.x + noRushOffsetX;
  const float noRushCenterZ = armyStartPosition.y + noRushOffsetY;
  const float noRushRadius = army->mVarDat.mNoRushRadius;

  // Gather every unit within the scan radius of this unit's position.
  gpg::core::FastVectorN<CollisionResult, 10> unitsInRange{};
  COGrid* const grid = SimulationRef->mOGrid;
  EntitiesAroundPoint(unitsInRange, scanRadius, *grid, ENTITYTYPE_Unit, GetPosition());

  // Reset the blip list: unlink every currently-held weak reference from its
  // owner chain, release escaped heap storage, and rebind to inline storage.
  // Engine addition (sim_DeferBlipUnlinks): a heap block's unlinks wait for the
  // next tick and run in bulk; see `DeferredBlipUnlinks`.
  if (sim_DeferBlipUnlinks) {
    BlipListUnlinks().Adopt(mBlipsInRange, SimulationRef->mCurTick);
  } else {
    BlipListUnlinks().Flush();
    mBlipsInRange.ResetStorageToInline();
  }

  for (const CollisionResult& hit : unitsInRange) {
    Entity* const candidate = hit.sourceEntity;
    if (candidate == nullptr || candidate->mVarDat.mIsDead != 0u) {
      continue;
    }

    Unit* const candidateUnit = candidate->IsUnit();
    if (candidateUnit == nullptr || candidate->DestroyQueuedFlag != 0u) {
      continue;
    }

    CArmyImpl* const candidateArmy = candidate->ArmyRef;
    const std::uint32_t candidateArmyIndex =
      (candidateArmy != nullptr) ? static_cast<std::uint32_t>(candidateArmy->mConstDat.mArmyIndex) : 0xFFFFFFFFu;
    // IArmy::IsAlly (FUN_005BD630) is shadowed on CArmyImpl by the same-named
    // cached byte field (+0x128); its body is the allies bit-set membership
    // test, replicated here via the shared `Set::Contains` helper.
    if (army->mVarDat.mAllies.Contains(candidateArmyIndex)) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    ReconBlip* const blip = (reconDb != nullptr) ? reconDb->ReconGetBlip(candidateUnit) : nullptr;
    if (blip == nullptr) {
      continue;
    }

    if (army->mVarDat.mNoRushTimer > 0) {
      const float deltaX = noRushCenterX - candidate->mVarDat.mCurTransform.pos_.x;
      const float deltaZ = noRushCenterZ - candidate->mVarDat.mCurTransform.pos_.z;
      const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      if (distance > noRushRadius) {
        continue;
      }
    }

    // Record a weak reference to the visible enemy.
    mBlipsInRange.push_back(WeakPtr<Entity>(candidate));

    // When the candidate is actively jamming, also record its shadow blips.
    if (candidateUnit->mIntelManager->HasActiveJamming()) {
      EntitySetTemplate<Entity> jammingBlips = army->GetReconDB()->ReconGetJamingBlips(candidateUnit);
      for (Entity* const jammingEntity : jammingBlips) {
        mBlipsInRange.push_back(WeakPtr<Entity>(jammingEntity));
      }
    }
  }

  mBlipLastUpdateTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
}

/**
 * Address: 0x006A76A0 (FUN_006A76A0, Moho::Unit::SetGuardedUnit)
 *
 * What it does:
 * Rebinds guarded-unit weak-link ownership, updates guarded-by slot lanes on
 * old/new guarded units, clears stale guard-formation lanes, and marks this
 * unit sync-dirty.
 */
void Unit::SetGuardedUnit(Unit* const guarded)
{
  Unit* const oldGuardedUnit = GuardedUnitRef.GetObjectPtr();
  if (oldGuardedUnit != nullptr) {
    (void)oldGuardedUnit->GuardedByList.Remove(this); // 0x005E8960
    ClearGuardFormation(oldGuardedUnit);
  }

  GuardedUnitRef.Set(guarded);

  Unit* const newGuardedUnit = GuardedUnitRef.GetObjectPtr();
  if (newGuardedUnit != nullptr) {
    (void)newGuardedUnit->GuardedByList.Add(this); // 0x0057DDD0
    ClearGuardFormation(newGuardedUnit);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006AA720 (FUN_006AA720, ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z)
 * Mangled: ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z
 *
 * What it does:
 * Inserts one guarding owner into this unit's guarded-by list when non-null,
 * then clears this unit's guard-formation lane.
 */
void Unit::RemoveGuardedByUnit(Unit* const guardedByUnit)
{
  if (guardedByUnit != nullptr) {
    (void)GuardedByList.Add(guardedByUnit); // 0x0057DDD0
  }

  ClearGuardFormation(this);
}

/**
 * Address: 0x00585B10 (FUN_00585B10, Moho::Unit::GetFocusEntity)
 */
Entity* Unit::GetFocusEntity() const
{
  return FocusEntityRef.GetObjectPtr();
}

/**
 * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
 */
Unit* Unit::GetStagingPlatform() const
{
  Unit* const transport = TransportedByRef.GetObjectPtr();
  if (transport == nullptr) {
    return nullptr;
  }

  if (transport->IsDead()) {
    return nullptr;
  }

  IAiTransport* const aiTransport = transport->AiTransport;
  if (aiTransport == nullptr || !aiTransport->TransportIsAirStagingPlatform()) {
    return nullptr;
  }

  return transport;
}

/**
 * Address: 0x005E3C30 (FUN_005E3C30, Moho::Unit::GetTransportedBy)
 */
Unit* Unit::GetTransportedBy() const
{
  return TransportedByRef.GetObjectPtr();
}

/**
 * Address: 0x005F0980 (FUN_005F0980, Moho::Unit::GetFerryUnit)
 *
 * IDA signature:
 * Moho::Unit *__usercall Moho::Unit::GetFerryUnit@<eax>(Moho::Unit *a1@<eax>);
 *
 * What it does:
 * Returns the unit currently bound to this unit's assigned-transport weak
 * lane (Unit +0x4C8). Identical accessor body to the binary's tiny FUN_005F0980
 * thunk: load the slot, return owner-decoded pointer or null on sentinel.
 */
Unit* Unit::GetFerryUnit() const
{
  return AssignedTransportRef.GetObjectPtr();
}

/**
 * Address: 0x0060DAD0 (FUN_0060DAD0, Moho::Unit::SetAssignedTransport)
 *
 * What it does:
 * Rebinds this unit's assigned-transport weak-reference lane.
 */
void Unit::SetAssignedTransport(Unit* const assignedTransport)
{
  AssignedTransportRef.Set(assignedTransport);
}

/**
 * Address: 0x006A8890 (FUN_006A8890, Moho::Unit::GetTransportFerryBeacon)
 *
 * What it does:
 * Returns ferry-beacon unit ownership from the current command-queue head
 * command when the weak unit lane resolves to a live unit.
 */
Unit* Unit::GetTransportFerryBeacon() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return nullptr;
  }

  const CUnitCommand* const command = commandQueue->mCommandVec.front().GetObjectPtr();
  if (command == nullptr) {
    return nullptr;
  }

  return command->mUnit.GetObjectPtr();
}

/**
 * Address: 0x005F5540 (FUN_005F5540, Moho::Unit::GetCreator)
 *
 * What it does:
 * Resolves `CreatorRef` intrusive weak-link slot to a `Unit*`.
 */
Unit* Unit::GetCreator() const
{
  return CreatorRef.GetObjectPtr();
}

/**
 * Address: 0x0062D2B0 (FUN_0062D2B0, Moho::Unit::OverlapsWith)
 *
 * What it does:
 * Returns true when this unit skirt rectangle overlaps `other` using the
 * original 1.0f edge-contact tolerance checks.
 */
bool Unit::OverlapsWith(Unit* const other) const
{
  if (other == nullptr || IsDead() || other->IsDead()) {
    return false;
  }

  const gpg::Rect2f thisSkirt = GetSkirtRect();
  const gpg::Rect2f otherSkirt = other->GetSkirtRect();

  const float xEdgeDelta0 = std::fabs(thisSkirt.x0 - otherSkirt.x1);
  const float xEdgeDelta1 = std::fabs(thisSkirt.x1 - otherSkirt.x0);
  const bool xEdge0WithinTolerance = xEdgeDelta0 >= 0.0f && xEdgeDelta0 < 1.0f;
  const bool xEdge1WithinTolerance = xEdgeDelta1 >= 0.0f && xEdgeDelta1 < 1.0f;

  if (xEdge0WithinTolerance || xEdge1WithinTolerance) {
    return (thisSkirt.z0 >= otherSkirt.z0 && otherSkirt.z1 >= thisSkirt.z1) ||
      (otherSkirt.z0 >= thisSkirt.z0 && thisSkirt.z1 >= otherSkirt.z1);
  }

  const float yEdgeDelta0 = std::fabs(thisSkirt.z0 - otherSkirt.z1);
  const float yEdgeDelta1 = std::fabs(thisSkirt.z1 - otherSkirt.z0);
  const bool yEdge0WithinTolerance = yEdgeDelta0 >= 0.0f && yEdgeDelta0 < 1.0f;
  const bool yEdge1WithinTolerance = yEdgeDelta1 >= 0.0f && yEdgeDelta1 < 1.0f;

  if (!(yEdge0WithinTolerance || yEdge1WithinTolerance)) {
    return false;
  }

  return (thisSkirt.x0 >= otherSkirt.x0 && otherSkirt.x1 >= thisSkirt.x1) ||
    (otherSkirt.x0 >= thisSkirt.x0 && thisSkirt.x1 >= otherSkirt.x1);
}

/**
 * Address: 0x006A8C20 (FUN_006A8C20, Moho::Unit::GetFormationVector)
 *
 * What it does:
 * Resolves one unit movement vector from formation runtime lanes, with
 * air-leader fallback to leader forward heading when applicable.
 */
Wm3::Vector3f Unit::GetFormationVector() const
{
  Wm3::Vector3f result{0.0f, 0.0f, 0.0f};

  if (IsUnitState(UNITSTATE_TransportLoading) || IsUnitState(UNITSTATE_Refueling) ||
      mInfoCache.mFormationLayer == nullptr) {
    return result;
  }

  if (mIsAir) {
    const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
    if (formationLead != nullptr && !formationLead->mIsAir) {
      return ForwardXZ(*formationLead);
    }
  }

  const auto* const formationLayer = reinterpret_cast<const CAiFormationInstance*>(mInfoCache.mFormationLayer);
  if (formationLayer != nullptr && formationLayer->CommandIsForm()) {
    formationLayer->GetForwardVector(&result, const_cast<Unit*>(this));
  }

  return result;
}

/**
 * Address: 0x006A9720 (FUN_006A9720, Moho::Unit::GetFormation)
 *
 * What it does:
 * Resolves active formation ownership either from guarded-unit formation lane
 * or from the current command queue head command.
 */
IFormationInstance* Unit::GetFormation() const
{
  Unit* const guardedUnit = GuardedUnitRef.GetObjectPtr();
  if (guardedUnit != nullptr && !mIsEngineer) {
    if (IsUnitState(UNITSTATE_GuardBusy)) {
      return nullptr;
    }

    return guardedUnit->GuardFormation;
  }

  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    CUnitCommand* const currentCommand = commandQueue->mCommandVec.front().GetObjectPtr();
    if (currentCommand != nullptr) {
      CAiFormationInstance* const commandFormation = currentCommand->mFormationInstance;
      if (commandFormation != nullptr && commandFormation->Contains(const_cast<Unit*>(this), true)) {
        return commandFormation;
      }
    }
  }

  return nullptr;
}

/**
 * Address: 0x006A9810 (FUN_006A9810, Moho::Unit::UpdateInfoCache)
 *
 * What it does:
 * Refreshes cached formation-owner/speed lanes and recomputes movement top
 * speed for mobile units.
 */
void Unit::UpdateInfoCache()
{
  if (!IsMobile()) {
    return;
  }

  CAiFormationInstance* const formation = reinterpret_cast<CAiFormationInstance*>(GetFormation());
  SOffsetInfo* offsetInfo = nullptr;

  if (formation != nullptr && formation->CommandIsForm() && formation->Contains(this, false)) {
    // Virtual-call order as at 0x006A9860-0x006A98DF: GetOffsetInfo,
    // GetPriority, GetLeader, GetTargetPosition, GetDistFromLeader,
    // IsInFormation.
    offsetInfo = formation->GetOffsetInfo(this);
    mInfoCache.mFormationLayer = reinterpret_cast<CFormationInstance*>(formation);
    mInfoCache.mFormationPriorityOrder = formation->GetPriority(this, offsetInfo);

    Unit* const formationLead = formation->GetLeader(this, offsetInfo);
    mInfoCache.mFormationLeadRef.Set(formationLead);

    Wm3::Vec3f headingHint{};
    formation->GetTargetPosition(&headingHint, this, offsetInfo);
    mInfoCache.mFormationHeadingHint = headingHint;
    mInfoCache.mFormationDistanceMetric = formation->GetDistFromLeader(this, offsetInfo);
    // 0x006A98DB: `push 0` -- IsInFormation is asked about a null unit, not
    // `this`.
    mInfoCache.mHasFormationSpeedData = formation->IsInFormation(nullptr);
  } else {
    // 0x006A98E9-0x006A9951: layer = null, priority = 1, lead link cleared,
    // heading = own position, distance = 0, flag = false.
    mInfoCache.mFormationLayer = nullptr;
    mInfoCache.mFormationPriorityOrder = 1;
    mInfoCache.mFormationLeadRef.Set(nullptr);
    mInfoCache.mFormationHeadingHint = GetPosition();
    mInfoCache.mFormationDistanceMetric = 0.0f;
    mInfoCache.mHasFormationSpeedData = false;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    mInfoCache.mFormationTopSpeed = 0.0f;
    return;
  }

  const float speedMult = GetAttributes().moveSpeedMult;
  float topSpeed = 0.0f;
  if (!blueprint->Air.CanFly) {
    topSpeed = blueprint->Physics.MaxSpeed * speedMult;
  } else {
    topSpeed = (blueprint->Air.MaxAirspeed * speedMult) / CalcTransportLoadFactor();
  }

  float speedScale = 1.0f;
  float clampedFormationSpeed = topSpeed;
  if (formation != nullptr && offsetInfo != nullptr) {
    const float formationSpeed = formation->CalcFormationSpeed(this, &speedScale, offsetInfo);
    if (formationSpeed > 0.0f) {
      clampedFormationSpeed = (formationSpeed > topSpeed) ? topSpeed : formationSpeed;
    }
  }

  const float scaledSpeed = speedScale * clampedFormationSpeed;
  // 0x006A9A24: `comiss scaled, top` / `ja` keeps `top`; unordered falls
  // through to the scaled value.
  if (!(scaledSpeed > topSpeed)) {
    topSpeed = scaledSpeed;
  }

  mInfoCache.mFormationTopSpeed = topSpeed;
}

/**
 * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
 */
bool Unit::IsHigherPriorityThan(const Unit* const other) const
{
  if (!other) {
    return true;
  }

  if (IsUnitState(UNITSTATE_Immobile) || IsUnitState(UNITSTATE_Upgrading)) {
    return true;
  }
  if (other->IsUnitState(UNITSTATE_Immobile) || other->IsUnitState(UNITSTATE_Upgrading)) {
    return false;
  }

  if (mIsNaval) {
    if (!other->mIsNaval) {
      return true;
    }
  } else if (other->mIsNaval) {
    return false;
  }

  const bool thisIgnoreStructures = HasFootprintFlag(GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  const bool otherIgnoreStructures =
    HasFootprintFlag(other->GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  if (thisIgnoreStructures) {
    if (!otherIgnoreStructures) {
      return true;
    }
  } else if (otherIgnoreStructures) {
    return false;
  }

  if (const RUnitBlueprint* const blueprint = GetBlueprint()) {
    if (blueprint->Air.CanFly && mVarDat.mLayerMask != LAYER_Air) {
      return true;
    }
  }
  if (const RUnitBlueprint* const blueprint = other->GetBlueprint()) {
    if (blueprint->Air.CanFly && other->mVarDat.mLayerMask != LAYER_Air) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_WaitingForTransport) && !other->IsUnitState(UNITSTATE_WaitingForTransport)) {
    return true;
  }

  if (GetGuardedUnit() == other) {
    return false;
  }
  if (other->GetGuardedUnit() == this) {
    return true;
  }

  bool inSharedFormation = false;
  if (mInfoCache.mFormationLayer && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer) {
    inSharedFormation = true;

    const Unit* const formationLead = mInfoCache.mFormationLeadRef.GetObjectPtr();
    if (formationLead == this) {
      return true;
    }
    if (formationLead == other) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_Moving) && !other->IsUnitState(UNITSTATE_Moving)) {
    return false;
  }
  if (!IsUnitState(UNITSTATE_Moving) && other->IsUnitState(UNITSTATE_Moving)) {
    return true;
  }

  if (inSharedFormation) {
    if (mInfoCache.mFormationPriorityOrder != other->mInfoCache.mFormationPriorityOrder) {
      return mInfoCache.mFormationPriorityOrder < other->mInfoCache.mFormationPriorityOrder;
    }
    return other->mInfoCache.mFormationDistanceMetric > mInfoCache.mFormationDistanceMetric;
  }

  const SFootprint& thisFootprint = GetFootprint();
  const SFootprint& otherFootprint = other->GetFootprint();
  const std::uint8_t thisFootprintSize = std::max(thisFootprint.mSizeX, thisFootprint.mSizeZ);
  const std::uint8_t otherFootprintSize = std::max(otherFootprint.mSizeX, otherFootprint.mSizeZ);
  if (thisFootprintSize > otherFootprintSize) {
    return true;
  }
  if (thisFootprintSize != otherFootprintSize) {
    return false;
  }

  if (const Unit* const moreInLine = UnitMoreInLineToOther(other, this)) {
    return moreInLine == this;
  }

  return static_cast<std::uint32_t>(GetEntityId()) < static_cast<std::uint32_t>(other->GetEntityId());
}

[[nodiscard]] bool PrepareMove(
  int moveFlags,
  Unit* unit,
  Wm3::Vector3f* inOutPos,
  gpg::Rect2f* outSkirtRect,
  bool useWholeMap
)
{
  // Alias of FUN_0062B780 canonical body in Unit::PrepareMove.
  if (unit == nullptr) {
    return false;
  }
  return unit->PrepareMove(moveFlags, inOutPos, outSkirtRect, useWholeMap);
}
namespace moho
{
  [[nodiscard]] bool PrepareMove(
    int moveFlags,
    Unit* unit,
    Wm3::Vector3f* inOutPos,
    gpg::Rect2f* outSkirtRect,
    bool useWholeMap
  )
  {
    return ::PrepareMove(moveFlags, unit, inOutPos, outSkirtRect, useWholeMap);
  }
}



/**
 * Address: 0x0062BEE0 (FUN_0062BEE0, Moho::Unit::HasMeleeSpaceAroundSmallTarget)
 *
 * What it does:
 * Scans perimeter candidate cells around `target` using this unit footprint,
 * filters by occupancy/pathability checks, and writes nearest valid melee
 * destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundSmallTarget(Unit* const target, SOCellPos* const inOutCell)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const SFootprint& targetFootprint = target->GetFootprint();
  const ELayer moveLayer = mVarDat.mLayerMask;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const int minX = static_cast<int>(inOutCell->x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = static_cast<int>(inOutCell->x) + static_cast<int>(targetFootprint.mSizeX);
  const int minZ = static_cast<int>(inOutCell->z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = static_cast<int>(inOutCell->z) + static_cast<int>(targetFootprint.mSizeZ);
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = gpg::pInf;
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    int stepX = ((z == minZ) || (z == maxZ)) ? 1 : (maxX - minX);
    if (stepX <= 0) {
      stepX = 1;
    }

    for (int x = minX; x <= maxX; x += stepX) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
}

/**
 * Address: 0x0062C340 (FUN_0062C340, Moho::Unit::HasMeleeSpaceAroundLargeTarget)
 *
 * What it does:
 * Scans a collision-bounds search window around `target`, applies shell
 * collision probes plus occupancy/pathability checks, and writes nearest
 * valid melee destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundLargeTarget(Unit* const target, SOCellPos* const inOutCell, const int targetSize)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  CColPrimitiveBase* const targetCollisionShape = target->CollisionExtents;
  if (targetCollisionShape == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const ELayer moveLayer = mVarDat.mLayerMask;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const float innerHalfExtentX = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeX)) * 0.5f;
  const float innerHalfExtentZ = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeZ)) * 0.5f;
  const float outerHalfExtentX = innerHalfExtentX + 1.0f;
  const float outerHalfExtentZ = innerHalfExtentZ + 1.0f;

  constexpr float kMeleeProbeHalfHeight = 1000.0f;
  Wm3::Box3f outerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(outerHalfExtentX, kMeleeProbeHalfHeight, outerHalfExtentZ)
  );
  Wm3::Box3f innerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(innerHalfExtentX, kMeleeProbeHalfHeight, innerHalfExtentZ)
  );
  CollisionResult collisionResult{};

  // 0x0062C558..0x0062C5F0: the binary's inlined floor and ceil.
  const int minX = msvc8::FloorToIntX87(target->mAABox.Min.x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = msvc8::CeilToIntX87(target->mAABox.Max.x) + 1;
  const int minZ = msvc8::FloorToIntX87(target->mAABox.Min.z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = msvc8::CeilToIntX87(target->mAABox.Max.z) + 1;
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = gpg::pInf;
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    for (int x = minX; x <= maxX; ++x) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      outerProbe.Center[0] = candidateWorldPos.x;
      outerProbe.Center[1] = candidateWorldPos.y;
      outerProbe.Center[2] = candidateWorldPos.z;
      if (!targetCollisionShape->CollideBox(&outerProbe, &collisionResult)) {
        continue;
      }

      innerProbe.Center[0] = candidateWorldPos.x;
      innerProbe.Center[1] = candidateWorldPos.y;
      innerProbe.Center[2] = candidateWorldPos.z;
      if (targetCollisionShape->CollideBox(&innerProbe, &collisionResult)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
}

/**
 * Address: 0x006A7770 (FUN_006A7770, ?ExecuteOccupyGround@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Applies blueprint occupy-rect lanes (or footprint fallback rect) into
 * O-grid terrain/water occupancy masks and dirties path clusters.
 */
void Unit::ExecuteOccupyGround()
{
  const SFootprint& footprint = GetFootprint();
  const RUnitBlueprint* const blueprint = GetBlueprint();
  COGrid* const ogrid = SimulationRef ? SimulationRef->mOGrid : nullptr;
  if (ogrid == nullptr) {
    return;
  }
  const EOccupancyCaps occupancyCaps = footprint.mOccupancyCaps;


  const auto& occupyRects = blueprint->Physics.OccupyRects;
  if (occupyRects.empty()) {
    const Wm3::Vec3f& unitPos = GetPosition();
    const SOCellPos origin{
      static_cast<std::int16_t>(std::lrintf(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)),
      static_cast<std::int16_t>(std::lrintf(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)),
    };
    ogrid->ExecuteOccupy(origin, footprint);
    return;
  }

  const Wm3::Vec3f& unitPos = GetPosition();
  for (const RUnitBlueprintOccupyRect& occupyRect : occupyRects) {
    gpg::Rect2i rect{};
    // 0x006A7819-0x006A78FC: min edges are `(center + pos) - half`, max edges
    // `(pos + half) + center` -- the add order differs between the two.
    rect.x0 = RoundOccupyRectEdge((occupyRect.CenterOffsetX + unitPos.x) - occupyRect.HalfSizeX);
    rect.x1 = RoundOccupyRectEdge((unitPos.x + occupyRect.HalfSizeX) + occupyRect.CenterOffsetX);
    rect.z0 = RoundOccupyRectEdge((unitPos.z + occupyRect.CenterOffsetZ) - occupyRect.HalfSizeZ);
    rect.z1 = RoundOccupyRectEdge((unitPos.z + occupyRect.HalfSizeZ) + occupyRect.CenterOffsetZ);
    ogrid->ExecuteOccupy(occupancyCaps, rect);
  }
}

/**
 * Address: 0x006A7AB0 (FUN_006A7AB0, Moho::Unit::ReleaseOccupyGround)
 *
 * What it does:
 * Clears the occupied-ground lane previously applied by `ExecuteOccupyGround`
 * and releases the matching footprint rectangle from the sim O-grid.
 */
void Unit::ReleaseOccupyGround()
{
  if (!FootprintDown) {
    return;
  }

  // 0x006A7AC9-0x006A7AF7: the blueprint's main footprint (`bp+0xD8`), not
  // `GetFootprint()` -- the alternate footprint is never consulted here.
  const SFootprint& footprint = GetBlueprint()->mFootprint;
  const Wm3::Vec3f& unitPos = GetPosition();
  const SOCellPos origin{
    static_cast<std::int16_t>(std::lrintf(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)),
    static_cast<std::int16_t>(std::lrintf(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)),
  };

  if (SimulationRef != nullptr && SimulationRef->mOGrid != nullptr) {
    SimulationRef->mOGrid->ReleaseOccupy(origin, footprint);
  }

  FootprintDown = false;
}

/**
 * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
 */
void Unit::ReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  FreeOgridRect();

  ReservedOgridRectMinX = ogridRect.x0;
  ReservedOgridRectMinZ = ogridRect.z0;
  ReservedOgridRectMaxX = ogridRect.x1;
  ReservedOgridRectMaxZ = ogridRect.z1;

  FillReservedOgridRect(*this, true);
}

/**
 * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
 */
void Unit::FreeOgridRect()
{
  // 0x006AB7C9: `je` past both the vacate and the zeroing when the reserved
  // rect quantises to the zero collision rect -- the stored bounds are left
  // untouched in that case.
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  if (IsCollisionRectEquivalentToZero(reservedRect)) {
    return;
  }

  FillReservedOgridRect(*this, false);

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;
}

/**
 * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
 */
bool Unit::CanReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  const bool hadReservation = !IsCollisionRectEquivalentToZero(reservedRect);
  if (hadReservation) {
    FillReservedOgridRect(*this, false);
  }

  bool canReserve = true;
  if (SimulationRef && SimulationRef->mOGrid) {
    canReserve = !SimulationRef->mOGrid->IsRectOccupied(ogridRect);
  }

  if (hadReservation) {
    FillReservedOgridRect(*this, true);
  }

  return canReserve;
}

// 0x006A4990
UnitAttributes& Unit::GetAttributes()
{
  return mUnitVarDat.mAttributes;
}

// 0x006A4980
UnitAttributes const& Unit::GetAttributes() const
{
  return mUnitVarDat.mAttributes;
}

// 0x006A4B90
StatItem* Unit::GetStat(gpg::StrArg name, const std::string&)
{
  return moho::ResolveStatString(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B70
StatItem* Unit::GetStat(gpg::StrArg name, const float&)
{
  return moho::ResolveStatFloat(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B50
StatItem* Unit::GetStat(gpg::StrArg name, const int&)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 1);
}

// 0x006A4B30
StatItem* Unit::GetStat(gpg::StrArg name)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 0);
}

/**
 * Address: 0x006A73A0 (FUN_006A73A0)
 *
 * What it does:
 * Stores the auto-mode flag and dispatches the matching script callback.
 */
void Unit::SetAutoMode(const bool enabled)
{
  mUnitVarDat.mAutoMode = enabled;
  CallbackStr(enabled ? "OnAutoModeOn" : "OnAutoModeOff");
}

/**
 * Address: 0x006A73E0 (FUN_006A73E0)
 *
 * What it does:
 * Stores the auto-surface-mode flag.
 */
void Unit::SetAutoSurfaceMode(const bool enabled)
{
  mUnitVarDat.mAutoSurfaceMode = enabled;
}

/**
 * Address: 0x006A4A30 (FUN_006A4A30)
 *
 * What it does:
 * Returns the current auto-mode flag.
 */
bool Unit::IsAutoMode() const
{
  return mUnitVarDat.mAutoMode;
}

/**
 * Address: 0x006A4A40 (FUN_006A4A40)
 *
 * What it does:
 * Returns the current auto-surface-mode flag.
 */
bool Unit::IsAutoSurfaceMode() const
{
  return mUnitVarDat.mAutoSurfaceMode;
}

/**
 * Address: 0x006A4A50 (FUN_006A4A50)
 *
 * What it does:
 * Copies a caller-provided name into the unit custom-name lane.
 */
void Unit::SetCustomName(const std::string name)
{
  mUnitVarDat.mCustomName = name.c_str();
}

/**
 * Address: 0x006A4AB0 (FUN_006A4AB0)
 *
 * What it does:
 * Copies and returns the current custom-name lane.
 */
std::string Unit::GetCustomName() const
{
  return std::string(mUnitVarDat.mCustomName.c_str(), mUnitVarDat.mCustomName.size());
}

/**
 * Address: 0x0062D460 (FUN_0062D460, Moho::Unit::CollectAllOverlapping)
 *
 * What it does:
 * Gathers nearby non-mobile same-army same-layer structures and appends
 * those whose skirt rectangles overlap `unit`.
 */
EntitySetTemplate<Unit>* Unit::CollectAllOverlapping(EntitySetTemplate<Unit>* const outSet, Unit* const unit)
{
  if (outSet == nullptr) {
    return nullptr;
  }

  outSet->ListResetLinks();
  outSet->mVec.RebindInlineNoFree();

  if (unit == nullptr || unit->SimulationRef == nullptr || unit->SimulationRef->mOGrid == nullptr) {
    return outSet;
  }

  // 0x0062D4C2-0x0062D531: sphere {unit->GetPosition(), 20.0f} (radius at
  // 0x00DFF25C), unit mask 0x100, through COGrid::ForAllEntitiesIterator
  // (0x00721FB0) into a fastvector_n<CollisionResult, 10>. The iterator owns
  // the acceptance test (inner-box containment for radius > 3, otherwise the
  // collision primitive's sphere test; no primitive -> skipped).
  const Wm3::Sphere3f querySphere{unit->GetPosition(), 20.0f};
  gpg::core::FastVectorN<CollisionResult, 10> sphereHits{};
  unit->SimulationRef->mOGrid->ForAllEntitiesIterator(sphereHits, ENTITYTYPE_Unit, querySphere);

  for (const CollisionResult& hit : sphereHits) {
    // 0x0062D561: `hit.sourceEntity->IsUnit()` -- no null check on the entity.
    Unit* const other = hit.sourceEntity->IsUnit();
    if (other == nullptr) {
      continue;
    }

    if (other->IsDead() || other->IsMobile()) {
      continue;
    }
    if (unit->ArmyRef != other->ArmyRef) {
      continue;
    }
    if (other == unit) {
      continue;
    }
    if (other->mVarDat.mLayerMask != unit->mVarDat.mLayerMask) {
      continue;
    }
    if (!unit->OverlapsWith(other)) {
      continue;
    }

    (void)outSet->Add(other);
  }

  return outSet;
}

/**
 * Address: 0x006A7E00 (FUN_006A7E00, ?LookForStructureRebuilder@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Scans same-army REBUILDER units for guard commands matching this structure
 * blueprint/position and queues one rebuild entry on the first matching
 * command per builder.
 */
void Unit::LookForStructureRebuilder()
{
  if (ArmyRef == nullptr || SimulationRef == nullptr || SimulationRef->mRules == nullptr) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return;
  }

  const EntityCategorySet* const rebuilderCategory = SimulationRef->mRules->GetEntityCategory("REBUILDER");
  if (rebuilderCategory == nullptr) {
    return;
  }

  EntitySetTemplate<Unit> rebuilderUnits{};
  (void)ArmyRef->GetUnits(&rebuilderUnits, const_cast<EntityCategorySet*>(rebuilderCategory));

  for (Entity* const entry : rebuilderUnits.mVec) {
    Unit* const rebuilder = static_cast<Unit*>(entry);
    if (rebuilder == nullptr) {
      continue;
    }

    if (rebuilder->IsDead() || rebuilder->DestroyQueued() || rebuilder->IsBeingBuilt() || rebuilder->AiBuilder == nullptr ||
        rebuilder->CommandQueue == nullptr) {
      continue;
    }

    const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot(rebuilder->CommandQueue->mCommandVec);
    for (const WeakPtr<CUnitCommand>& commandRef : commandSnapshot) {
      CUnitCommand* const command = commandRef.GetObjectPtr();
      if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Guard) {
        continue;
      }

      const RUnitBlueprint* const commandBlueprint = static_cast<const RUnitBlueprint*>(command->mConstDat.blueprint);
      if (commandBlueprint != blueprint) {
        continue;
      }

      const Wm3::Vec3f targetPosition = command->mTarget.GetTargetPosGun(false);
      const Wm3::Vec3f& myPosition = GetPosition();
      const float deltaX = targetPosition.x - myPosition.x;
      const float deltaZ = targetPosition.z - myPosition.z;
      if (std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ)) >= 0.001f) {
        continue;
      }

      const SOCellPos cellPos = GetFootprint().ToCellPos(GetPosition());
      rebuilder->AiBuilder->BuilderAddRebuildStructure(cellPos, blueprint);
      break;
    }
  }
}

/**
 * Address: 0x006A8090 (FUN_006A8090, ?Kill@Unit@Moho@@UAEXPAVEntity@2@VStrArg@gpg@@M@Z)
 *
 * What it does:
 * Applies unit death gating and teardown, notifies adjacency/transport and
 * script lanes, then updates army/platoon kill-value statistics.
 */
void Unit::Kill(Entity* const instigator, const gpg::StrArg reason, float excessDamageRatio)
{
  if (IsDead()) {
    return;
  }

  const bool scriptAllowsKill = RunScriptUnitBool("CheckCanBeKilled", this);
  if (!scriptAllowsKill && IsWithinPlayableRectOrNotCommander(*this)) {
    return;
  }

  // 0x006A81A2: `or dword ptr [esi+4A4h], 200h`. That is the HIGH state dword,
  // so bit 9 of it is state 32+9 = 41, UNITSTATE_NoCost -- what CArmyImpl's
  // unit-cap walk skips on, so a unit stops counting against the cap the moment
  // it starts dying. Read as a low-dword write it came out as state 9,
  // UNITSTATE_TransportUnloading, which every corpse then carried.
  mUnitVarDat.mUnitStates |= (1ull << static_cast<std::uint32_t>(UNITSTATE_NoCost));

  EntitySetTemplate<Unit> overlappingStructures{};
  if (!IsMobile()) {
    CollectAllOverlapping(&overlappingStructures, this);
    LookForStructureRebuilder();
  }

  if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr) {
    if (transportOwner->AiTransport != nullptr && mAttachInfo.GetAttachTargetEntity() != nullptr) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
    }
    TransportedByRef.UnlinkFromOwnerChain();
    excessDamageRatio = 10.0f;
  }

  // 0x006A82BF..0x006A82D7: the half-built test compares 0.5 against the
  // entity build fraction (`this+0xD8`), not the unit's own work progress.
  if (IsBeingBuilt() && mVarDat.mFractionComplete < 0.5f) {
    excessDamageRatio = 10.0f;
  }

  (void)RunScript("SetDead");
  Entity::Kill(nullptr, "", 0.0f);
  mNeedsKillCleanup = true;

  if (!IsMobile() && !IsBeingBuilt()) {
    for (Entity* const entry : overlappingStructures.mVec) {
      Unit* const adjacent = static_cast<Unit*>(entry);
      if (adjacent == nullptr) {
        continue;
      }

      RunScriptUnit("OnNotAdjacentTo", adjacent);
      adjacent->RunScriptUnit("OnNotAdjacentTo", this);
      adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
    }
  }

  if (AiTransport != nullptr) {
    (void)AiTransport->TransportDetachAllUnits(true);
  }

  if (CommandQueue != nullptr) {
    CommandQueue->ClearCommandQueue();
  }

  RunScriptUnitOnKilled(instigator, reason, excessDamageRatio);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  float massValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostMass : 0.0f;
  float energyValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostEnergy : 0.0f;
  if (IsBeingBuilt()) {
    massValue *= mVarDat.mFractionComplete;
    energyValue *= mVarDat.mFractionComplete;
  }

  if (ArmyRef != nullptr) {
    if (CArmyStats* const armyStats = ArmyRef->GetArmyStats(); armyStats != nullptr) {
      if (blueprint != nullptr) {
        IncrementArmyBlueprintFloatStat(armyStats, "Units_Killed", blueprint, 1.0f);
      }
      IncrementArmyIntStatByName(armyStats, "Units_Killed");
      (void)AddArmyStatFloatByName(armyStats, &massValue, "Units_MassValue_Lost");
      (void)AddArmyStatFloatByName(armyStats, &energyValue, "Units_EnergyValue_Lost");
    }

    ESquadClass squadClass = ESquadClass::Unassigned;
    if (CPlatoon* const platoon =
          ArmyRef->GetPlatoonFor(this, &squadClass);
        platoon != nullptr) {
      ++platoon->mLosses;
    }
  }

  CArmyImpl* const instigatorArmy = (instigator != nullptr) ? instigator->ArmyRef : nullptr;
  if (instigatorArmy == nullptr || ArmyRef == nullptr ||
      !ArmyRef->IsEnemy(static_cast<std::uint32_t>(instigatorArmy->mConstDat.mArmyIndex))) {
    return;
  }

  if (Unit* const instigatorUnit = instigator->IsUnit(); instigatorUnit != nullptr && instigatorUnit->ArmyRef != nullptr) {
    ESquadClass instigatorSquadClass = ESquadClass::Unassigned;
    if (CPlatoon* const instigatorPlatoon = instigatorUnit->ArmyRef->GetPlatoonFor(
          instigatorUnit,
          &instigatorSquadClass
        );
        instigatorPlatoon != nullptr) {
      ++instigatorPlatoon->mKills;
    }
  }

  CArmyStats* const enemyArmyStats = instigatorArmy->GetArmyStats();
  if (enemyArmyStats == nullptr) {
    return;
  }

  IncrementArmyIntStatByName(enemyArmyStats, "Enemies_Killed");
  if (blueprint != nullptr) {
    IncrementArmyBlueprintFloatStat(enemyArmyStats, "Enemies_Killed", blueprint, 1.0f);
  }
  (void)AddArmyStatFloatByName(enemyArmyStats, &massValue, "Enemies_MassValue_Destroyed");
  (void)AddArmyStatFloatByName(enemyArmyStats, &energyValue, "Enemies_EnergyValue_Destroyed");

  static const std::string kCommanderCategory = "COMMAND";
  if (Entity::IsInCategory(kCommanderCategory.c_str())) {
    const std::int32_t delta = 1;
    (void)enemyArmyStats->UpdateUnitStat("Enemies_Commanders_Destroyed", &delta);
  }
}

/**
 * Address: 0x006A88D0 (FUN_006A88D0, ?OnDestroy@Unit@Moho@@UAEXXZ)
 *
 * What it does:
 * Dispatches unit destruction-side adjacency/transport cleanup and then
 * forwards to the base entity destroy-dispatch path.
 */
void Unit::OnDestroy()
{
  if (AiAttacker != nullptr) {
    AiAttacker->WeaponsOnDestroy();
  }

  if (FootprintDown) {
    FreeOgridRect();
  }

  if (!IsDead()) {
    if (!IsMobile() && !IsBeingBuilt()) {
      EntitySetTemplate<Unit> adjacentUnits{};
      CollectAllOverlapping(&adjacentUnits, this);
      for (Entity* const entry : adjacentUnits.mVec) {
        Unit* const adjacent = static_cast<Unit*>(entry);
        RunScriptUnit("OnNotAdjacentTo", adjacent);
        adjacent->RunScriptUnit("OnNotAdjacentTo", this);
        adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
      }
    }

    RunScriptUnit("SetDead", this);
    mVarDat.mIsDead = 1u;

    if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr && !transportOwner->IsDead()) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
      TransportedByRef.UnlinkFromOwnerChain();
    }

    if (AiTransport != nullptr) {
      EntitySetTemplate<Unit> detachedUnits = AiTransport->TransportDetachAllUnits(false);
      (void)detachedUnits;
    }
  }

  Entity::OnDestroy();
}

/**
 * Address: 0x006A8790 (FUN_006A8790)
 *
 * What it does:
 * Releases AI sidecars and command queue ownership during kill-cleanup, then
 * clears all corresponding unit pointers.
 */
void Unit::KillCleanup()
{
  mNeedsKillCleanup = false;

  if (AiAttacker) {
    AiAttacker->WeaponsOnDestroy();
  }

  auto* commandDispatch = AiCommandDispatch;
  AiCommandDispatch = nullptr;
  delete commandDispatch;

  if (CommandQueue) {
    CommandQueue->ClearCommandQueue();
  }

  auto* attacker = AiAttacker;
  AiAttacker = nullptr;
  delete attacker;

  auto* transport = AiTransport;
  AiTransport = nullptr;
  delete transport;

  auto* navigator = AiNavigator;
  AiNavigator = nullptr;
  delete navigator;

  auto* steering = AiSteering;
  AiSteering = nullptr;
  delete steering;

  auto* builder = AiBuilder;
  AiBuilder = nullptr;
  delete builder;

  auto* siloBuild = AiSiloBuild;
  AiSiloBuild = nullptr;
  delete siloBuild;

  CUnitCommandQueue* queue = CommandQueue;
  CommandQueue = nullptr;
  delete queue;
}

/**
 * Address: 0x006ACB20 (FUN_006ACB20)
 *
 * What it does:
 * Appends this unit's sync extra-data records into `out`: one `{bone, target
 * entity id}` pair per weapon for an attacker, or a single `{-1, beacon id}`
 * pair for a transport holding a teleport beacon.
 *
 * The weapon loop used to run through `CAiAttackerImpl::TryGetWeaponExtraData`
 * and `ReadExtraDataValue` over a `WeaponEmitterEntryView` / `WeaponExtraRefSubobject`
 * pair of reach-in structs. Reading 0x006ACB9A-0x006ACBDC says what those
 * anonymous offsets are:
 *
 *     mov  ecx, [esi+0D0h]   ; weapon->mTarget.targetEntity.ownerLinkSlot
 *     test ecx,ecx / je      ;   (mTarget is at +0xCC, the weak node at +0x04)
 *     add  ecx, -4           ; WeakPtr<Entity>::DecodeOwnerObject
 *     mov  edx, [esi+0A8h]   ; weapon->mBone
 *     mov  [eax], edx        ; pair.key
 *     je   no_entity
 *     mov  ecx, [ecx+68h]    ; Entity::id_
 *   ...
 *     mov  [esp+10h], 0F0000000h   ; no_entity: the missing-id sentinel
 *
 * so `extraKey` was the weapon's bone index, `extraRef` was the raw owner-link
 * slot of its target weak node, and `extraValue` at +0x64 off that slot was the
 * target entity's id (0x04 + 0x64 == 0x68). `GetObjectPtr()` also treats the
 * bare slot value 4 as an unbound sentinel, which the binary walks into; no
 * caller can produce it and the guard only turns a fault into the null path.
 */
void Unit::GetExtraData(SExtraUnitData* out) const
{
  if (!out) {
    return;
  }

  if (AiAttacker) {
    const int count = AiAttacker->GetWeaponCount();
    for (int i = 0; i < count; ++i) {
      const UnitWeapon* const weapon = AiAttacker->GetWeapon(i);

      SExtraUnitDataPair pair{};
      pair.key = weapon->mBone;
      const Entity* const targetEntity = weapon->mTarget.targetEntity.GetObjectPtr();
      pair.value = (targetEntity != nullptr) ? static_cast<std::int32_t>(targetEntity->id_)
                                             : static_cast<std::int32_t>(ToRaw(EEntityIdSentinel::Invalid));
      out->pairs.PushBack(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      out->pairs.PushBack(pair);
    }
  }

  out->unitEntityId = id_;
}

/**
 * Address: 0x006A73F0 (FUN_006A73F0)
 *
 * What it does:
 * Applies pause/unpause when unit caps allow it, emits script callbacks on
 * state transitions, and marks sync game-data dirty.
 */
void Unit::SetPaused(const bool paused)
{
  const UnitAttributes& attributes = GetAttributes();
  const bool canToggle =
    (attributes.commandCapsMask & kCommandCapPause) != 0u || (attributes.toggleCapsMask & kToggleCapGeneric) != 0u;
  if (!canToggle) {
    return;
  }

  if (paused) {
    if (!mUnitVarDat.mIsPaused) {
      CallbackStr("OnPaused");
    }
  } else if (mUnitVarDat.mIsPaused) {
    CallbackStr("OnUnpaused");
  }

  mUnitVarDat.mIsPaused = paused;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A7450 (FUN_006A7450)
 *
 * What it does:
 * Sets repeat-queue mode, marks the dirty-sync lane, and emits
 * OnStartRepeatQueue/OnStopRepeatQueue callbacks.
 */
void Unit::SetRepeatQueue(const bool enabled)
{
  if (enabled) {
    if (!mUnitVarDat.mRepeatQueue) {
      CallbackStr("OnStartRepeatQueue");
    }
  } else if (mUnitVarDat.mRepeatQueue) {
    CallbackStr("OnStopRepeatQueue");
  }

  mUnitVarDat.mRepeatQueue = enabled;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006AAE20 (FUN_006AAE20, Moho::Unit::GetConsumptionRequest)
 *
 * What it does:
 * Returns the requested per-tick consumption pair from `mConsumptionData`.
 */
SEconValue Unit::GetConsumptionRequest() const
{
  SEconValue request{};
  request.energy = mConsumptionData->mRequested.energy;
  request.mass = mConsumptionData->mRequested.mass;
  return request;
}

/**
 * Address: 0x006AAE40 (FUN_006AAE40, Moho::Unit::UpdateResourceProduction)
 *
 * What it does:
 * Stores one economy-rate pair in the shared runtime production lane.
 */
void Unit::UpdateResourceProduction(const SEconValue& resourceProduction)
{
  mUnitVarDat.mMaintainenceCost.ENERGY = resourceProduction.energy;
  mUnitVarDat.mMaintainenceCost.MASS = resourceProduction.mass;
}

/**
 * Address: 0x006ABC70 (FUN_006ABC70, ?ResetEconValues@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Clears the unit's produced and resources-spent economy totals.
 */
Unit* Unit::ResetEconValues()
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mResourcesSpent.ENERGY = 0.0f;
  varDat.mResourcesSpent.MASS = 0.0f;
  varDat.mProduced.ENERGY = 0.0f;
  varDat.mProduced.MASS = 0.0f;
  return this;
}

/**
 * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Rebuilds unit upkeep request lanes for active/inactive economy
 * consumption and dispatches matching Lua script callbacks.
 */
void Unit::SetConsumptionActive(const bool isActive)
{
  const bool oldConsumptionIsActive = ConsumptionActive;
  ConsumptionActive = isActive;

  SEconValue newConsumption{};
  newConsumption.energy = mUnitVarDat.mAttributes.consumptionPerSecondEnergy * 0.1f;
  newConsumption.mass = mUnitVarDat.mAttributes.consumptionPerSecondMass * 0.1f;

  if (mConsumptionData == nullptr) {
    auto* const request = new CEconRequest{};
    request->mRequested = newConsumption;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        request->mNode.ListLinkBefore(&economyInfo->registrationNode);
      }
    }

    if (mConsumptionData != nullptr) {
      mConsumptionData->mNode.ListUnlink();
      delete mConsumptionData;
    }
    mConsumptionData = request;
  }

  if (!ConsumptionActive) {
    // 0x006AA9DF..0x006AAA23: the unspent grant goes back into the army's
    // production pool (`GetEconomy() + 8` = mResources), so it is banked as
    // income on the next economy tick -- not straight into mStored.
    if (mConsumptionData != nullptr && ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        economyInfo->mResources.ENERGY += mConsumptionData->mGranted.energy;
        economyInfo->mResources.MASS += mConsumptionData->mGranted.mass;
      }
    }

    newConsumption.energy = 0.0f;
    newConsumption.mass = 0.0f;
  }

  if (mConsumptionData != nullptr) {
    mConsumptionData->mRequested = newConsumption;
  }

  mUnitVarDat.mMaintainenceCost.ENERGY = newConsumption.energy;
  mUnitVarDat.mMaintainenceCost.MASS = newConsumption.mass;

  if (ConsumptionActive != oldConsumptionIsActive) {
    if (ConsumptionActive) {
      CallbackStr("OnConsumptionActive");
    } else {
      CallbackStr("OnConsumptionInActive");
    }
  }
}

/**
 * Address: 0x006AAA90 (FUN_006AAA90, ?SetProductionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Writes one production-active flag lane and dispatches matching
 * `OnProductionActive` / `OnProductionInActive` script callbacks.
 */
void Unit::SetProductionActive(const bool isActive)
{
  ProductionActive = isActive;
  (void)RunScript(isActive ? kUnitOnProductionActiveScript : kUnitOnProductionInactiveScript);
}

/**
 * Address: 0x006A9370 (FUN_006A9370, ?RenderAIDebugInfo@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Emits per-unit AI debug stat counters under `AIDebug_<UniqueName>`,
 * including platoon metadata, idle marker, and active unit-state markers.
 */
void Unit::RenderAIDebugInfo()
{
  if (!mDebugAIStates || ArmyRef == nullptr) {
    return;
  }

  ArmyRef->UpdateAIDebugPlatoonStats(this);

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const msvc8::string debugPrefix = msvc8::string("AIDebug_") + GetUniqueName();
  const msvc8::string unitStatePrefix = debugPrefix + "_UnitStates";

  const CUnitCommand* headCommand = nullptr;
  if (CommandQueue != nullptr && !CommandQueue->mCommandVec.empty()) {
    headCommand = CommandQueue->mCommandVec.begin()->GetObjectPtr();
  }

  if (headCommand == nullptr) {
    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_Idle");
  }

  for (
    std::int32_t stateValue = static_cast<std::int32_t>(UNITSTATE_Immobile);
    stateValue <= static_cast<std::int32_t>(UNITSTATE_SiloBuildingAmmo);
    ++stateValue
  ) {
    const EUnitState state = static_cast<EUnitState>(stateValue);
    if (!IsUnitState(state)) {
      continue;
    }

    const char* const stateLexical = UnitStateToDebugLexical(state);
    if (stateLexical == nullptr || stateLexical[0] == '\0') {
      continue;
    }

    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_" + stateLexical);
  }
}
namespace
{
  /**
   * Collapse one weak reference slot to the referenced entity's id, or to the
   * `0xF0000000` sentinel when the slot is empty or its target has died.
   *
   * `Unit::Sync` publishes four of these into the sync payload; the binary
   * inlines the same null-tag test and `id_` load at each one.
   */
  template <class TObject>
  [[nodiscard]] moho::EntId WeakRefEntityId(const moho::WeakPtr<TObject>& weak) noexcept
  {
    const TObject* const target = weak.GetObjectPtr();
    return target != nullptr ? target->id_ : kNoCreatorEntityId;
  }

  /**
   * A weapon's effective min/max radius: the live attribute when it has been
   * set, otherwise the blueprint default. The binary encodes "unset" as a
   * negative attribute value, and reaches the blueprint only on that path -
   * hence the member pointer rather than an eagerly-loaded fallback value.
   */
  [[nodiscard]] float ResolveWeaponRadius(
    const float attributeRadius,
    const moho::RUnitBlueprintWeapon* const blueprint,
    float moho::RUnitBlueprintWeapon::* const blueprintRadius
  ) noexcept
  {
    return attributeRadius < 0.0f ? blueprint->*blueprintRadius : attributeRadius;
  }
}



/**
 * Address: 0x006ABCC0 (FUN_006ABCC0, ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z)
 * Mangled: ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z
 * VFTable SLOT: 12 (over `Entity::Sync`)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::Sync(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Refreshes the on-demand half of `VarDat()` and chains into `Entity::Sync`.
 *
 * Everything behind `NeedSyncGameData` is republished only when some gameplay
 * path has marked the unit dirty, and the flag is cleared on the way out:
 * the four weak references become entity ids, the six silo counters are
 * re-read (a unit with no silo controller reports zero rather than keeping a
 * stale count), and the weapon-info snapshot lane is regrown and refilled.
 *
 * The weapon pass is skipped entirely for a dead or destroy-queued unit -
 * its weapons are already being torn down - which leaves the last published
 * snapshot in place for the UI to keep drawing.
 *
 * Both shared animation poses are refreshed on every sync, dirty or not,
 * because they change every frame the unit animates.
 */
void Unit::Sync(SSyncData* const syncData)
{
  RefreshSyncBlock();
  Entity::Sync(syncData);
}

void Unit::RefreshSyncBlock(
  boost::shared_ptr<CAniPose>* const releasedPose, boost::shared_ptr<CAniPose>* const releasedPriorPose
)
{
  if (NeedSyncGameData) {
    SSTIUnitVariableData& varDat = VarDat();

    varDat.mCreator = WeakRefEntityId<Unit>(CreatorRef);
    varDat.mFocusUnit = WeakRefEntityId<Entity>(FocusEntityRef);
    varDat.mGuardedUnit = WeakRefEntityId<Unit>(GuardedUnitRef);
    varDat.mTargetBlip = WeakRefEntityId<Entity>(TargetBlipEntityRef);

    varDat.mTacticalSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloMaxStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloMaxStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Nuke) : 0;

    if (!IsDead() && !DestroyQueued()) {
      const std::int32_t weaponCount = AiAttacker != nullptr ? AiAttacker->GetWeaponCount() : 0;

      gpg::fastvector_n<UnitWeaponInfo, 1>& weaponInfo = varDat.mWeaponInfo;
      if (static_cast<std::size_t>(weaponCount) > weaponInfo.size()) {
        weaponInfo.resize(static_cast<std::size_t>(weaponCount), UnitWeaponInfo{});
      }

      for (std::int32_t index = 0; index < weaponCount; ++index) {
        CAiAttackerImpl* const attacker = AiAttacker;
        if (attacker == nullptr) {
          continue;
        }

        const UnitWeapon* const weapon = attacker->GetWeapon(index);
        if (weapon == nullptr) {
          continue;
        }

        UnitWeaponInfo& snapshot = weaponInfo[static_cast<std::size_t>(index)];

        {
          EntityCategorySet category;
          snapshot.mCat1 = *weapon->GetCat1(&category);
        }
        {
          EntityCategorySet category;
          snapshot.mCat2 = *weapon->GetCat2(&category);
        }

        snapshot.mLayer = weapon->mFireTargetLayerCaps;

        const CWeaponAttributes& attributes = weapon->mAttributes;
        snapshot.mMinRadius =
          ResolveWeaponRadius(attributes.mMinRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MinRadius);
        snapshot.mMaxRadius =
          ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);

        if (weapon->mWeaponBlueprint != nullptr) {
          snapshot.mUIMinRangeVisualId = weapon->mWeaponBlueprint->UIMinRangeVisualId;
          snapshot.mUIMaxRangeVisualId = weapon->mWeaponBlueprint->UIMaxRangeVisualId;
        }

        // The blueprint's own effective radius wins when it is set; otherwise
        // the weapon falls back to whatever it resolved as its max range.
        if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->EffectiveRadius >= 0.0f) {
          snapshot.mEffectiveRadius = weapon->mWeaponBlueprint->EffectiveRadius;
        } else {
          snapshot.mEffectiveRadius =
            ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);
        }
      }
    }

    NeedSyncGameData = false;
  }

  if (!POSE_HoldClientHandles(*AniActor)) {
    if (VarDat().mSharedPose.get() != nullptr || VarDat().mPriorSharedPose.get() != nullptr) {
      boost::shared_ptr<CAniPose> none;
      boost::shared_ptr<CAniPose> nonePrior;
      if (releasedPose != nullptr) {
        releasedPose->swap(VarDat().mSharedPose);
      } else {
        VarDat().mSharedPose.swap(none);
      }
      if (releasedPriorPose != nullptr) {
        releasedPriorPose->swap(VarDat().mPriorSharedPose);
      } else {
        VarDat().mPriorSharedPose.swap(nonePrior);
      }
    }
    return;
  }
  if (releasedPose != nullptr) {
    releasedPose->swap(VarDat().mSharedPose);
  }
  VarDat().mSharedPose = AniActor->GetPoseShared();
  if (releasedPriorPose != nullptr) {
    releasedPriorPose->swap(VarDat().mPriorSharedPose);
  }
  VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();
}

/**
 * Address: 0x006AC2C0 (FUN_006AC2C0, ?CreateInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * What it does:
 * Queues one unit-create sync packet and marks this entity interface as
 * created for subsequent SyncInterface lanes.
 */
void Unit::CreateInterface(SSyncData* const syncData)
{
  if (syncData != nullptr) {
    SCreateUnitParams createParams{};
    createParams.mEntityId = id_;
    createParams.mBlueprint = BluePrint;
    createParams.mTickCreated = mTickCreated;
    createParams.mConstDat.mBuildStateTag = mConstDat.mBuildStateTag;
    createParams.mConstDat.mStatsRoot = mConstDat.mStatsRoot;
    createParams.mConstDat.mFake = mConstDat.mFake;
    (void)QueueCreateUnitParams(syncData, createParams);
  }

  mInterfaceCreated = 1u;
}

/**
 * Address: 0x006AC3A0 (FUN_006AC3A0, ?SyncInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SyncInterface(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Rebuilds the per-sim command / build-queue CmdId snapshots when their source
 * queues are marked dirty, then queues a `{ id_, mUnitVarDat }` record onto
 * `SSyncData::mUnitUpdates` (+0x158) with the recon-flag word set to 28, and
 * finally chains into the base `Entity::SyncInterface`.
 *   1. `mUnitVarDat.mDidRefresh` is cleared up front.
 *   2. If the command queue is present and dirty, the `mCommands` snapshot is
 *      reset to inline storage and rebuilt from the queue's live commands, the
 *      queue's dirty flag is cleared, and `mDidRefresh` is set.
 *   3. If the AI builder is present and its factory queue is dirty, the
 *      `mBuildQueue` snapshot is likewise rebuilt from the builder's factory
 *      command queue, the builder's dirty flag is cleared, and `mDidRefresh` is
 *      set.
 *   4. A default unit-update record is pushed, `id_` + `mUnitVarDat` are copied
 *      into it, and its recon-flag word (+0x230) is set to 28.
 */
void Unit::SyncInterface(SSyncData* const syncData)
{
  SSTIUnitVariableData& varData = VarDat();
  varData.mDidRefresh = false;

  if (CommandQueue != nullptr && CommandQueue->mNeedsRefresh) {
    varData.mCommands.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mCommands, CommandQueue->mCommandVec);
    CommandQueue->mNeedsRefresh = false;
    varData.mDidRefresh = true;
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactoryQueueDirty()) {
    varData.mBuildQueue.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mBuildQueue, AiBuilder->BuilderGetFactoryCommandQueue());
    AiBuilder->BuilderSetFactoryQueueDirty(false);
    varData.mDidRefresh = true;
  }

  // sim_ParallelSync finishes the copy on workers after the walk; otherwise the serial queue.
  SUnitVariableUpdateEntry* entry = QueueUnitVariableUpdateDeferred(syncData, id_, varData);
  if (entry == nullptr) {
    entry = QueueUnitVariableUpdate(syncData, id_, varData);
  }
  SetUnitUpdateReconFlags(entry, 28);

  Entity::SyncInterface(syncData);
}

/**
 * Address: 0x006AC530 (FUN_006AC530, ?ShowAIDebugInfo@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Resolves this unit's `AIDebug_<UniqueName>` stat path and clears it from
 * owning army stats.
 */
void Unit::ShowAIDebugInfo(const bool isEnabled)
{
  (void)isEnabled;

  if (ArmyRef == nullptr) {
    return;
  }

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const msvc8::string debugStatPath = msvc8::string("AIDebug_") + GetUniqueName();
  armyStats->Delete(debugStatPath.c_str());
}

/**
 * Address: 0x0062AF70 (FUN_0062AF70, Moho::Unit::DistanceToOccupiedRect)
 *
 * What it does:
 * Finds the first raised-platform quad covering `samplePoint` in local XZ and
 * bilinearly interpolates one additional Y offset for occupancy snap lanes.
 */
float Unit::DistanceToOccupiedRect(const Wm3::Vector3f* const samplePoint)
{
  if (samplePoint == nullptr || IsDead()) {
    return 0.0f;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return 0.0f;
  }

  const Wm3::Vector3f& unitPosition = GetPosition();
  const float sampleX = samplePoint->x;
  const float sampleZ = samplePoint->z;

  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const float x0 = platform.Vertex0X + unitPosition.x;
    const float x1 = platform.Vertex1X + unitPosition.x;
    const float x3 = platform.Vertex3X + unitPosition.x;

    const float z0 = platform.Vertex0Z + unitPosition.z;
    const float z2 = platform.Vertex2Z + unitPosition.z;
    const float z3 = platform.Vertex3Z + unitPosition.z;

    // 0x0062B0B4-0x0062B0D3: four `comiss` + `ja` rejections, so an unordered
    // lane counts as inside.
    if (!(sampleX > x3) && !(x0 > sampleX) && !(sampleZ > z3) && !(z0 > sampleZ)) {
      const float zBlend = (sampleZ - z0) / (z2 - z0);
      const float yOnLeftEdge = ((platform.Vertex2Y - platform.Vertex0Y) * zBlend) + platform.Vertex0Y;
      const float yOnRightEdge = ((platform.Vertex3Y - platform.Vertex1Y) * zBlend) + platform.Vertex1Y;
      const float xBlend = (sampleX - x0) / (x1 - x0);
      return ((yOnRightEdge - yOnLeftEdge) * xBlend) + yOnLeftEdge;
    }
  }

  return 0.0f;
}

/**
 * Address: 0x006AC600 (FUN_006AC600, ?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * When `ShowRaisedPlatforms` sim-convar is enabled, draws one debug quad per
 * raised-platform blueprint polygon in world space.
 */
void Unit::DebugShowRaisedPlatforms()
{
  if (!SimulationRef) {
    return;
  }

  CSimConVarBase* const showRaisedPlatformsDef = &moho::gSimConVar_ShowRaisedPlatforms;
  if (!showRaisedPlatformsDef) {
    return;
  }

  CSimConVarInstanceBase* const showRaisedPlatforms = SimulationRef->GetSimVar(showRaisedPlatformsDef);
  const void* const valueStorage = showRaisedPlatforms ? showRaisedPlatforms->GetValueStorage() : nullptr;
  if (!valueStorage || !*reinterpret_cast<const std::uint8_t*>(valueStorage)) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (!blueprint) {
    return;
  }

  CDebugCanvas* const debugCanvas = SimulationRef->GetDebugCanvas();
  if (!debugCanvas) {
    return;
  }

  const Wm3::Vector3f unitPos = GetPosition();
  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const Wm3::Vector3f p0{
      unitPos.x + platform.Vertex0X,
      unitPos.y + platform.Vertex0Y,
      unitPos.z + platform.Vertex0Z,
    };
    const Wm3::Vector3f p1{
      unitPos.x + platform.Vertex1X,
      unitPos.y + platform.Vertex1Y,
      unitPos.z + platform.Vertex1Z,
    };
    const Wm3::Vector3f p2{
      unitPos.x + platform.Vertex2X,
      unitPos.y + platform.Vertex2Y,
      unitPos.z + platform.Vertex2Z,
    };
    const Wm3::Vector3f p3{
      unitPos.x + platform.Vertex3X,
      unitPos.y + platform.Vertex3Y,
      unitPos.z + platform.Vertex3Z,
    };

    DrawRaisedPlatformEdge(*debugCanvas, p0, p1);
    DrawRaisedPlatformEdge(*debugCanvas, p1, p3);
    DrawRaisedPlatformEdge(*debugCanvas, p3, p2);
    DrawRaisedPlatformEdge(*debugCanvas, p2, p0);
  }
}

// 0x006A7490
void Unit::ToggleScriptBit(const int bitIndex)
{
  const std::uint32_t shift = static_cast<std::uint32_t>(static_cast<std::uint8_t>(bitIndex)) & 0x1Fu;
  const std::uint32_t mask = 1u << shift;

  const UnitAttributes& attributes = GetAttributes();
  if ((attributes.toggleCapsMask & mask) == 0u) {
    return;
  }

  // 0x006A74DC..0x006A751B: the TRANSPORTATION test is on the attach parent
  // (`mAttachInfo` target at unit+0x194), not on this unit.
  if (IsUnitState(kTransportScriptBitGuardState)) {
    if (Entity* const attachParent = mAttachInfo.GetAttachTargetEntity();
        attachParent != nullptr && attachParent->IsInCategory("TRANSPORTATION")) {
      return;
    }
  }

  if ((mUnitVarDat.mScriptbits & mask) != 0u) {
    mUnitVarDat.mScriptbits &= ~mask;
    CallbackInt("OnScriptBitClear", bitIndex);
  } else {
    mUnitVarDat.mScriptbits |= mask;
    CallbackInt("OnScriptBitSet", bitIndex);
  }

  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A97C0 (FUN_006A97C0)
 *
 * What it does:
 * Updates fire-state storage and marks the dirty-sync lane for replication.
 */
void Unit::SetFireState(const std::int32_t fireState)
{
  if (mUnitVarDat.mFireState == fireState) {
    return;
  }

  mUnitVarDat.mFireState = fireState;
  MarkNeedsSyncGameData();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitWeaponInfoTypeInfo_d3b904, moho::preregister_UnitWeaponInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_SSTIUnitVariableDataTypeInfo_d3b904, moho::preregister_SSTIUnitVariableDataTypeInfo)

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UnitLuaFuncDefBootstrap
  {
    UnitLuaFuncDefBootstrap()
    {
      (void)::moho::func_UnitGetUnitId_LuaFuncDef();
      (void)::moho::func_UnitSetCreator_LuaFuncDef();
      (void)::moho::func_UnitGetCargo_LuaFuncDef();
      (void)::moho::func_UnitAlterArmor_LuaFuncDef();
      (void)::moho::func_UnitGetArmorMult_LuaFuncDef();
      (void)::moho::func_UnitClearFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitSetFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitGetFocusUnit_LuaFuncDef();
      (void)::moho::func_UnitGetWeapon_LuaFuncDef();
      (void)::moho::func_UnitGetWeaponCount_LuaFuncDef();
      (void)::moho::func_UnitGetTargetEntity_LuaFuncDef();
      (void)::moho::func_UnitGetHealth_LuaFuncDef();
      (void)::moho::func_UnitGetAttacker_LuaFuncDef();
      (void)::moho::func_UnitEnableManipulators_LuaFuncDef();
      (void)::moho::func_UnitKillManipulator_LuaFuncDef();
      (void)::moho::func_UnitKillManipulators_LuaFuncDef();
      (void)::moho::func_UnitScaleGetBuiltEmitter_LuaFuncDef();
      (void)::moho::func_UnitSetStrategicUnderlay_LuaFuncDef();
      (void)::moho::func_GetIsPaused_LuaFuncDef();
      (void)::moho::func_GetIsAutoMode_LuaFuncDef();
      (void)::moho::func_SetFireState_LuaFuncDef();
      (void)::moho::func_ToggleFireState_LuaFuncDef();
      (void)::moho::func_GetFireState_LuaFuncDef();
      (void)::moho::func_GetIsSubmerged_LuaFuncDef();
      (void)::moho::func_GetIsAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_UnitGetGuards_LuaFuncDef();
      (void)::moho::func_UnitGetTransportFerryBeacon_LuaFuncDef();
      (void)::moho::func_UnitGetGuardedUnit_LuaFuncDef();
      (void)::moho::func_UnitHasValidTeleportDest_LuaFuncDef();
      (void)::moho::func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();
      (void)::moho::func_UnitForceAltFootprint_LuaFuncDef();
      (void)::moho::func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();
      (void)::moho::func_UnitAddUnitToStorage_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentMoveLocation_LuaFuncDef();
      (void)::moho::func_UnitGiveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetNukeSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitGiveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitSetCustomName_LuaFuncDef();
      (void)::moho::func_UnitGetCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitPrintCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitIsIdleState_LuaFuncDef();
      (void)::moho::func_UnitIsStunned_LuaFuncDef();
      (void)::moho::func_UnitIsBeingBuilt_LuaFuncDef();
      (void)::moho::func_UnitIsPaused_LuaFuncDef();
      (void)::moho::func_UnitSetPaused_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionActive_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitSetRegenRate_LuaFuncDef();
      (void)::moho::func_UnitRevertRegenRate_LuaFuncDef();
      (void)::moho::func_UnitSetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitGetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetResourceConsumed_LuaFuncDef();
      (void)::moho::func_UnitSetElevation_LuaFuncDef();
      (void)::moho::func_UnitRevertElevation_LuaFuncDef();
      (void)::moho::func_UnitSetSpeedMult_LuaFuncDef();
      (void)::moho::func_UnitSetAccMult_LuaFuncDef();
      (void)::moho::func_UnitSetTurnMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffTriggerMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffDistanceMult_LuaFuncDef();
      (void)::moho::func_UnitSetStat_LuaFuncDef();
      (void)::moho::func_UnitSetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitGetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitIsUnitState_LuaFuncDef();
      (void)::moho::func_UnitSetProductionActive_LuaFuncDef();
      (void)::moho::func_UnitSetBusy_LuaFuncDef();
      (void)::moho::func_UnitSetBlockCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitSetImmobile_LuaFuncDef();
      (void)::moho::func_UnitSetUnSelectable_LuaFuncDef();
      (void)::moho::func_UnitSetDoNotTarget_LuaFuncDef();
      (void)::moho::func_UnitStopSiloBuild_LuaFuncDef();
      (void)::moho::func_UnitSetIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitGetNumBuildOrders_LuaFuncDef();
      (void)::moho::func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();
      (void)::moho::func_UnitSetStunned_LuaFuncDef();
      (void)::moho::func_UnitSetUnitState_LuaFuncDef();
      (void)::moho::func_GetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitGetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitSetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleFireState_LuaFuncDef();
      (void)::moho::func_UnitSetFireState_LuaFuncDef();
      (void)::moho::func_UnitGetFireState_LuaFuncDef();
      (void)::moho::func_UnitSetAutoMode_LuaFuncDef();
      (void)::moho::func_UnitAddBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRemoveBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRestoreBuildRestrictions_LuaFuncDef();
      (void)::moho::func_UnitAddCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitAddToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitTestCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitTestToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitGetRallyPoint_LuaFuncDef();
      (void)::moho::func_UnitGetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitGetFuelRatio_LuaFuncDef();
      (void)::moho::func_UnitGetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitGetBlip_LuaFuncDef();
      (void)::moho::func_UnitTransportHasSpaceFor_LuaFuncDef();
      (void)::moho::func_UnitTransportHasAvailableStorage_LuaFuncDef();
      (void)::moho::func_UnitTransportDetachAllUnits_LuaFuncDef();
      (void)::moho::func_UnitShowBone_LuaFuncDef();
      (void)::moho::func_UnitHideBone_LuaFuncDef();
      (void)::moho::func_UnitSetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitSetReclaimable_LuaFuncDef();
      (void)::moho::func_UnitSetCapturable_LuaFuncDef();
      (void)::moho::func_UnitIsCapturable_LuaFuncDef();
      (void)::moho::func_UnitSetOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitIsOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitRevertCollisionShape_LuaFuncDef();
      (void)::moho::func_UnitRecoilImpulse_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentLayer_LuaFuncDef();
      (void)::moho::func_UnitCanPathTo_LuaFuncDef();
      (void)::moho::func_UnitCanPathToRect_LuaFuncDef();
      (void)::moho::func_UnitIsMobile_LuaFuncDef();
      (void)::moho::func_UnitIsMoving_LuaFuncDef();
      (void)::moho::func_UnitGetNavigator_LuaFuncDef();
      (void)::moho::func_UnitGetVelocity_LuaFuncDef();
      (void)::moho::func_UnitGetStat_LuaFuncDef();
      (void)::moho::func_UnitCanBuild_LuaFuncDef();
      (void)::moho::func_UnitSetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitSetFuelRatio_LuaFuncDef();
      (void)::moho::func_CreateUnit2_LuaFuncDef();
      (void)::moho::func_CreateUnit_LuaFuncDef();
      (void)::moho::func_CreateUnitHPR_LuaFuncDef();
    }
  };

  const UnitLuaFuncDefBootstrap gUnitLuaFuncDefBootstrap{};
} // namespace
namespace moho
{
  /**
   * `gpg::SerConstructHelper<Unit>`, vtable 0x00E2A810.
   *
   * Address: 0x00BD6B20 (FUN_00BD6B20 -- constructs the global and registers its destructor.)
   * Address: 0x00BFDA00 (FUN_00BFDA00 -- the global's destructor.)
   * Address: 0x006AE9A0 (FUN_006AE9A0 -- `Init`.)
   * Address: 0x006AD3A0 (FUN_006AD3A0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x006B1010 (FUN_006B1010 -- `Delete`.)
   */
  struct UnitConstruct : gpg::SerConstructHelper<Unit>
  {};

  /**
   * `gpg::SerSaveConstructHelper<Unit>`, vtable 0x00E2A800.
   *
   * Address: 0x00BD6AF0 (FUN_00BD6AF0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD9D0 (FUN_00BFD9D0 -- the global's destructor.)
   * Address: 0x006AE920 (FUN_006AE920 -- `Init`.)
   * Address: 0x006AD210 (FUN_006AD210 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
   */
  struct UnitSaveConstruct : gpg::SerSaveConstructHelper<Unit>
  {};

  /**
   * `gpg::SerSaveLoadHelper<Unit>`, vtable 0x00E2A820.
   *
   * Address: 0x00BD6B60 (FUN_00BD6B60 -- constructs the global and registers its destructor.)
   * Address: 0x00BFDA30 (FUN_00BFDA30 -- the global's destructor.)
   * Address: 0x006AEA20 (FUN_006AEA20 -- `Init`.)
   * Address: 0x006AD470 (FUN_006AD470 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006AD490 (FUN_006AD490 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct UnitSerializer : gpg::SerSaveLoadHelper<Unit>
  {};
}

namespace
{
  // Address: 0x010B5BB4 -- process-global `UnitConstruct` singleton.
  moho::UnitConstruct gUnitConstruct;

  // Address: 0x010B5AE8 -- process-global `UnitSaveConstruct` singleton.
  moho::UnitSaveConstruct gUnitSaveConstruct;

  // Address: 0x010B5B80 -- process-global `UnitSerializer` singleton.
  moho::UnitSerializer gUnitSerializer;
}

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTIUnitVariableData>`, vtable 0x00E188E4.
   *
   * Address: 0x00BCA6A0 (FUN_00BCA6A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF54B0 (FUN_00BF54B0 -- the global's destructor.)
   * Address: 0x0055D100 (FUN_0055D100 -- `Init`.)
   * Address: 0x0055C760 (FUN_0055C760 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055C770 (FUN_0055C770 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SSTIUnitVariableDataSerializer : gpg::SerSaveLoadHelper<SSTIUnitVariableData>
  {};
}

namespace
{
  // Address: 0x010ACB54 -- process-global `SSTIUnitVariableDataSerializer` singleton.
  moho::SSTIUnitVariableDataSerializer gSSTIUnitVariableDataSerializer;
}

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<UnitWeaponInfo>`, vtable 0x00E1879C.
   *
   * Address: 0x00BCA580 (FUN_00BCA580 -- constructs the global and registers its destructor.)
   * Address: 0x00BF5300 (FUN_00BF5300 -- the global's destructor.)
   * Address: 0x0055CA40 (FUN_0055CA40 -- `Init`.)
   * Address: 0x0055C160 (FUN_0055C160 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0055C170 (FUN_0055C170 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct UnitWeaponInfoSerializer : gpg::SerSaveLoadHelper<UnitWeaponInfo>
  {};
}

namespace
{
  // Address: 0x010ACD0C -- process-global `UnitWeaponInfoSerializer` singleton.
  moho::UnitWeaponInfoSerializer gUnitWeaponInfoSerializer;
}

