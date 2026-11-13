#include "moho/unit/core/UnitPrivate2.h"
#include "moho/collision/AxisAlignedProbe.h"

namespace moho
{
  /**
   * Address: 0x00720F70 (FUN_00720F70, Moho::COORDS_CanMoveAt)
   *
   * What it does:
   * Validates whether `moveUnit` can occupy/move through `*pos` while filtering
   * nearby collision occupants against movement/attachment/formation rules.
   */
  bool COORDS_CanMoveAt(
    SOCellPos* pos,
    COGrid* grid,
    Unit* moveUnit,
    bool disallowAttached,
    Unit* ignoreUnit
  )
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
  bool UnitIsBlockedAt(
    const Wm3::Vec3f& worldPosition,
    Unit* const unit,
    const int mode
  )
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
  float BlueprintCollisionMass(
    const RUnitBlueprint& blueprint
  ) noexcept
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
  bool CollisionImpulseAllowed(
    const Unit& pushed,
    const Unit& against
  ) noexcept
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
  bool UnitCanShoveAside(
    const Unit& mover,
    const Unit& obstacle
  ) noexcept
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
  bool UnitWontFitAt(
    const Wm3::Vec3f& worldPosition,
    const Unit* const unit
  )
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

  void ClearGuardFormation(
    Unit* const unit
  )
  {
    if (unit == nullptr) {
      return;
    }

    IFormationInstance* const guardFormation = unit->GuardFormation;
    unit->GuardFormation = nullptr;
    delete guardFormation;
  }

  void AddIntStatCounter(
    StatItem* const statItem,
    const long delta
  ) noexcept
  {
    if (!statItem) {
      return;
    }
#if FAFRE_PLATFORM_WINDOWS
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

  void IncrementArmyIntStatByName(
    CArmyStats* const armyStats,
    const char* const statPath
  )
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

  [[nodiscard]] bool IsWithinPlayableRectOrNotCommander(
    const Unit& unit
  )
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
    return !(
      static_cast<float>(playableRect.x0) > position.x || static_cast<float>(playableRect.z0) > position.z ||
      position.x > static_cast<float>(playableRect.x1) || position.z > static_cast<float>(playableRect.z1)
    );
  }

  [[nodiscard]] std::int32_t PickUniformIndexFromU32(
    const std::uint32_t randomValue,
    const std::uint32_t count
  ) noexcept
  {
    const std::uint64_t product = static_cast<std::uint64_t>(randomValue) * static_cast<std::uint64_t>(count);
    return static_cast<std::int32_t>(product >> 32u);
  }

  [[nodiscard]] bool HasFootprintFlag(
    const EFootprintFlags value,
    const EFootprintFlags flag
  ) noexcept
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
  [[nodiscard]] Wm3::Vector3f ForwardXZ(
    const Unit& unit
  ) noexcept
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
    const float gravityMagnitude =
      std::sqrt((gravity.x * gravity.x) + (gravity.y * gravity.y) + (gravity.z * gravity.z));

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

  void FillReservedOgridRect(
    Unit& unit,
    const bool occupied
  ) noexcept
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

  // 0x006A7827..0x006A784F: `addss 0.5`, stored to float, then the inlined floor.
  [[nodiscard]] std::int32_t RoundOccupyRectEdge(
    const float value
  ) noexcept
  {
    return fa::FloorToIntX87(value + 0.5f);
  }

  /**
   * Address: 0x0062EAC0 (FUN_0062EAC0, func_UnitMoreInLineToOther)
   */
  [[nodiscard]] const Unit* UnitMoreInLineToOther(
    const Unit* const a1,
    const Unit* const a2
  ) noexcept
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
    const float a2Alignment = ((a2ToA1.y * a2Forward.y) + (a2ToA1.z * a2Forward.z)) + (a2ToA1.x * a2Forward.x);
    const float a1Alignment = ((a1ToA2.z * a1Forward.z) + (a1ToA2.y * a1Forward.y)) + (a1ToA2.x * a1Forward.x);
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
moho::Unit* moho::SCR_GetUnitOptional(
  const LuaPlus::LuaObject& unitObject
)
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

LuaPlus::LuaObject CScrLuaMetatableFactory<Unit>::Create(
  LuaPlus::LuaState* const state
)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00564660 (FUN_00564660,
 * ?ARMOR_GetArmorDefinations@Moho@@YA?AV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
 *
 * What it does:
 * Loads `/lua/armordefinition.lua`, resolves `armordefinition` table rows for
 * one armor type, and returns raw `<damageType multiplier>` string lanes.
 */
fa::list<fa::string> moho::ARMOR_GetArmorDefinations(
  LuaPlus::LuaState* const state,
  const gpg::StrArg armorTypeName
)
{
  fa::list<fa::string> definitions{};

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
        definitions.push_back(fa::string(definitionText));
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
 * Address: 0x006C39F0 (FUN_006C39F0)
 *
 * What it does:
 * Rebinds this unit's creator weak-reference lane and marks game-data sync
 * dirty for replication.
 */
void moho::AssignCreatorWeakRefAndMarkSyncDirty(
  Unit* const unit,
  Unit* const creator
)
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
    const fa::vector<moho::WeakPtr<moho::CUnitCommand>>& source
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
  [[maybe_unused]] void DeserializeUnitWeaponInfoSerializerCallback(
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
  [[maybe_unused]] void SerializeUnitWeaponInfoSerializerCallback(
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
  [[maybe_unused]] void SSTIUnitVariableDataSerializerDeserialize(
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
  [[maybe_unused]] void SSTIUnitVariableDataSerializerSerialize(
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

#include "UnitReflection.inl"

#include "UnitGuard.inl"

#include "UnitBuildQueries.inl"

#include "UnitCollision.inl"

#include "UnitState.inl"

#include "UnitFormationOccupy.inl"

#include "UnitStats.inl"

#include "UnitDeath.inl"

#include "UnitEconomy.inl"

#include "UnitInterface.inl"
