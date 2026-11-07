#include "moho/ai/CAiBrainPrivate.h"

namespace moho
{
  class CUnitCommand;
}

namespace
{
  constexpr const char* kAiBrainModulePath = "/lua/aibrain.lua";
  constexpr const char* kAiBrainClassName = "AIBrain";
  constexpr const char* kAiBrainPickBestAttackVectorLoadCallbackError =
    "Error loading user-supplied callback in CAiBrain::PickBestAttackVector: %s";
  constexpr const char* kAiBrainPickBestAttackVectorRunCallbackError =
    "Error running user-supplied callback in CAiBrain::PickBestAttackVector: %s";
  constexpr std::int32_t kAiDebugGridStep = 32;
  constexpr std::int32_t kAiDebugGridLineDepth = static_cast<std::int32_t>(0xFF7FFF7Fu);
  constexpr std::int32_t kAiDebugAttackLineDepth = static_cast<std::int32_t>(0xFFFFFF00u);
  constexpr std::uint32_t kAiDebugAttackRingDepth = 0xFFFF0000u;
  constexpr std::uint32_t kAiDebugAttackRingPrecision = 6u;
  constexpr float kAiDebugAttackRingRadius = 5.0f;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = 0;

  /**
   * Records whether one grid cell holds enemy units, advancing the row's
   * next-cell cursor. `row.mOccupancyWords` holds the row's occupancy flags packed
   * one bit per 32-bit word; growing it one `int` word at a time via the
   * container's own `push_back` is the faithful modern expression of the
   * inlined bit-insert-and-grow mechanic `CAiBrain::ProcessAttackVectors`
   * (0x0057BDB0) performs once per grid column via `sub_57FB30`/`sub_443D90`
   * (the same insert-one-bit + word-array-grow shape already recovered
   * generically as `VectorBoolInsertOneBit`/`VectorBoolReserveWordCapacity`
   * in ManipulatorStartupRegistrations.cpp). `row.mOccupancyWords` is proven to be
   * the binary's per-row payload by `sub_5837F0`'s cleanup shape (the row
   * vector's `_Destroy_range`, cited on Vector.h).
   */
  void MarkGridCellEnemyPresence(SAttackVectorGridRow& row, const bool hasEnemyUnits)
  {
    const auto cellIndex = static_cast<std::uint32_t>(row.mNextColumn);
    const std::uint32_t wordIndex = cellIndex >> 5;
    if (wordIndex >= row.mOccupancyWords.size()) {
      row.mOccupancyWords.push_back(0);
    }

    if (hasEnemyUnits) {
      row.mOccupancyWords[wordIndex] |= (1 << (cellIndex & 0x1Fu));
    }

    ++row.mNextColumn;
  }

  /**
   * Reports whether grid cell `column` was previously marked as holding
   * enemy units. A column the row never grew to (past its last written
   * word) reads as empty, matching the binary's zero-filled tail-word
   * semantics.
   */
  [[nodiscard]] bool GridCellHasEnemyPresence(const SAttackVectorGridRow& row, const std::int32_t column)
  {
    if (column < 0) {
      return false;
    }

    const auto wordIndex = static_cast<std::uint32_t>(column) >> 5;
    if (wordIndex >= row.mOccupancyWords.size()) {
      return false;
    }

    return (row.mOccupancyWords[wordIndex] & (1 << (column & 0x1F))) != 0;
  }

  /**
   * `mov eax, [ecx+0x554]` at 0x0057B0D5 is `Unit::AiBuilder`, the unit's
   * builder sidecar -- the field is already declared at exactly that offset.
   * A `UnitBuilderSubsystemView` of 0x554 pad bytes plus a `void*` used to
   * stand in for it here.
   */
  [[nodiscard]] bool UnitHasBuilderSubsystem(const Unit* const unit) noexcept
  {
    return unit != nullptr && unit->AiBuilder != nullptr;
  }

  /**
   * Address: 0x0057B0C0 (FUN_0057B0C0, sub_57B0C0)
   * Mangled: (file-static; no external linkage)
   *
   * IDA signature:
   * char __userpurge sub_57B0C0@<al>(Moho::Unit *builder@<ecx>, int count@<edx>,
   *                                  Moho::RUnitBlueprint *blueprint@<edi>,
   *                                  Moho::CAiBrain *brain);
   *
   * What it does:
   * Verifies `builder` owns a builder subsystem and `blueprint` is non-null,
   * builds a single-element selected-unit set from `builder`, then issues one
   * `UNITCOMMAND_BuildFactory` command carrying `blueprint` `count` times
   * against `brain->mSim`. Returns false when the builder/blueprint gate fails.
   */
  [[nodiscard]] bool IssueBuildFactoryCommands(
    Unit* const builder, const int count, RUnitBlueprint* const blueprint, CAiBrain* const brain
  )
  {
    if (!UnitHasBuilderSubsystem(builder) || blueprint == nullptr) {
      return false;
    }

    EntitySetTemplate<Unit> selectedUnits{};
    (void)selectedUnits.Add(builder);

    for (int issueIndex = 0; issueIndex < count; ++issueIndex) {
      SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_BuildFactory);
      issueData.mBlueprint = blueprint;
      (void)IssueCommandToSelectedUnits(brain->mSim, selectedUnits, issueData, false);
    }

    return true;
  }

  void SubtractCategoryWordRange(EntityCategorySet& lhs, const EntityCategorySet& rhs)
  {
    const std::size_t lhsCount = lhs.WordCount();
    const std::size_t rhsCount = rhs.WordCount();
    if (lhsCount == 0 || rhsCount == 0) {
      return;
    }

    const std::uint32_t lhsBeginWord = lhs.mBits.mFirstWordIndex;
    const std::uint32_t rhsBeginWord = rhs.mBits.mFirstWordIndex;
    const std::uint32_t lhsEndWord = lhsBeginWord + static_cast<std::uint32_t>(lhsCount);
    const std::uint32_t rhsEndWord = rhsBeginWord + static_cast<std::uint32_t>(rhsCount);

    const std::uint32_t overlapBegin = lhsBeginWord < rhsBeginWord ? rhsBeginWord : lhsBeginWord;
    const std::uint32_t overlapEnd = lhsEndWord < rhsEndWord ? lhsEndWord : rhsEndWord;
    if (overlapBegin >= overlapEnd) {
      return;
    }

    std::uint32_t* const lhsWords = lhs.WordData();
    const std::uint32_t* const rhsWords = rhs.WordData();
    for (std::uint32_t absoluteWord = overlapBegin; absoluteWord < overlapEnd; ++absoluteWord) {
      const std::size_t lhsIndex = static_cast<std::size_t>(absoluteWord - lhsBeginWord);
      const std::size_t rhsIndex = static_cast<std::size_t>(absoluteWord - rhsBeginWord);
      lhsWords[lhsIndex] &= ~rhsWords[rhsIndex];
    }
  }
}

namespace moho
{
  /**
   * Address: 0x0062D7E0 (FUN_0062D7E0, func_CalulateWaterRatio)
   *
   * What it does:
   * Samples the map height field at an 8x8 grid step and returns the ratio
   * of sampled cells where water elevation is above sampled terrain elevation.
   */
  float CalculateMapWaterRatio(const moho::STIMap& map)
  {
    const moho::CHeightField* const heightField = map.mHeightField.get();
    const int mapWidth = heightField->width;
    const int mapHeight = heightField->height;

    int widthBucketCount = static_cast<int>((static_cast<std::uint32_t>(mapWidth - 1) >> 3) - 1u);
    int heightBucketCount = static_cast<int>((static_cast<std::uint32_t>(mapHeight - 1) >> 3) - 1u);

    const float waterElevation = (map.mWaterEnabled != 0u) ? map.mWaterElevation : -10000.0f;
    constexpr float kHeightToWorldScale = 0.0078125f;
    constexpr float kSampleUnit = 1.0f;

    auto ClampX = [mapWidth](const int x) noexcept -> int {
      int clamped = (x < (mapWidth - 1)) ? x : (mapWidth - 1);
      if (clamped < 0) {
        clamped = 0;
      }
      return clamped;
    };

    auto ClampZ = [mapHeight](const int z) noexcept -> int {
      int clamped = (z < (mapHeight - 1)) ? z : (mapHeight - 1);
      if (clamped < 0) {
        clamped = 0;
      }
      return clamped;
    };

    auto SampleElevation = [&](const int x, const int z) noexcept -> float {
      const int sx = ClampX(x);
      const int sz = ClampZ(z);
      const std::uint16_t heightValue = heightField->data[sx + (sz * mapWidth)];
      return static_cast<float>(heightValue) * kHeightToWorldScale;
    };

    float underwaterSampleCount = 0.0f;
    float totalSampleCount = 0.0f;

    if (widthBucketCount > 1) {
      int sampleX = 8;
      int xLoopCount = widthBucketCount - 1;
      while (xLoopCount != 0) {
        int zBlockBase = 1;
        if ((heightBucketCount - 1) >= 4) {
          int zBlockLoopCount = static_cast<int>((static_cast<std::uint32_t>(heightBucketCount - 5) >> 2) + 1u);
          zBlockBase = (zBlockLoopCount * 4) + 1;

          int sampleZ = 24;
          while (zBlockLoopCount != 0) {
            if (waterElevation > SampleElevation(sampleX, sampleZ - 16)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ - 8)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ + 8)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            sampleZ += 32;
            --zBlockLoopCount;
          }
        }

        if (zBlockBase < heightBucketCount) {
          int sampleZ = zBlockBase * 8;
          int zTailCount = heightBucketCount - zBlockBase;
          while (zTailCount != 0) {
            if (waterElevation > SampleElevation(sampleX, sampleZ)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;
            sampleZ += 8;
            --zTailCount;
          }
        }

        sampleX += 8;
        --xLoopCount;
      }
    }

    return underwaterSampleCount / totalSampleCount;
  }
}

namespace
{
  /**
   * Address: 0x00581910 (FUN_00581910, func_CreateCAiBrainLuaObject)
   *
   * What it does:
   * Returns one cached `CAiBrain` metatable object from
   * `CScrLuaMetatableFactory<CAiBrain>`.
   */
  [[nodiscard]] LuaPlus::LuaObject CreateCAiBrainLuaObject(LuaPlus::LuaState* const state)
  {
    return CScrLuaMetatableFactory<CAiBrain>::Instance().Get(state);
  }

  /**
   * Address: 0x0057A350 (FUN_0057A350, func_LoadAiBrain)
   *
   * What it does:
   * Imports `/lua/aibrain.lua` and returns the `AIBrain` class table when
   * present; otherwise logs one warning and falls back to the native
   * `CAiBrain` metatable factory object.
   */
  [[nodiscard]] LuaPlus::LuaObject LoadAiBrainFactoryObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiBrainModulePath);
    if (moduleObj) {
      LuaPlus::LuaObject classObj = moduleObj.GetByName(kAiBrainClassName);
      if (!classObj.IsNil()) {
        return classObj;
      }
    }

    gpg::Logf("Can't find AIBrain, using CAiBrain directly");
    return CreateCAiBrainLuaObject(state);
  }

  /**
   * Address: 0x0057CAF0 (FUN_0057CAF0, sub_57CAF0) - the tail of `sub_5812C0`.
   *
   * What it does:
   * Drops one reservation out of both owner weak-link chains and then erases it
   * from the map, returning a cursor on the following element. `fa::map`
   * frees the node itself; the two intrusive lanes have to leave their owners'
   * chains first or the owner keeps a link into freed storage.
   */
  SBuildStructurePositionMap::iterator EraseBuildReservation(
    SBuildStructurePositionMap& map,
    const SBuildStructurePositionMap::iterator position
  ) noexcept
  {
    UnlinkBuildReservation(position->second);
    return map.erase(position);
  }

  /**
   * Address: 0x00579F50 (FUN_00579F50)
   *
   * What it does:
   * Empties one build-structure reservation map. The binary walks the tree and
   * frees node by node with `sub_5812C0`, which unlinks both weak lanes before
   * releasing the storage; `erase(begin(), end())` (FUN_00580600, cited in
   * RbTree.h) owns the node walk itself, so only the unlink half is written
   * out here. Reached from `CAiBrain::~CAiBrain` (FUN_0057A1E0) below.
   */
  void DestroyBuildStructureMap(SBuildStructurePositionMap& map) noexcept
  {
    for (auto& entry : map) {
      UnlinkBuildReservation(entry.second);
    }
    map.erase(map.begin(), map.end());
  }

  [[nodiscard]] gpg::RType* CachedAttackVectorType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::REF_FindFirstTypeNamed(
        {"std::vector<Moho::SPointVector>",
         "std::vector<Moho::SPointVector >",
         "vector<Moho::SPointVector>",
         "vector<SPointVector>"}
      );
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedBuildReserveMapType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(BuildReserveMapStorage));
      if (!type) {
        type = preregister_BuildReserveMapTypeInfo();
      }
      if (!type) {
        type = gpg::REF_FindFirstTypeNamed(
          {"std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>",
           "std::map<Wm3::IVector2<int>, Moho::SBuildReserveInfo>",
           "map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>"}
        );
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Sim));
      if (!type) {
        type = gpg::REF_FindFirstTypeNamed({"Moho::Sim", "Sim"});
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedTaskStageType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(CTaskStage));
      if (!type) {
        type = gpg::REF_FindFirstTypeNamed({"Moho::CTaskStage", "CTaskStage"});
      }
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakePointerRef(TObject* const object, gpg::RType* const type)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = (object != nullptr) ? type : nullptr;
    return out;
  }

  void ReplaceOwnedTaskStage(CTaskStage*& field, CTaskStage* const replacement)
  {
    CTaskStage* const previous = field;
    field = replacement;
    delete previous;
  }

  struct CAiBrainStartupBootstrap
  {
    CAiBrainStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CAiBrain_Index();
    }
  };

  [[maybe_unused]] CAiBrainStartupBootstrap gCAiBrainStartupBootstrap;
}

namespace moho
{
  /**
   * Address: 0x006934E0 (FUN_006934E0, func_FillLuaTableWithEntities)
   *
   * What it does:
   * Initializes `outTable` as a Lua array sized to `entities` and fills slots
   * `1..N` with each entity's script object lane in storage order.
   */
  LuaPlus::LuaObject* FillLuaTableWithEntities(
    const EntitySetTemplate<Unit>& entities,
    LuaPlus::LuaObject* const outTable,
    LuaPlus::LuaState* const state
  )
  {
    outTable->AssignNewTable(state, static_cast<std::int32_t>(entities.mVec.Size()), 0);

    std::int32_t tableIndex = 1;
    for (Entity* const* entitySlot = entities.mVec.begin(); entitySlot != entities.mVec.end(); ++entitySlot) {
      outTable->Insert(tableIndex, (*entitySlot)->mLuaObj);
      ++tableIndex;
    }

    return outTable;
  }

  /**
   * Address: 0x0057B290 (FUN_0057B290, func_GetUnitsAroundPoint)
   *
   * What it does:
   * Resets one output unit-set lane, gathers nearby unit entities around
   * `position` within `dist`, filters by liveness/destroy-queue/alliance/recon
   * visibility/category membership, and appends matching units.
   *
   * Called by CPlatoon::FindClosestUnitToPos (the COMPARE_LeastDefended lane)
   * to score how well-defended each candidate is.
   */
  EntitySetTemplate<Unit>* CollectUnitsAroundPointFiltered(
    CAiBrain* const brain,
    EntitySetTemplate<Unit>* const outUnits,
    const EntityCategorySet* const categorySet,
    const Wm3::Vector3f& position,
    const float dist,
    const EAlliance alliance
  )
  {
    outUnits->ListResetLinks();
    outUnits->mVec.ResetStorageToInline();

    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();

    // 0x0057B2F4..0x0057B343: the same circular `EntitiesAroundPoint` gather
    // (radius in xmm0, ENTITYTYPE_Unit) as the counting twin 0x0057B480 --
    // not a square rect gather, so corner units outside `dist` are excluded.
    gpg::core::FastVectorN<CollisionResult, 10> gatheredEntities{};
    EntitiesAroundPoint(gatheredEntities, dist, *brain->mSim->mOGrid, ENTITYTYPE_Unit, position);

    for (const CollisionResult& hit : gatheredEntities) {
      Entity* const candidateEntity = hit.sourceEntity;
      if (candidateEntity == nullptr || candidateEntity->mVarDat.mIsDead != 0u || candidateEntity->DestroyQueuedFlag != 0u) {
        continue;
      }

      if (static_cast<int>(alliance) != kAiBrainAllianceAnySentinel) {
        const IArmy* const candidateArmy =
          (candidateEntity->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidateEntity->ArmyRef) : nullptr;
        if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
          continue;
        }
      }

      Unit* const candidateUnit = candidateEntity->IsUnit();
      if (candidateUnit == nullptr) {
        continue;
      }

      if (brain->mArmy != candidateEntity->ArmyRef && reconDb->ReconGetBlip(candidateUnit) == nullptr) {
        continue;
      }

      if (EntityCategory::HasBlueprint(candidateEntity->BluePrint, categorySet)) {
        (void)outUnits->Add(candidateUnit);
      }
    }

    return outUnits;
  }

  /**
   * Address: 0x0057B480 (FUN_0057B480, func_GetNumUnitsAroundPoint)
   *
   * IDA signature:
   * int __stdcall sub_57B480(CAiBrain* this, EntityCategory* cat, Vector3f* pos,
   *                          float dist, EAlliance ally);
   *
   * What it does:
   * Counting twin of `CollectUnitsAroundPointFiltered`: gathers unit entities
   * within `dist` of `position` and returns how many pass the
   * liveness / destroy-queue / alliance / recon-visibility / category filters.
   * Backs the `CAiBrain:GetNumUnitsAroundPoint()` Lua binding.
   */
  int CountUnitsAroundPointFiltered(
    CAiBrain* const brain,
    const EntityCategorySet* const categorySet,
    const Wm3::Vector3f& position,
    const float dist,
    const EAlliance alliance)
  {
    int matchCount = 0;

    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();

    gpg::core::FastVectorN<CollisionResult, 10> gatheredEntities{};
    EntitiesAroundPoint(gatheredEntities, dist, *brain->mSim->mOGrid, ENTITYTYPE_Unit, position);

    for (const CollisionResult& hit : gatheredEntities) {
      Entity* const candidateEntity = hit.sourceEntity;
      if (candidateEntity == nullptr || candidateEntity->mVarDat.mIsDead != 0u || candidateEntity->DestroyQueuedFlag != 0u) {
        continue;
      }

      if (static_cast<int>(alliance) != kAiBrainAllianceAnySentinel) {
        const IArmy* const candidateArmy =
          (candidateEntity->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidateEntity->ArmyRef) : nullptr;
        if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
          continue;
        }
      }

      Unit* const candidateUnit = candidateEntity->IsUnit();
      if (candidateUnit == nullptr) {
        continue;
      }

      if (brain->mArmy != candidateEntity->ArmyRef && reconDb->ReconGetBlip(candidateUnit) == nullptr) {
        continue;
      }

      if (EntityCategory::HasBlueprint(candidateEntity->BluePrint, categorySet)) {
        ++matchCount;
      }
    }

    return matchCount;
  }
namespace
{
    /**
     * Footprint-size multiplier (`ds:dword_DFF31C == 10.0`) that scales a
     * candidate's footprint extent into the LeastDefended threat-scan radius.
     */
    constexpr float kLeastDefendedFootprintRadiusScale = 10.0f;

    /**
     * Nearby-unit scan radius (`ds:flt_E4F92C == 32.0`) used by the
     * HighestValue / count comparison lanes of `PickBestAttackVector`.
     */
    constexpr float kLeastDefendedScanRadius = 32.0f;

    /**
     * Initial "no candidate scored yet" sentinel (`ds:flt_E4F6E8 == -1.0`) for
     * the running best score in both candidate-ranking functions.
     */
    constexpr float kNoBestScoreSentinel = -1.0f;

    /**
     * Sum of a unit's build-cost mass and energy (blueprint `Economy`
     * `BuildCostMass + BuildCostEnergy`). Mirrors the binary's `[bp+0x4EC] +
     * [bp+0x4E8]` value read used to rank candidates by economic worth.
     */
    [[nodiscard]] float UnitBuildValue(const RUnitBlueprint* const blueprint) noexcept
    {
      if (blueprint == nullptr) {
        return 0.0f;
      }
      return blueprint->Economy.BuildCostMass + blueprint->Economy.BuildCostEnergy;
    }

    /**
     * Squared XYZ distance between two positions, summed z-first as
     * `(dz*dz + dy*dy) + dx*dx` -- the order of the Closest/Furthest lanes
     * (0x0057B81A..0x0057B839, 0x0057C53D..0x0057C562, 0x0057C586..0x0057C5BF).
     */
    [[nodiscard]] float DistanceSquared(const Wm3::Vector3f& a, const Wm3::Vector3f& b) noexcept
    {
      const float dx = a.x - b.x;
      const float dy = a.y - b.y;
      const float dz = a.z - b.z;
      return ((dz * dz) + (dy * dy)) + (dx * dx);
    }

    /**
     * Squared XYZ distance summed x-first as `(dx*dx + dy*dy) + dz*dz` -- the
     * order of the HighestValue tie-break (0x0057C776..0x0057C7EE).
     */
    [[nodiscard]] float DistanceSquaredXFirst(const Wm3::Vector3f& a, const Wm3::Vector3f& b) noexcept
    {
      const float dx = a.x - b.x;
      const float dy = a.y - b.y;
      const float dz = a.z - b.z;
      return ((dx * dx) + (dy * dy)) + (dz * dz);
    }
}


  /**
   * Address: 0x0057B620 (FUN_0057B620, sub_57B620)
   *
   * IDA signature:
   * Value* __stdcall sub_57B620(CAiBrain* brain, ECompareType compareType,
   *     EAlliance alliance, EntityCategory* category, Wm3::Vector3f* refPos);
   *
   * What it does:
   * Gathers candidate entities and returns the single best-scored one relative
   * to `referencePosition`, ranked by `compareType`. One id-sorted candidate
   * set is scored: when `alliance == ALLIANCE_Ally` it starts as
   * `mArmy->GetUnits(category)`, then every live recon-blip creator is added
   * into the same set (0x0057B70E..0x0057B74D).
   *
   * Each scored candidate must be allied per `IArmy::GetAllianceWith` and must
   * NOT be a member of `category` (the binary's category test is an exclusion
   * filter, the inverse of `HasBlueprint`). Scoring:
   *   COMPARE_Closest / COMPARE_Furthest : nearest / farthest to referencePosition.
   *   COMPARE_HighestValue               : highest build-cost value.
   *   COMPARE_LeastDefended              : lowest summed build value of armed
   *                                        units within footprint*10 of it.
   * Returns the best candidate `Entity*`, or nullptr when none qualify.
   */
  Entity* CollectAttackCandidateEntities(
    CAiBrain* const brain,
    const ECompareType compareType,
    const EAlliance alliance,
    const EntityCategorySet* const category,
    const Wm3::Vector3f& referencePosition)
  {
    // The one candidate set this function scores (`[esp+0x24]`).
    EntitySetTemplate<Unit> allyCandidates{};

    if (alliance == ALLIANCE_Ally) {
      EntitySetTemplate<Unit> armyUnits{};
      brain->mArmy->GetUnits(&armyUnits, const_cast<EntityCategorySet*>(category));
      allyCandidates.mVec.AddAll(&armyUnits.mVec);
    }

    // 0x0057B70E..0x0057B74D: live recon-blip creators are `Add`ed (0x0057DDD0,
    // id-sorted, de-duplicated) into the SAME set that is scored below.
    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();
    for (ReconBlip* const blip : reconDb->ReconGetBlips()) {
      Unit* const creator = blip ? blip->GetCreator() : nullptr;
      if (creator != nullptr && !creator->IsDead()) {
        (void)allyCandidates.Add(creator);
      }
    }

    Entity* bestCandidate = nullptr;
    float bestScore = kNoBestScoreSentinel;

    for (Entity* const candidate : allyCandidates.mVec) {
      if (candidate == nullptr) {
        continue;
      }

      const IArmy* const candidateArmy =
        (candidate->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidate->ArmyRef) : nullptr;
      if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
        continue;
      }

      Unit* const candidateUnit = candidate->IsUnit();
      const RUnitBlueprint* const candidateBlueprint =
        (candidateUnit != nullptr) ? candidateUnit->GetBlueprint() : nullptr;

      // Exclusion filter: the binary keeps candidates that are NOT in `category`
      // (or whose category bit falls outside the set's word range).
      if (EntityCategory::HasBlueprint(candidate->BluePrint, category)) {
        continue;
      }

      switch (compareType) {
        case COMPARE_Closest: {
          const float score = DistanceSquared(candidate->GetPositionWm3(), referencePosition);
          if (score < bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_Furthest: {
          const float score = DistanceSquared(candidate->GetPositionWm3(), referencePosition);
          if (score > bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_HighestValue: {
          const float score = UnitBuildValue(candidateBlueprint);
          if (score > bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_LeastDefended: {
          float nearbyDefenseValue = 0.0f;

          const SFootprint& footprint = candidate->GetFootprint();
          const std::uint8_t footprintExtent = std::max(footprint.mSizeX, footprint.mSizeZ);
          const float scanRadius = static_cast<float>(footprintExtent) * kLeastDefendedFootprintRadiusScale;
          const Wm3::Vector3f& candidatePos = candidate->GetPositionWm3();

          // The binary re-derives the scoring brain from the candidate's own
          // army (`[candidate+0x154]` -> army vtable slot GetArmyBrain), so the
          // surrounding-defense scan is run from that army's perspective.
          CAiBrain* const candidateBrain =
            (candidate->ArmyRef != nullptr) ? candidate->ArmyRef->GetArmyBrain() : nullptr;

          EntitySetTemplate<Unit> nearbyDefenders{};
          CollectUnitsAroundPointFiltered(
            candidateBrain, &nearbyDefenders, category, candidatePos, scanRadius, ALLIANCE_Ally
          );

          for (Entity* const defenderEntity : nearbyDefenders.mVec) {
            Unit* const defenderUnit = defenderEntity ? defenderEntity->IsUnit() : nullptr;
            const RUnitBlueprint* const defenderBlueprint =
              (defenderUnit != nullptr) ? defenderUnit->GetBlueprint() : nullptr;
            if (defenderBlueprint != nullptr && !defenderBlueprint->Weapons.WeaponBlueprints.empty()) {
              nearbyDefenseValue += UnitBuildValue(defenderBlueprint);
            }
          }

          if (bestScore > nearbyDefenseValue || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = nearbyDefenseValue;
          }
          break;
        }
        default:
          break;
      }
    }

    return bestCandidate;
  }

  /**
   * Address: 0x0057C290 (FUN_0057C290, Moho::CAiBrain::PickBestAttackVector)
   *
   * What it does:
   * See the header declaration. Scores this brain's debug attack vectors and
   * writes the winning vector's origin/direction into `outResult`.
   */
  SPointVector* CAiBrain::PickBestAttackVector(
    SPointVector* const outResult,
    CPlatoon* const platoon,
    const ESquadClass squadClass,
    const EAlliance alliance,
    const ECompareType compareType,
    const EntityCategorySet* const category,
    const char* const scoreScript,
    const char* const scoreFunc)
  {
    // Winning attack vector kept as an SPointVector (point=origin, vector=direction).
    const Wm3::Vector3f zeroVector = Wm3::Vector3f::Zero();
    SPointVector bestVector{zeroVector, zeroVector};
    float bestScore = kNoBestScoreSentinel;

    // Locate the squad of the requested class by linear scan over the platoon's
    // squad list (the binary inlines this rather than calling GetSquad).
    CSquad* matchingSquad = nullptr;
    for (CSquad* const squad : platoon->mSquadList) {
      if (squad != nullptr && squad->mSquadClass == squadClass) {
        matchingSquad = squad;
        break;
      }
    }

    // Early-out guards -> zero result: no current enemy, no matching squad, or
    // an empty squad unit set.
    if (mCurrentEnemy == nullptr || matchingSquad == nullptr ||
        matchingSquad->mUnits.mVec.begin() == matchingSquad->mUnits.mVec.end()) {
      outResult->point = bestVector.point;
      outResult->vector = bestVector.vector;
      return outResult;
    }

    // Optional user-supplied Lua scorer. Loading and running it are each
    // guarded (FuncInfo 0x00F004D0: two runtime_error try blocks); a failure is
    // logged and the vectors are scored as if the scorer had approved them.
    LuaPlus::LuaObject scorerFunctionObject;
    if (scoreFunc != nullptr) {
      try {
        LuaPlus::LuaState* const luaState = mSim->GetLuaState();
        LuaPlus::LuaObject scoreModule = SCR_Import(luaState, scoreScript);
        scorerFunctionObject = scoreModule[scoreFunc];
      } catch (const fa::runtime_error& error) {
        gpg::Warnf(kAiBrainPickBestAttackVectorLoadCallbackError, error.what());
      }
    }

    Wm3::Vector3f squadCenter{};
    (void)matchingSquad->GetCenter(&squadCenter);

    // Iterate this brain's attack vectors (origin + direction).
    for (const SPointVector& attackVector : mAttackVectors) {
      const Wm3::Vector3f candidatePoint{
        attackVector.point.x + attackVector.vector.x,
        attackVector.point.y + attackVector.vector.y,
        attackVector.point.z + attackVector.vector.z
      };

      if (!matchingSquad->FitsAt(candidatePoint)) {
        continue;
      }

      // When a scorer is supplied, gate on scorer(centerX, centerZ, candidateX, candidateZ).
      if (scoreFunc != nullptr) {
        try {
          LuaPlus::LuaFunction scorer(scorerFunctionObject);
          const bool approved = scorer.Call_Num4_bool(
            squadCenter.x, squadCenter.z, candidatePoint.x, candidatePoint.z
          );
          if (!approved) {
            continue;
          }
        } catch (const fa::runtime_error& error) {
          gpg::Warnf(kAiBrainPickBestAttackVectorRunCallbackError, error.what());
        }
      }

      switch (compareType) {
        case COMPARE_Closest: {
          // 0x0057C53D / 0x0057C586: squared distances summed z-first.
          float score;
          if (category->Empty()) {
            score = DistanceSquared(candidatePoint, squadCenter);
          } else {
            Entity* const bestEntity =
              CollectAttackCandidateEntities(this, COMPARE_Closest, alliance, category, squadCenter);
            score = (bestEntity != nullptr)
                      ? DistanceSquared(candidatePoint, bestEntity->GetPositionWm3())
                      : gpg::pInf;
          }
          if (bestScore > score || bestScore < 0.0f) {
            // `SPointVector::operator=` (0x0057C9F0, the compiler-generated copy).
            bestVector = attackVector;
            bestScore = score;
          }
          break;
        }
        case COMPARE_Furthest: {
          // 0x0057C60F / 0x0057C658: squared distances summed z-first.
          float score;
          if (category->Empty()) {
            score = DistanceSquared(candidatePoint, squadCenter);
          } else {
            Entity* const bestEntity =
              CollectAttackCandidateEntities(this, COMPARE_Furthest, alliance, category, squadCenter);
            score = (bestEntity != nullptr)
                      ? DistanceSquared(candidatePoint, bestEntity->GetPositionWm3())
                      : gpg::pInf;
          }
          if (score > bestScore || bestScore < 0.0f) {
            // `SPointVector::operator=` (0x0057C9F0, the compiler-generated copy).
            bestVector = attackVector;
            bestScore = score;
          }
          break;
        }
        case COMPARE_HighestValue: {
          // 0x0057C6D6..0x0057C6FC: gather around the CANDIDATE point with
          // radius 32.0 (`flt_E4F92C`), not around the squad centre.
          EntitySetTemplate<Unit> nearbyUnits{};
          CollectUnitsAroundPointFiltered(
            this, &nearbyUnits, category, candidatePoint, kLeastDefendedScanRadius, alliance
          );

          float score = 0.0f;
          for (Entity* const nearbyEntity : nearbyUnits.mVec) {
            Unit* const nearbyUnit = nearbyEntity ? nearbyEntity->IsUnit() : nullptr;
            score += UnitBuildValue(nearbyUnit != nullptr ? nearbyUnit->GetBlueprint() : nullptr);
          }

          // 0x0057C758..0x0057C7F5: enter when `score >= best` (ordered) or
          // `best < 0`; then keep unless `score == best`, in which case the
          // tie-break prefers the candidate point closer to the squad centre
          // than the kept vector's origin.
          bool keep = false;
          if (score >= bestScore || bestScore < 0.0f) {
            if (score != bestScore) {
              keep = true;
            } else {
              const float keptOriginDist = DistanceSquaredXFirst(bestVector.point, squadCenter);
              const float candidateDist = DistanceSquaredXFirst(candidatePoint, squadCenter);
              keep = keptOriginDist > candidateDist;
            }
          }
          if (keep) {
            // `SPointVector::operator=` (0x0057C9F0, the compiler-generated copy).
            bestVector = attackVector;
            bestScore = score;
          }
          break;
        }
        case COMPARE_LeastDefended: {
          // 0x0057C826..0x0057C844: gather around the CANDIDATE point, radius 32.0.
          EntitySetTemplate<Unit> nearbyUnits{};
          CollectUnitsAroundPointFiltered(
            this, &nearbyUnits, category, candidatePoint, kLeastDefendedScanRadius, alliance
          );

          const float score =
            static_cast<float>((nearbyUnits.mVec.end() - nearbyUnits.mVec.begin()));

          // 0x0057C85D..0x0057C893: take the smallest NON-ZERO count -- replace
          // when `count > 0` and (`best > count` or `best == 0`), or when `best < 0`.
          if (((bestScore > score || bestScore == 0.0f) && score > 0.0f) || bestScore < 0.0f) {
            // `SPointVector::operator=` (0x0057C9F0, the compiler-generated copy).
            bestVector = attackVector;
            bestScore = score;
          }
          break;
        }
        default:
          break;
      }
    }

    // When value/count scoring found nothing near any vector, retry once in
    // COMPARE_Closest with the same squad/alliance/category/scorer.
    if ((compareType == COMPARE_HighestValue || compareType == COMPARE_LeastDefended) && bestScore == 0.0f) {
      SPointVector retryResult{zeroVector, zeroVector};
      (void)PickBestAttackVector(
        &retryResult, platoon, squadClass, alliance, COMPARE_Closest, category, scoreScript, scoreFunc
      );
      outResult->point = retryResult.point;
      outResult->vector = retryResult.vector;
      return outResult;
    }

    outResult->point = bestVector.point;
    outResult->vector = bestVector.vector;
    return outResult;
  }
}


gpg::RType* CAiBrain::sType = nullptr;

/**
 * Address: 0x00579E40 (FUN_00579E40, default ctor)
 */
CAiBrain::CAiBrain()
  : mArmy(nullptr)
  , mCurrentEnemy(nullptr)
  , mPersonality(nullptr)
  , mCurrentPlan()
  , mAttackVectors()
  , mBuildCategoryRange()
  , mBuildStructureMap{}
  , mSim(nullptr)
  , mAiThreadStage(nullptr)
  , mAttackerThreadStage(nullptr)
  , mReservedThreadStage(nullptr)
  , mTailWord(0)
{
  mCurrentPlan.assign("", 0);
}

/**
 * Address: 0x00579F80 (FUN_00579F80, army ctor)
 */
CAiBrain::CAiBrain(CArmyImpl* const army)
  : CAiBrain()
{
  mArmy = army;
  mCurrentEnemy = nullptr;
  mSim = army ? army->GetSim() : nullptr;

  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject factory = LoadAiBrainFactoryObject(mSim->mLuaState);
    CreateLuaObject(factory, arg1, arg2, arg3);
  }

  mPersonality = new (std::nothrow) CAiPersonality(mSim);

  mAiThreadStage = new CTaskStage();
  mAttackerThreadStage = new CTaskStage();
  mReservedThreadStage = new CTaskStage();

  if (mPersonality) {
    mPersonality->ReadData();
  }
}

/**
 * Address: 0x0057A440 (FUN_0057A440, Moho::CAiBrain::Initialize)
 *
 * What it does:
 * Resolves this brain's army-plan text (or `"None"` fallback), then calls
 * `OnCreateHuman` for human armies and `OnCreateAI` for non-human armies.
 */
void CAiBrain::Initialize()
{
  LuaPlus::LuaObject armyPlanArg;
  const char* const armyPlan = (mArmy != nullptr) ? mArmy->GetArmyPlans() : nullptr;
  if (armyPlan != nullptr) {
    armyPlanArg.AssignString(mSim->mLuaState, armyPlan);
  } else {
    armyPlanArg.AssignString(mSim->mLuaState, "None");
  }

  if (mArmy != nullptr && mArmy->IsHuman()) {
    LuaCall("OnCreateHuman", &armyPlanArg);
  } else {
    LuaCall("OnCreateAI", &armyPlanArg);
  }
}

/**
 * Address: 0x00579590 (FUN_00579590, ?GetClass@CAiBrain@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiBrain::GetClass() const
{
  return gpg::CachedLookup<moho::CAiBrain>(moho::CAiBrain::sType);
}

/**
 * Address: 0x005795B0 (FUN_005795B0, ?GetDerivedObjectRef@CAiBrain@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiBrain::GetDerivedObjectRef()
{
  return gpg::MakeSelfRef(this);
}

/**
 * Address: 0x00583CB0 (FUN_00583CB0, Moho::CAiBrain::MemberDeserialize)
 *
 * What it does:
 * Loads CAiBrain runtime lanes from archive storage, replacing owned
 * personality/task-stage pointers with freshly deserialized instances.
 */
void CAiBrain::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  gpg::RType* const scriptObjectType = gpg::RTypeOf<CScriptObject>();
  GPG_ASSERT(scriptObjectType != nullptr);
  if (scriptObjectType != nullptr) {
    archive->Read(scriptObjectType, static_cast<CScriptObject*>(this), owner);
  }

  (void)archive->ReadPointer(reinterpret_cast<moho::SimArmy**>(&mArmy), &owner);
  (void)archive->ReadPointer(reinterpret_cast<moho::SimArmy**>(&mCurrentEnemy), &owner);

  CAiPersonality* loadedPersonality = nullptr;
  (void)archive->ReadPointerOwned(&loadedPersonality, &owner);
  CAiPersonality* const previousPersonality = mPersonality;
  mPersonality = loadedPersonality;
  delete previousPersonality;

  archive->ReadString(&mCurrentPlan);

  gpg::RType* const attackVectorType = CachedAttackVectorType();
  GPG_ASSERT(attackVectorType != nullptr);
  if (attackVectorType != nullptr) {
    archive->Read(attackVectorType, &mAttackVectors, owner);
  }

  gpg::RType* const buildReserveMapType = CachedBuildReserveMapType();
  GPG_ASSERT(buildReserveMapType != nullptr);
  if (buildReserveMapType != nullptr) {
    archive->Read(buildReserveMapType, &mBuildStructureMap, owner);
  }

  (void)archive->ReadPointer(&mSim, &owner);

  CTaskStage* loadedAiThreadStage = nullptr;
  (void)archive->ReadPointerOwned(&loadedAiThreadStage, &owner);
  ReplaceOwnedTaskStage(mAiThreadStage, loadedAiThreadStage);

  CTaskStage* loadedAttackerThreadStage = nullptr;
  (void)archive->ReadPointerOwned(&loadedAttackerThreadStage, &owner);
  ReplaceOwnedTaskStage(mAttackerThreadStage, loadedAttackerThreadStage);

  CTaskStage* loadedReservedThreadStage = nullptr;
  (void)archive->ReadPointerOwned(&loadedReservedThreadStage, &owner);
  ReplaceOwnedTaskStage(mReservedThreadStage, loadedReservedThreadStage);

  gpg::RType* const categorySetType = gpg::RTypeOf<moho::EntityCategorySet>();
  GPG_ASSERT(categorySetType != nullptr);
  if (categorySetType != nullptr) {
    archive->Read(categorySetType, &mBuildCategoryRange, owner);
  }
}

/**
 * Address: 0x00583ED0 (FUN_00583ED0, Moho::CAiBrain::MemberSerialize)
 *
 * What it does:
 * Saves CAiBrain runtime lanes to archive storage, preserving original
 * tracked-pointer ownership states for each pointer field.
 */
void CAiBrain::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  gpg::RType* const scriptObjectType = gpg::RTypeOf<CScriptObject>();
  GPG_ASSERT(scriptObjectType != nullptr);
  if (scriptObjectType != nullptr) {
    archive->Write(scriptObjectType, static_cast<const CScriptObject*>(this), owner);
  }

  archive->WritePointer<moho::SimArmy>(mArmy, gpg::TrackedPointerState::Unowned, owner);

  archive->WritePointer<moho::SimArmy>(mCurrentEnemy, gpg::TrackedPointerState::Unowned, owner);

  archive->WritePointer<moho::CAiPersonality>(mPersonality, gpg::TrackedPointerState::Owned, owner);

  archive->WriteString(const_cast<fa::string*>(&mCurrentPlan));

  gpg::RType* const attackVectorType = CachedAttackVectorType();
  GPG_ASSERT(attackVectorType != nullptr);
  if (attackVectorType != nullptr) {
    archive->Write(attackVectorType, &mAttackVectors, owner);
  }

  gpg::RType* const buildReserveMapType = CachedBuildReserveMapType();
  GPG_ASSERT(buildReserveMapType != nullptr);
  if (buildReserveMapType != nullptr) {
    archive->Write(buildReserveMapType, &mBuildStructureMap, owner);
  }

  gpg::RType* const simType = CachedSimType();
  GPG_ASSERT(simType != nullptr || mSim == nullptr);
  gpg::RRef simRef = MakePointerRef(mSim, simType);
  gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, owner);

  gpg::RType* const taskStageType = CachedTaskStageType();
  GPG_ASSERT(
    taskStageType != nullptr
    || (mAiThreadStage == nullptr && mAttackerThreadStage == nullptr && mReservedThreadStage == nullptr)
  );

  gpg::RRef aiThreadStageRef = MakePointerRef(mAiThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, aiThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RRef attackerThreadStageRef = MakePointerRef(mAttackerThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, attackerThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RRef reservedThreadStageRef = MakePointerRef(mReservedThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, reservedThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RType* const categorySetType = gpg::RTypeOf<moho::EntityCategorySet>();
  GPG_ASSERT(categorySetType != nullptr);
  if (categorySetType != nullptr) {
    archive->Write(categorySetType, &mBuildCategoryRange, owner);
  }
}

/**
 * Address: 0x00BCB4B0 (FUN_00BCB4B0, sub_BCB4B0)
 *
 * What it does:
 * Allocates the next Lua metatable-factory object index for the CAiBrain startup lane.
 */
int moho::register_CScrLuaMetatableFactory_CAiBrain_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = index;
  return index;
}

/**
 * Address: 0x00579F30 (FUN_00579F30, scalar deleting thunk)
 * Address: 0x0057A1E0 (FUN_0057A1E0, core destructor)
 */
CAiBrain::~CAiBrain()
{
  delete mReservedThreadStage;
  delete mAttackerThreadStage;
  delete mAiThreadStage;

  DestroyBuildStructureMap(mBuildStructureMap);

  // mCurrentPlan has no automatic heap cleanup in this legacy wrapper.
  mCurrentPlan.tidy(true, 0U);

  delete mPersonality;
  mPersonality = nullptr;
}

/**
 * Address: 0x0057A6D0 (FUN_0057A6D0, Moho::CAiBrain::CanBuildUnit)
 *
 * What it does:
 * Resolves a unit blueprint id through active sim rules and tests whether
 * `builder` can construct that blueprint under current build restrictions.
 */
bool CAiBrain::CanBuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder)
{
  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);

  const RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  return blueprint != nullptr && builder->CanBuild(blueprint);
}

/**
 * Address: 0x0057B1E0 (FUN_0057B1E0, Moho::CAiBrain::BuildUnit)
 *
 * What it does:
 * Resolves one blueprint id through `brain->mSim->mRules` and, when it maps to
 * a real blueprint, delegates to `IssueBuildFactoryCommands` (0x0057B0C0) which
 * validates the builder lane and emits `UNITCOMMAND_BuildFactory` `count` times.
 */
bool CAiBrain::BuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder, const int count)
{
  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);

  RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  if (blueprint == nullptr) {
    return false;
  }

  return IssueBuildFactoryCommands(builder, count, blueprint, brain);
}

/**
 * Address: 0x0057BDB0 (FUN_0057BDB0, Moho::CAiBrain::ProcessAttackVectors)
 *
 * IDA signature:
 * void __stdcall Moho::CAiBrain::ProcessAttackVectors(Moho::CAiBrain *a1);
 *
 * What it does:
 * Rebuilds the attack-vector debug lane by scanning the map heightfield in
 * 32-unit cells (`kAiDebugGridStep`, the same constant `DrawDebug` uses just
 * below). For each cell, `mCurrentEnemy->CountUnitsInBoundsXZ` (vtable slot
 * 0x8C, `CArmyImpl::CountUnitsInBoundsXZ`) tests whether any unit from the
 * enemy army's `mBuildCategoryRange`-filtered unit set falls inside that
 * cell's XZ bounds; the result is recorded into a per-row growable bitset
 * (`grid`, one `SAttackVectorGridRow` per row). A second pass walks every
 * cell whose bit is clear (no enemy presence) and, for each of its up-to-3x3
 * edge-clamped neighbor cells whose bit IS set, appends one
 * `SPointVector` arrow that starts at the empty cell and points
 * toward the enemy-occupied neighbor -- the visual "attack vector" frontier
 * between the enemy's grid presence and the surrounding empty cells.
 */
void CAiBrain::ProcessAttackVectors()
{
  mAttackVectors.clear();

  if (mCurrentEnemy == nullptr) {
    return;
  }

  CHeightField* const heightField = mSim->mMapData->mHeightField.get();
  const std::int32_t colCount = (heightField->width - 1) / kAiDebugGridStep;
  const std::int32_t rowCount = (heightField->height - 1) / kAiDebugGridStep;

  EntitySetTemplate<Unit> enemyUnits{};
  mCurrentEnemy->GetUnits(&enemyUnits, &mBuildCategoryRange);

  if (rowCount <= 0) {
    return;
  }

  const float halfCell = static_cast<float>(kAiDebugGridStep) * 0.5f;

  // One growable per-row bitset, one bit per column: bit set means the
  // enemy has at least one unit inside that grid cell.
  fa::vector<SAttackVectorGridRow> grid;

  float cellZ = halfCell;
  for (std::int32_t row = 0; row < rowCount; ++row, cellZ += static_cast<float>(kAiDebugGridStep)) {
    grid.push_back(SAttackVectorGridRow{});
    SAttackVectorGridRow& gridRow = grid.back();

    float cellX = halfCell;
    for (std::int32_t col = 0; col < colCount; ++col, cellX += static_cast<float>(kAiDebugGridStep)) {
      Wm3::Vector3f minBounds{};
      minBounds.x = cellX - halfCell;
      minBounds.y = 0.0f;
      minBounds.z = cellZ - halfCell;

      Wm3::Vector3f maxBounds{};
      maxBounds.x = cellX + halfCell;
      maxBounds.y = 0.0f;
      maxBounds.z = cellZ + halfCell;

      const bool hasEnemyUnits = mCurrentEnemy->CountUnitsInBoundsXZ(minBounds, maxBounds, enemyUnits) > 0;
      MarkGridCellEnemyPresence(gridRow, hasEnemyUnits);
    }
  }

  for (std::int32_t row = 0; row < rowCount; ++row) {
    for (std::int32_t col = 0; col < colCount; ++col) {
      if (GridCellHasEnemyPresence(grid[row], col)) {
        continue;
      }

      const float emptyX = halfCell + static_cast<float>(kAiDebugGridStep * col);
      const float emptyZ = halfCell + static_cast<float>(kAiDebugGridStep * row);

      const std::int32_t rowLo = std::max(row - 1, 0);
      const std::int32_t rowHi = std::min(row + 1, rowCount - 1);
      const std::int32_t colLo = std::max(col - 1, 0);
      const std::int32_t colHi = std::min(col + 1, colCount - 1);

      for (std::int32_t neighborRow = rowLo; neighborRow <= rowHi; ++neighborRow) {
        const float neighborZ = halfCell + static_cast<float>(kAiDebugGridStep * neighborRow);

        for (std::int32_t neighborCol = colLo; neighborCol <= colHi; ++neighborCol) {
          if (!GridCellHasEnemyPresence(grid[neighborRow], neighborCol)) {
            continue;
          }

          const float neighborX = halfCell + static_cast<float>(kAiDebugGridStep * neighborCol);

          SPointVector debugVector{};
          debugVector.point.x = emptyX;
          debugVector.point.y = 0.0f;
          debugVector.point.z = emptyZ;
          debugVector.vector.x = neighborX - emptyX;
          debugVector.vector.y = 0.0f;
          debugVector.vector.z = neighborZ - emptyZ;

          mAttackVectors.push_back(debugVector);
        }
      }
    }
  }
}

/**
 * Address: 0x0057BAA0 (FUN_0057BAA0, Moho::CAiBrain::DrawDebug)
 *
 * What it does:
 * Draws terrain debug grid lines and attack-vector markers to the active
 * simulation debug canvas.
 */
CAiBrain* CAiBrain::DrawDebug(CAiBrain* const brain)
{
  CDebugCanvas* const debugCanvas = brain->mSim->GetDebugCanvas();
  CHeightField* const heightField = brain->mSim->mMapData->mHeightField.get();

  const std::int32_t maxX = heightField->width - 1;
  const std::int32_t maxZ = heightField->height - 1;

  std::int32_t zLineCount = maxX / kAiDebugGridStep;
  std::int32_t xLineCount = maxZ / kAiDebugGridStep;

  if (zLineCount > 0) {
    const float maxXf = static_cast<float>(maxX);
    std::int32_t z = 0;
    do {
      SDebugLine line{};
      line.p0.x = 0.0f;
      line.p0.y = 0.0f;
      line.p0.z = static_cast<float>(z);
      line.p1.x = maxXf;
      line.p1.y = 0.0f;
      line.p1.z = static_cast<float>(z);
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      z += kAiDebugGridStep;
      --zLineCount;
    } while (zLineCount != 0);

    xLineCount = maxZ / kAiDebugGridStep;
  }

  if (xLineCount > 0) {
    const float maxZf = static_cast<float>(maxZ);
    std::int32_t x = 0;
    do {
      SDebugLine line{};
      line.p0.x = static_cast<float>(x);
      line.p0.y = 0.0f;
      line.p0.z = 0.0f;
      line.p1.x = static_cast<float>(x);
      line.p1.y = 0.0f;
      line.p1.z = maxZf;
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      x += kAiDebugGridStep;
      --xLineCount;
    } while (xLineCount != 0);
  }

  const Wm3::Vector3f upAxis{0.0f, 1.0f, 0.0f};
  for (const SPointVector& attackVector : brain->mAttackVectors) {
    debugCanvas->AddWireCircle(
      upAxis,
      attackVector.point,
      kAiDebugAttackRingRadius,
      kAiDebugAttackRingDepth,
      kAiDebugAttackRingPrecision
    );

    SDebugLine line{};
    line.p0 = attackVector.point;
    line.p1.x = attackVector.point.x + attackVector.vector.x;
    line.p1.y = attackVector.point.y + attackVector.vector.y;
    line.p1.z = attackVector.point.z + attackVector.vector.z;
    line.depth0 = kAiDebugAttackLineDepth;
    line.depth1 = kAiDebugAttackLineDepth;
    debugCanvas->DebugDrawLine(line);
  }

  return brain;
}

/**
 * Address: 0x0057AEC0 (FUN_0057AEC0, Moho::CAiBrain::GetAvailableFactories)
 *
 * What it does:
 * Builds one `(FACTORY - MOBILE)` category set, then appends live non-busy
 * factory builders into `outSet`, with optional XZ distance filtering.
 */
EntitySetTemplate<Unit>* CAiBrain::GetAvailableFactories(
  EntitySetTemplate<Unit>* const outSet,
  const Wm3::Vector3f* const referencePosition,
  const float maxDistance
)
{
  const EntityCategorySet* const mobileCategory = mSim->mRules->GetEntityCategory("MOBILE");
  const EntityCategorySet* const factoryCategory = mSim->mRules->GetEntityCategory("FACTORY");

  EntityCategorySet candidateCategory{};
  if (factoryCategory != nullptr) {
    candidateCategory = *factoryCategory;
    if (mobileCategory != nullptr) {
      SubtractCategoryWordRange(candidateCategory, *mobileCategory);
    }
  } else if (mobileCategory != nullptr) {
    candidateCategory.ResetToEmpty(mobileCategory->mUniverse);
  }

  EntitySetTemplate<Unit> foundUnits{};
  mArmy->GetUnits(&foundUnits, &candidateCategory);

  for (Entity* const* unitIt = foundUnits.mVec.begin(); unitIt != foundUnits.mVec.end(); ++unitIt) {
    Unit* const unit = static_cast<Unit*>(*unitIt);
    if (unit == nullptr || unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }

    IAiBuilder* const builder = unit->AiBuilder;
    if (builder == nullptr || !builder->BuilderIsFactory()) {
      continue;
    }

    if (unit->IsBeingBuilt() || unit->IsBusy()) {
      continue;
    }

    if (maxDistance > 0.0f) {
      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      const float deltaX = referencePosition->x - unitPosition.x;
      const float deltaZ = referencePosition->z - unitPosition.z;
      const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      if (planarDistance > maxDistance) {
        continue;
      }
    }

    (void)outSet->Add(unit);
  }

  return outSet;
}

/**
 * Address: 0x0057AC30 (FUN_0057AC30, Moho::FindAvailableFactory)
 *
 * IDA signature:
 * Moho::Unit *__fastcall Moho::FindAvailableFactory(
 *   gpg::fastvector_Unit *candidateList,
 *   const char *blueprintId,
 *   Moho::CAiBrain *brain);
 *
 * What it does:
 * Returns the first builder unit (from a caller-supplied candidate list or,
 * if that list is empty, every non-mobile `FACTORY` owned by the brain's
 * army) that is live, idle, fully built, and capable of building the unit
 * blueprint identified by `blueprintId`. Returns null when the blueprint
 * cannot be resolved or no matching builder exists.
 *
 * The candidate list is copied once on entry (0x0057E550 is that copy
 * constructor: the caller's vector in `ecx`, the local in the stack slot),
 * because an empty list is refilled from the army below and the caller's
 * must not grow.
 */
moho::Unit* moho::FindAvailableFactory(
  const fa::vector<Unit*>& candidateList, const char* const blueprintId, CAiBrain* const brain
)
{
  fa::vector<Unit*> candidates(candidateList);

  // Resolve target blueprint once (by normalized filename).
  RResId blueprintResId{};
  (void)gpg::STR_InitFilename(&blueprintResId.name, blueprintId);

  RRuleGameRules* const rules = brain->mSim->mRules;
  const RUnitBlueprint* const targetBlueprint = rules->GetUnitBlueprint(blueprintResId);
  if (targetBlueprint == nullptr) {
    if (blueprintId != nullptr) {
      gpg::Warnf("Passed in a bad unit blueprint name (%s) to FindAvailableFactory!", blueprintId);
    }
    return nullptr;
  }

  // If caller didn't pre-populate `candidateList`, harvest all static
  // factories owned by this brain's army into the local std::vector copy.
  if (candidates.empty()) {
    const EntityCategorySet* const mobileCategory = rules->GetEntityCategory("MOBILE");
    const EntityCategorySet* const factoryCategory = rules->GetEntityCategory("FACTORY");

    EntityCategorySet staticFactoryCategory{};
    if (factoryCategory != nullptr) {
      staticFactoryCategory = *factoryCategory;
      if (mobileCategory != nullptr) {
        SubtractCategoryWordRange(staticFactoryCategory, *mobileCategory);
      }
    }

    EntitySetTemplate<Unit> foundFactories{};
    brain->mArmy->GetUnits(&foundFactories, &staticFactoryCategory);

    for (Entity* const* slot = foundFactories.mVec.begin(); slot != foundFactories.mVec.end(); ++slot) {
      Unit* const unit = static_cast<Unit*>(*slot);
      if (unit != nullptr) {
        candidates.push_back(unit);
      }
    }
  }

  // Linear walk for the first builder that passes every buildability gate.
  for (Unit* const candidate : candidates) {
    if (candidate == nullptr) {
      continue;
    }
    if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()) {
      continue;
    }
    if (candidate->IsBusy()) {
      continue;
    }
    if (!candidate->CanBuild(targetBlueprint)) {
      continue;
    }
    return candidate;
  }
  return nullptr;
}

/**
 * Address: 0x0057CBB0 (FUN_0057CBB0, Moho::CAiBrain::CanBuildStructureAt)
 *
 * IDA signature:
 * bool __thiscall CAiBrain::CanBuildStructureAt(CAiBrain* this,
 *     const Wm3::Vector3f& pos, RUnitBlueprint* structureBp, EAlliance alliance,
 *     int cellX, int cellZ);
 *
 * What it does:
 * Full "can this structure be placed here?" test, in three stages that preserve
 * the binary's control flow and short-circuit ordering exactly:
 *
 *   Stage 1 - grid placement check via `func_LocationIsFree`. When the site is
 *     free, stage 2A is skipped and the common stages 2B/3 run.
 *   Stage 2A (only when Stage 1 failed) - rescue path. A `ALLIANCE_None`
 *     request or a null blueprint fails outright. Otherwise the candidate skirt
 *     is scanned for nearby structures of the opposite-and-neutral alliance
 *     lanes; the placement is only rescued when the relevant structure sets are
 *     empty. On success the code FALLS THROUGH into Stage 2B (it is not an
 *     if/else against the free path).
 *   Stage 2B (common) - reject the site when the requested skirt overlaps any
 *     nearby live, non-mobile enemy unit.
 *   Stage 3 (common, only when the running result is still true) - walk this
 *     brain's outstanding build reservations. A reservation whose builder or
 *     command lane is dead is erased in place; a live reservation whose reserved
 *     structure skirt overlaps the requested skirt rejects the placement.
 */
bool moho::CAiBrain::CanBuildStructureAt(
  const Wm3::Vector3f& pos,
  RUnitBlueprint* const structureBp,
  const EAlliance alliance,
  const int cellX,
  const int cellZ
)
{
  (void)cellX;
  (void)cellZ;

  // Stage 1: grid placement check. `func_LocationIsFree` writes its resolved
  // occupation into a scratch result that is otherwise unused here.
  const SCoordsVec2 worldXZ{pos.x, pos.z};
  SOccupationResult placementResult{};
  bool locationOk = false;
  if (structureBp != nullptr) {
    locationOk = func_LocationIsFree(*structureBp, *mSim->mOGrid, worldXZ, placementResult);
  }

  // Stage 2A: rescue path when the raw grid check failed.
  if (!locationOk) {
    if (structureBp == nullptr || alliance == ALLIANCE_None) {
      return false;
    }

    const gpg::Rect2f candidateSkirt = structureBp->GetSkirtRect(worldXZ);
    const float extent = std::max(candidateSkirt.x1 - candidateSkirt.x0, candidateSkirt.z1 - candidateSkirt.z0);

    RRuleGameRules* const rules = mSim->mRules;
    const EntityCategorySet* const structureCategory = rules->GetEntityCategory("STRUCTURE");

    // Structures whose alliance is the mirror of the requested one
    // (Ally request -> gather Enemy, Enemy request -> gather Ally), plus the
    // neutral-alliance structures, both around the candidate position.
    const EAlliance mirroredAlliance = (alliance == ALLIANCE_Enemy) ? ALLIANCE_Ally : ALLIANCE_Enemy;

    EntitySetTemplate<Unit> mirroredStructures{};
    (void)CollectUnitsAroundPointFiltered(this, &mirroredStructures, structureCategory, pos, extent, mirroredAlliance);

    EntitySetTemplate<Unit> neutralStructures{};
    (void)CollectUnitsAroundPointFiltered(this, &neutralStructures, structureCategory, pos, extent, ALLIANCE_Neutral);

    if (alliance == ALLIANCE_Enemy) {
      // Requesting an enemy placement: only the mirrored (ally) set must be empty.
      locationOk = mirroredStructures.Empty();
    } else {
      // Requesting an ally placement: both the mirrored (enemy) and neutral
      // structure sets must be empty.
      locationOk = mirroredStructures.Empty() && neutralStructures.Empty();
    }

    if (!locationOk) {
      return false;
    }
    // else: fall through into the common stages below.
  }

  // Stage 2B (common): reject when the requested skirt overlaps a nearby live,
  // non-mobile enemy unit.
  if (structureBp != nullptr) {
    const gpg::Rect2f requestedSkirt = structureBp->GetSkirtRect(worldXZ);

    Wm3::AxisAlignedBox3f queryBox{};
    queryBox.Min.x = requestedSkirt.x0;
    queryBox.Max.x = requestedSkirt.x1;
    queryBox.Min.y = -1000.0f;
    queryBox.Max.y = 1000.0f;
    queryBox.Min.z = requestedSkirt.z0;
    queryBox.Max.z = requestedSkirt.z1;

    gpg::core::FastVectorN<CollisionResult, 10> nearbyUnits{};
    GatherUnmarkedUnitsInBox(*mSim->mOGrid, queryBox, nearbyUnits);

    for (const CollisionResult& hit : nearbyUnits) {
      Entity* const source = hit.sourceEntity;
      Unit* const unit = (source != nullptr) ? source->IsUnit() : nullptr;
      if (unit == nullptr) {
        continue;
      }
      if (unit->IsDead()) {
        continue;
      }
      if (unit->DestroyQueued()) {
        continue;
      }
      if (alliance != ALLIANCE_None) {
        const IArmy* const unitArmy =
          (unit->ArmyRef != nullptr) ? static_cast<const IArmy*>(unit->ArmyRef) : nullptr;
        if (mArmy->GetAllianceWith(unitArmy) == alliance) {
          continue;
        }
      }
      if (unit->IsMobile()) {
        continue;
      }
      if (requestedSkirt.Overlaps(unit->GetSkirtRect())) {
        return false;
      }
    }
  }

  if (!locationOk) {
    return false;
  }

  // Stage 3 (common): scan outstanding build reservations. Erase reservations
  // whose builder/command lane has died; reject the placement when a live
  // reservation's reserved structure skirt overlaps the requested skirt.
  // (The reserved structure blueprint is the command's build blueprint,
  // mConstDat.blueprint; the binary reaches it via the command's target lane.)
  const gpg::Rect2f requestedSkirt = (structureBp != nullptr) ? structureBp->GetSkirtRect(worldXZ) : gpg::Rect2f{};

  for (auto it = mBuildStructureMap.begin(); it != mBuildStructureMap.end();) {
    SBuildReserveInfo& reservation = it->second;
    Unit* const builder = reservation.mUnit.GetObjectPtr();
    CUnitCommand* const command = reservation.mCom.GetObjectPtr();

    // A reservation with no live command lane, no live builder, or a dead
    // builder is stale and is dropped from the map.
    if (command == nullptr || builder == nullptr || builder->IsDead()) {
      it = EraseBuildReservation(mBuildStructureMap, it);
      continue;
    }

    // Reserved structure blueprint and its target position drive the reserved
    // skirt rectangle.
    auto* const reservedBlueprint = static_cast<RUnitBlueprint*>(command->mConstDat.blueprint);
    if (reservedBlueprint == nullptr) {
      ++it;
      continue;
    }

    const Wm3::Vec3f reservedPos = command->mTarget.GetTargetPosGun(false);
    const SCoordsVec2 reservedXZ{reservedPos.x, reservedPos.z};
    const gpg::Rect2f reservedSkirt = reservedBlueprint->GetSkirtRect(reservedXZ);

    if (structureBp != nullptr && reservedSkirt.Overlaps(requestedSkirt)) {
      return false;
    }

    ++it;
  }

  return locationOk;
}

/**
 * Address: 0x0057A510 (FUN_0057A510, Moho::CAiBrain::CenterOfArmy)
 *
 * What it does:
 * Iterates the brain's structure (non-mobile) army units, sums their world
 * positions, and writes the average into `outPosition`.
 */
Wm3::Vec3f* moho::CAiBrain::CenterOfArmy(Wm3::Vec3f* const outPosition)
{
  outPosition->x = 0.0f;
  outPosition->y = 0.0f;
  outPosition->z = 0.0f;

  if (mArmy == nullptr || mSim == nullptr || mSim->mRules == nullptr) {
    return outPosition;
  }

  RRuleGameRules* const rules = mSim->mRules;
  const EntityCategorySet* const mobileCategory = rules->GetEntityCategory("MOBILE");
  const EntityCategorySet* const structureCategory = rules->GetEntityCategory("STRUCTURE");

  // 0x0057A55C..0x0057A570: STRUCTURE is Sub's `this` (lhs) and MOBILE the
  // stack operand, so the averaged set is STRUCTURE - MOBILE (the base).
  EntityCategorySet structureMinusMobile{};
  EntityCategory::Sub(&structureMinusMobile, structureCategory, mobileCategory);

  EntitySetTemplate<Unit> candidateUnits{};
  mArmy->GetUnits(&candidateUnits, &structureMinusMobile);

  std::uint32_t aliveUnitCount = 0u;
  for (Entity* const* unitIt = candidateUnits.mVec.begin(); unitIt != candidateUnits.mVec.end(); ++unitIt) {
    Unit* const candidateUnit = static_cast<Unit*>(*unitIt);
    if (candidateUnit == nullptr || candidateUnit->IsDead() || candidateUnit->DestroyQueued()) {
      continue;
    }

    const Wm3::Vec3f& unitPosition = candidateUnit->GetPosition();
    outPosition->x += unitPosition.x;
    outPosition->y += unitPosition.y;
    outPosition->z += unitPosition.z;
    ++aliveUnitCount;
  }

  if (aliveUnitCount == 0u) {
    return outPosition;
  }

  const float invCount = 1.0f / static_cast<float>(aliveUnitCount);
  outPosition->x *= invCount;
  outPosition->y *= invCount;
  outPosition->z *= invCount;
  return outPosition;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_BuildReserveMapTypeInfo_f3fc29, preregister_BuildReserveMapTypeInfo)

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
  struct CAiBrainLuaFuncDefBootstrap
  {
    CAiBrainLuaFuncDefBootstrap()
    {
      (void)::moho::func_CAiBrainIsOpponentAIRunning_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyIndex_LuaFuncDef();
      (void)::moho::func_CAiBrainGetFactionIndex_LuaFuncDef();
      (void)::moho::func_CAiBrainSetCurrentPlan_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPersonality_LuaFuncDef();
      (void)::moho::func_CAiBrainSetCurrentEnemy_LuaFuncDef();
      (void)::moho::func_CAiBrainGetCurrentEnemy_LuaFuncDef();
      (void)::moho::func_CAiBrainGetUnitBlueprint_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainSetArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainAddArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainSetGreaterOf_LuaFuncDef();
      (void)::moho::func_CAiBrainGetBlueprintStat_LuaFuncDef();
      (void)::moho::func_CAiBrainGetCurrentUnits_LuaFuncDef();
      (void)::moho::func_CAiBrainSetArmyStatsTrigger_LuaFuncDef();
      (void)::moho::func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef();
      (void)::moho::func_CAiBrainGetListOfUnits_LuaFuncDef();
      (void)::moho::func_CAiBrainSetResourceSharing_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyStartPos_LuaFuncDef();
      (void)::moho::func_CAiBrainCreateUnitNearSpot_LuaFuncDef();
      (void)::moho::func_CAiBrainFindPlaceToBuild_LuaFuncDef();
      (void)::moho::func_CAiBrainGetAttackVectors_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyStored_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyIncome_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyUsage_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyRequested_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyTrend_LuaFuncDef();
      (void)::moho::func_CAiBrainGetMapWaterRatio_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyStoredRatio_LuaFuncDef();
      (void)::moho::func_CAiBrainGiveResource_LuaFuncDef();
      (void)::moho::func_CAiBrainGiveStorage_LuaFuncDef();
      (void)::moho::func_CAiBrainTakeResource_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUnit_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUpgradeBP_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUnitToUpgrade_LuaFuncDef();
      (void)::moho::func_CAiBrainDecideWhatToBuild_LuaFuncDef();
      (void)::moho::func_CAiBrainGetAvailableFactories_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatAtPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatBetweenPositions_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatsAroundPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainPickBestAttackVector_LuaFuncDef();
      (void)::moho::func_CAiBrainCanBuildStructureAt_LuaFuncDef();
      (void)::moho::func_CAiBrainAssignThreatAtPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainGetHighestThreatPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildStructure_LuaFuncDef();
      (void)::moho::func_CAiBrainNumCurrentlyBuilding_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildUnit_LuaFuncDef();
      (void)::moho::func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainPlatoonExists_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPlatoonsList_LuaFuncDef();
      (void)::moho::func_CAiBrainDisbandPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNoRushTicks_LuaFuncDef();
      (void)::moho::func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef();
      (void)::moho::func_CAiBrainFindClosestArmyWithBase_LuaFuncDef();
      (void)::moho::func_CAiBrainGetUnitsAroundPoint_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef();
      (void)::moho::func_CAiBrainCheckBlockingTerrain_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainMakePlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainCanBuildPlatoon_LuaFuncDef();
    }
  };

  const CAiBrainLuaFuncDefBootstrap gCAiBrainLuaFuncDefBootstrap{};
} // namespace
namespace moho
{
  /**
   * Address: 0x00579D00 (FUN_00579D00)
   */
  void CAiBrain::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CAiBrain()), 0u);
  }

  /**
   * `gpg::SerConstructHelper<CAiBrain>`, vtable 0x00E19A48.
   *
   * Address: 0x00BCB3F0 (FUN_00BCB3F0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF62C0 (FUN_00BF62C0 -- the global's destructor.)
   * Address: 0x0057E3E0 (FUN_0057E3E0 -- `Init`.)
   * Address: 0x00579CF0 (FUN_00579CF0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x00581890 (FUN_00581890 -- `Delete`.)
   */
  struct CAiBrainConstruct : gpg::SerConstructHelper<CAiBrain>
  {};
}

namespace
{
  // Address: 0x010AD510 -- process-global `CAiBrainConstruct` singleton.
  moho::CAiBrainConstruct gCAiBrainConstruct;
}

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CAiBrain>`, vtable 0x00E19A58.
   *
   * Address: 0x00BCB430 (FUN_00BCB430 -- constructs the global and registers its destructor.)
   * Address: 0x00BF62F0 (FUN_00BF62F0 -- the global's destructor.)
   * Address: 0x00579DE0 (FUN_00579DE0 -- an unreferenced copy of the global's destructor.)
   * Address: 0x00579E10 (FUN_00579E10 -- an unreferenced copy of the global's destructor.)
   * Address: 0x0057E460 (FUN_0057E460 -- `Init`.)
   * Address: 0x00579D90 (FUN_00579D90 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00579DA0 (FUN_00579DA0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CAiBrainSerializer : gpg::SerSaveLoadHelper<CAiBrain>
  {};
}

namespace
{
  // Address: 0x010AD79C -- process-global `CAiBrainSerializer` singleton.
  moho::CAiBrainSerializer gCAiBrainSerializer;
}

