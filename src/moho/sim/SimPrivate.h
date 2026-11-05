#pragma once

// Private to moho/sim: helpers the pieces of the former Sim.cpp share.

#include "Sim.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "SimDriver.h"
#include "gpg/core/profiling/Profiler.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Windows.h>
#include <intrin.h>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/DesyncRecorder.h"
#include "lua/LuaCallGate.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/animation/PoseJobs.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/command/CCommandDb.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/sim/CDamage.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CVarAccess.h"
#include "moho/debug/RDebugOverlayClass.h"
#include "moho/entity/Entity.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/EntityPositionWatchEntry.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "lua/LuaError.h"
#include "lua/LuaRuntimeTypes.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CWldMap.h"
#include "moho/task/CLuaTask.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/BlueprintLoaderContext.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "gpg/core/containers/BitArray2D.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/math/Vector3f.h"
#include "moho/containers/BVSet.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMapReflection.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/EIntelTypeInfo.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/sim/SimDebugCommandRegistrations.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "lua/LuaCrashDump.h"
#if FAF_SERVER_MODE
#include "remote/client/LockstepDriver.h"
#endif


using namespace moho;
using EntId = std::int32_t;
namespace moho
{
  int cfunc_ReconBlipGetSource(lua_State* luaContext); // ReconBlip.cpp, `ReconBlip:GetSource()`
}

namespace
{
  constexpr CommandSourceId kInvalidCommandSource = 0xFF;



  [[nodiscard]] Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
  }

  [[nodiscard]] RRuleGameRulesImpl* ResolveRulesImpl(LuaPlus::LuaState* const state) noexcept
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    Sim* const sim = ResolveGlobalSim(state->m_state);
    if (!sim || !sim->mRules) {
      return nullptr;
    }

    return static_cast<RRuleGameRulesImpl*>(sim->mRules);
  }

  [[nodiscard]] const BVIntSet& CategoryWordRangeAsBVIntSet(const EntityCategorySet& range) noexcept
  {
    return range.mBits;
  }

  template <typename TInt>
  [[nodiscard]] std::uint32_t PackOpaqueArmyColor(const TInt red, const TInt green, const TInt blue) noexcept
  {
    const std::int32_t redLane = (static_cast<std::int32_t>(red) | 0xFFFFFF00) << 16;
    const std::int32_t greenLane = (static_cast<std::int32_t>(green) & 0xFF) << 8;
    const std::int32_t blueLane = static_cast<std::int32_t>(blue) & 0xFF;
    return static_cast<std::uint32_t>(redLane | greenLane | blueLane);
  }

  using ArmyListCursor = CArmyImpl* const*;

  template <typename TIterator>
  [[nodiscard]] TIterator FindArmyByNameCursor(TIterator begin, const TIterator end, const std::string_view armyName)
  {
    return std::find_if(begin, end, [armyName](const CArmyImpl* const army) -> bool {
      return army != nullptr && army->mConstDat.mArmyName.view() == armyName;
    });
  }

  /**
   * Address: 0x0070AD00 (FUN_0070AD00, func_FindArmyWithName)
   *
   * What it does:
   * Scans the army pointer range and returns the first entry whose `ArmyName`
   * matches `armyName` exactly, or `end` when no match exists.
   */
  [[nodiscard]] ArmyListCursor
  func_FindArmyWithName(ArmyListCursor begin, const ArmyListCursor end, const std::string_view armyName)
  {
    return FindArmyByNameCursor(begin, end, armyName);
  }

  /**
   * Address: 0x0070AC50 (FUN_0070AC50, func_GetArmyWithName)
   *
   * What it does:
   * Thin wrapper around `func_FindArmyWithName` used by army-Lua argument
   * decoding helpers.
   */
  [[maybe_unused]] [[nodiscard]] ArmyListCursor
  func_GetArmyWithName(ArmyListCursor begin, const ArmyListCursor end, const std::string_view armyName)
  {
    return func_FindArmyWithName(begin, end, armyName);
  }





  static_assert(sizeof(CommandManager) == 0xCC0, "CommandManager size must be 0xCC0");

  static_assert(
    offsetof(SimSubRes3, mValue) == offsetof(BVIntSet, mFirstWordIndex), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(
    offsetof(SimSubRes3, mReserved04) == offsetof(BVIntSet, mReservedMetaWord), "SimSubRes3/BVIntSet offset mismatch"
  );
  static_assert(offsetof(SimSubRes3, mValues) == offsetof(BVIntSet, mWords), "SimSubRes3/BVIntSet offset mismatch");
  static_assert(sizeof(SimSubRes3) == sizeof(BVIntSet), "SimSubRes3/BVIntSet size mismatch");

  /**
   * Address: 0x006856C0 (FUN_006856C0, std::map_EntId_Entity::find)
   *
   * What it does:
   * The `sim->mEntityDB->mAllUnits.find(id)` + end-check that every EntId
   * consumer in the sim (IssueCommand, DestroyEntity, WarpEntity, AdvanceBeat,
   * ProcessInfoPair, ...) open-codes around that one map lookup.
   */
  Entity* FindEntityById(EntityDB* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    const auto it = entityDb->mAllUnits.find(static_cast<std::uint32_t>(id));
    if (it == entityDb->mAllUnits.end()) {
      return nullptr;
    }

    return it->second;
  }

  static_assert(sizeof(EntitySetTemplate<Unit>) == 0x28, "EntitySetTemplate<Unit> size must be 0x28");
  static_assert(
    sizeof(TDatList<EntitySetBase, void>) == 0x08, "EntitySetTemplate<Unit> link-node size must be 0x08"
  );

  /**
   * The guarded shape of `CCommandDB::RemoveCmd` (0x006E0EC0, CCommandDb.cpp)
   * that this file's issue paths need.
   *
   * The retire body itself belongs to `CCommandDB` and lives there now -- it is
   * called unconditionally from `~CUnitCommand` (0x006E8500), which is how a
   * completed or cancelled order actually leaves the sim's command map. What
   * stays here is the pair of call-site guards the binary applies around it:
   * `Moho::UNIT_IssueCommand` (FUN_006F12C0) skips the call when the id is
   * still the unresolved `0xFF......` sentinel, and one Sim.cpp path
   * deliberately passes a possibly-null `mCommandDB`.
   */
  [[maybe_unused]] void ReleaseCommandIdIfUnconsumed(CCommandDB* commandDb, const CmdId cmdId)
  {
    if (!commandDb) {
      return;
    }

    if ((static_cast<std::uint32_t>(cmdId) & 0xFF000000u) == 0xFF000000u) {
      return;
    }

    commandDb->RemoveCmd(cmdId);
  }

  [[nodiscard]] Unit* GetTransportedBy(const Unit* const unit) noexcept
  {
    return (unit != nullptr) ? unit->TransportedByRef.GetObjectPtr() : nullptr;
  }

  [[nodiscard]] Unit* GetTransportFerryBeacon(Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return nullptr;
    }

    CUnitCommand* const currentCommand = unit->CommandQueue->GetCurrentCommand();
    if (currentCommand == nullptr) {
      return nullptr;
    }

    return currentCommand->mUnit.GetObjectPtr();
  }

  [[nodiscard]] bool HasCommandCap(const Unit* const unit, const ERuleBPUnitCommandCaps commandCap) noexcept
  {
    return unit != nullptr && (unit->GetAttributes().commandCapsMask & static_cast<std::uint32_t>(commandCap)) != 0u;
  }

  [[nodiscard]] bool IsValidTargetPosition(const Wm3::Vec3f& targetPosition) noexcept
  {
    return Wm3::Vector3fIsntNaN(&targetPosition);
  }

  [[nodiscard]] bool IsDuplicateSuppressionCommand(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Capture:
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Upgrade:
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
      case EUnitCommandType::UNITCOMMAND_Dock:
        return true;
      default:
        break;
    }

    return false;
  }

  [[nodiscard]] Unit* ResolveTargetUnit(Entity* const entity) noexcept
  {
    return entity != nullptr ? entity->IsUnit() : nullptr;
  }

  [[nodiscard]] Unit* ResolveTargetUnitOrReconCreator(Entity* const entity) noexcept
  {
    if (entity == nullptr) {
      return nullptr;
    }

    if (ReconBlip* const blip = entity->IsReconBlip(); blip != nullptr) {
      return blip->GetCreator();
    }

    return entity->IsUnit();
  }

  [[nodiscard]] bool CategoryCachesIntersect(
    const RUnitBlueprint* const lhsBlueprint,
    const RUnitBlueprint* const rhsBlueprint
  )
  {
    if (lhsBlueprint == nullptr || rhsBlueprint == nullptr) {
      return false;
    }

    const EntityCategorySet& lhsCategories = lhsBlueprint->Economy.CategoryCache;
    const EntityCategorySet& rhsCategories = rhsBlueprint->Economy.CategoryCache;
    const BVIntSet& lhsBits = CategoryWordRangeAsBVIntSet(lhsCategories);
    const BVIntSet& rhsBits = CategoryWordRangeAsBVIntSet(rhsCategories);

    BVIntSet intersection{};
    (void)lhsBits.Intersect(&intersection, &rhsBits);
    return intersection.Count() != 0u;
  }

  [[nodiscard]] bool HasBlueprintInCategory(
    const Sim* const sim,
    const REntityBlueprint* const blueprint,
    const char* const categoryName
  )
  {
    if (sim == nullptr || sim->mRules == nullptr || blueprint == nullptr || categoryName == nullptr) {
      return false;
    }

    const EntityCategorySet* const categoryRange = sim->mRules->GetEntityCategory(categoryName);
    const EntityCategorySet* const categorySet =
      categoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(categoryRange) : nullptr;
    return categorySet != nullptr && EntityCategory::HasBlueprint(blueprint, categorySet);
  }

  [[nodiscard]] bool EqualsNoCase(const char* const lhs, const char* const rhs) noexcept
  {
    const char* const safeLhs = lhs != nullptr ? lhs : "";
    const char* const safeRhs = rhs != nullptr ? rhs : "";
    return _stricmp(safeLhs, safeRhs) == 0;
  }

  [[nodiscard]] bool IsOutsideArmyNoRushRadius(const CArmyImpl* const army, const CAiTarget& target) noexcept
  {
    if (army == nullptr || army->mVarDat.mNoRushTimer <= 0 || target.targetType == EAiTargetType::AITARGET_None) {
      return false;
    }

    const float dx = (army->mVarDat.mArmyStart.x + army->mVarDat.mNoRushOffset.x) - target.position.x;
    const float dz = (army->mVarDat.mArmyStart.y + army->mVarDat.mNoRushOffset.y) - target.position.z;
    return std::sqrt((dx * dx) + (dz * dz)) > army->mVarDat.mNoRushRadius;
  }

  /**
   * Address: 0x006EF9E0 (FUN_006EF9E0, func_ProcessUnitCommand)
   *
   * What it does:
   * Applies per-unit command-family validation and rejection side-effects
   * before queue insertion in `UNIT_IssueCommand`.
   */
  [[maybe_unused]] [[nodiscard]] bool ProcessIssuedUnitCommand(
    Sim* const sim,
    const SSTICommandIssueData& commandIssueData,
    Unit* const unit,
    const bool clearQueue,
    const EntitySetTemplate<Unit>& selectedUnits
  )
  {
    if (sim == nullptr || unit == nullptr) {
      return false;
    }

    Entity* targetEntity = FindEntityById(sim->mEntityDB, static_cast<EntId>(commandIssueData.mTarget.mEntityId));
    CUnitCommandQueue* const queue = unit->CommandQueue;

    if (unit->IsDead()) {
      return false;
    }

    // FAF hot-patch: 0x006EFAC9 jumps to 0x0128D975 in .exxt, which tests
    // "FACTORY" (0x00E19824) and then "CQUEMOV" (string at 0x01293160, via the
    // pointer at 0x0129315C) before falling back to the original reject at
    // 0x006EFACE. CQUEMOV units (e.g. mass extractors) accept orders - such as
    // a queued upgrade - while still being built.
    if (unit->IsBeingBuilt() && !unit->IsInCategory("FACTORY")) {
      if (!unit->IsInCategory("CQUEMOV")) {
        return false;
      }

      // 0x0128D998 stores the failed FACTORY test's result (0) to `[esp+20h]`
      // while the CQUEMOV string pointer is pushed, which lands on the frame
      // slot holding the target entity. From here on the order is checked
      // against its issued position only, and an entity order whose position
      // lies off the map is dropped.
      targetEntity = nullptr;
    }

    if (queue != nullptr && IsDuplicateSuppressionCommand(commandIssueData.mCommandType)) {
      CUnitCommand* const currentCommand = queue->GetCurrentCommand();
      if (clearQueue && currentCommand != nullptr && currentCommand->mVarDat.mCmdType == commandIssueData.mCommandType
          && queue->GetNextCommand() == nullptr) {
        bool sameTarget = false;
        switch (commandIssueData.mTarget.mType) {
          case EAiTargetType::AITARGET_Entity:
            sameTarget = commandIssueData.mTarget.mEntityId == currentCommand->mVarDat.mTarget1.mEntityId;
            break;
          case EAiTargetType::AITARGET_Ground: {
            const Wm3::Vec3f& currentTargetPos = currentCommand->mVarDat.mTarget1.mPos;
            const float dx = commandIssueData.mTarget.mPos.x - currentTargetPos.x;
            const float dy = commandIssueData.mTarget.mPos.y - currentTargetPos.y;
            const float dz = commandIssueData.mTarget.mPos.z - currentTargetPos.z;
            sameTarget = std::sqrt((dx * dx) + (dy * dy) + (dz * dz)) < 0.001f;
            break;
          }
          default:
            break;
        }

        // 0x006EFE2A..0x006EFE3E: `EntitySetTemplate<Unit>::Same` (0x006EEC40)
        // -- raw entry counts, then every entry of the command's set looked
        // up in the selection; null entries are compared like any other.
        if (sameTarget && currentCommand->mUnitSet.Same(selectedUnits)) {
          return false;
        }
      }
    }

    if (commandIssueData.mTarget.mType != EAiTargetType::AITARGET_None) {
      const Wm3::Vec3f targetPosition = targetEntity != nullptr ? targetEntity->mVarDat.mCurTransform.pos_ : commandIssueData.mTarget.mPos;
      CArmyImpl* const army = unit->ArmyRef;

      if (sim->mMapData != nullptr && army != nullptr && !sim->mMapData->IsWithin(targetPosition, 0.0f, army->UseWholeMap())) {
        return false;
      }

      CAiTarget noRushTarget{};
      noRushTarget.targetType = commandIssueData.mTarget.mType;
      noRushTarget.position = targetPosition;
      if (IsOutsideArmyNoRushRadius(army, noRushTarget)) {
        return false;
      }
    }

    if (unit->IsUnitState(UNITSTATE_Enhancing) && clearQueue
        && commandIssueData.mCommandType != EUnitCommandType::UNITCOMMAND_Stop) {
      return false;
    }

    switch (commandIssueData.mCommandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove: {
        // 0x006EFED4..0x006EFF87: a carried unit may only take a move order
        // when it is a POD or its carrier is a CARRIER; anything riding in an
        // ordinary transport is refused (replay 26898759 beat 1890).
        Unit* const transportedBy = GetTransportedBy(unit);
        const bool invalidTransportState =
          transportedBy != nullptr && !unit->IsInCategory("POD") && !transportedBy->IsInCategory("CARRIER");
        if (invalidTransportState || !unit->IsMobile() || !IsValidTargetPosition(commandIssueData.mTarget.mPos)
            || commandIssueData.mTarget.mType == EAiTargetType::AITARGET_None) {
          return false;
        }
        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Dive: {
        const RUnitBlueprint* const blueprint = unit->GetBlueprint();
        return blueprint != nullptr && blueprint->Physics.MotionType == RULEUMT_SurfacingSub;
      }
      case EUnitCommandType::UNITCOMMAND_BuildFactory:
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
        return unit->IsInCategory("FACTORY") || unit->IsInCategory("ENGINEER") || unit->IsInCategory("NEEDMOBILEBUILD")
          || unit->IsInCategory("POD");
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
        if (!unit->IsMobile() && unit->AiAttacker == nullptr) {
          return false;
        }
        // 0x006F003E..0x006F0067: the attacker's army is asked (IArmy::IsAlly,
        // 0x005BD630, on `unit->ArmyRef + 8`) whether the target's army index
        // is in its ally set -- not the target army about the attacker.
        if (targetEntity != nullptr && targetEntity->ArmyRef != nullptr && unit->ArmyRef != nullptr) {
          const std::uint32_t targetArmyIndex = static_cast<std::uint32_t>(targetEntity->ArmyRef->mConstDat.mArmyIndex);
          if (targetArmyIndex != 0xFFFFFFFFu && unit->ArmyRef->mVarDat.mAllies.Contains(targetArmyIndex)) {
            return false;
          }
        }
        return true;
      case EUnitCommandType::UNITCOMMAND_Teleport:
        return HasCommandCap(unit, RULEUCC_Teleport);
      case EUnitCommandType::UNITCOMMAND_Guard: {
        // 0x006F08A7..0x006F097C: as for Move, a carried unit is refused unless
        // its carrier is a CARRIER (tested first) or it is itself a POD.
        Unit* const transportedBy = GetTransportedBy(unit);
        if ((transportedBy != nullptr && !transportedBy->IsInCategory("CARRIER") && !unit->IsInCategory("POD"))
            || !HasCommandCap(unit, RULEUCC_Guard)) {
          return false;
        }

        Unit* const targetUnit = ResolveTargetUnit(targetEntity);
        if (targetUnit == nullptr) {
          return unit->IsMobile();
        }

        if (unit == targetUnit) {
          return false;
        }

        if (!targetUnit->IsMobile() && !unit->IsMobile() && targetUnit->IsInCategory("FACTORY") && unit->IsInCategory("FACTORY")
            && !CategoryCachesIntersect(unit->GetBlueprint(), targetUnit->GetBlueprint())) {
          return false;
        }

        if (targetUnit->IsInCategory("FERRYBEACON") && GetTransportFerryBeacon(unit) == targetUnit) {
          return false;
        }

        const bool unitIsFactory = HasBlueprintInCategory(sim, unit->GetBlueprint(), "FACTORY");
        const bool targetIsFactory = HasBlueprintInCategory(sim, targetUnit->GetBlueprint(), "FACTORY");
        if (unitIsFactory && !targetIsFactory) {
          return false;
        }

        return targetUnit->GetGuardedUnit() != unit;
      }
      case EUnitCommandType::UNITCOMMAND_Ferry:
        return GetTransportedBy(unit) == nullptr && unit->IsInCategory("TRANSPORTATION") && unit->AiTransport != nullptr;
      case EUnitCommandType::UNITCOMMAND_Reclaim: {
        // 0x006F059C..0x006F060F: a carried unit is refused unless it is a POD.
        if ((GetTransportedBy(unit) != nullptr && !unit->IsInCategory("POD")) || !unit->IsInCategory("RECLAIM")) {
          return false;
        }

        if (targetEntity != nullptr && !targetEntity->IsBeingBuilt()) {
          if (targetEntity->BluePrint == nullptr || !targetEntity->IsInCategory("RECLAIMABLE")
              || targetEntity->mVarDat.mLayerMask == LAYER_Air) {
            return false;
          }

          Unit* const sourceUnit = ResolveTargetUnitOrReconCreator(targetEntity);
          if (sourceUnit != nullptr && !sourceUnit->GetAttributes().mReclaimable) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Capture: {
        // 0x006F043C..0x006F04A7: a carried unit is refused unless it is a POD.
        if ((GetTransportedBy(unit) != nullptr && !unit->IsInCategory("POD")) || !unit->IsInCategory("CAPTURE")) {
          return false;
        }

        if (targetEntity != nullptr) {
          Unit* const targetUnit = ResolveTargetUnitOrReconCreator(targetEntity);
          if (targetUnit == nullptr || !targetUnit->GetAttributes().mCapturable) {
            return false;
          }

          // 0x006F053F..0x006F0561: the target's army is asked about the
          // capturer's (`GetAllianceWith(this = target army + 8, unit army + 8
          // or null)` == Ally); a null capturer army reads as Neutral.
          if ((targetUnit->ArmyRef != nullptr && targetUnit->ArmyRef->GetAllianceWith(unit->ArmyRef) == ALLIANCE_Ally)
              || targetUnit->IsDead() || targetUnit->IsBeingBuilt()) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Sacrifice: {
        if (commandIssueData.mCommandType == EUnitCommandType::UNITCOMMAND_Sacrifice
            && !HasCommandCap(unit, RULEUCC_Sacrifice)) {
          return false;
        }

        if (targetEntity == nullptr) {
          return false;
        }

        // 0x006F0766..0x006F07D5: a carried unit is refused unless it is a POD.
        if ((GetTransportedBy(unit) != nullptr && !unit->IsInCategory("POD")) || !unit->IsInCategory("REPAIR")) {
          return false;
        }

        if (unit->ArmyRef != nullptr && targetEntity->ArmyRef != nullptr
            && unit->ArmyRef->GetAllianceWith(targetEntity->ArmyRef) == ALLIANCE_Enemy) {
          return false;
        }

        if (Unit* const targetUnit = ResolveTargetUnit(targetEntity); targetUnit != nullptr && targetUnit == unit) {
          return false;
        }

        return HasBlueprintInCategory(sim, unit->GetBlueprint(), "REPAIR");
      }
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Dock: {
        if (GetTransportedBy(unit) != nullptr || unit->IsInCategory("PODS")) {
          return false;
        }

        Unit* const targetUnit = ResolveTargetUnit(targetEntity);
        if (targetUnit == nullptr) {
          return true;
        }

        if ((targetUnit != unit && !HasCommandCap(unit, RULEUCC_CallTransport)) || targetUnit->mVarDat.mLayerMask == LAYER_Seabed) {
          return false;
        }

        const bool usesSpecialFerryFactoryLane =
          targetUnit->IsInCategory("FERRYBEACON")
          || (targetUnit->IsInCategory("FACTORY") && !targetUnit->IsInCategory("AIRSTAGINGPLATFORM")
              && !targetUnit->IsInCategory("TELEPORTATION"));
        if (!usesSpecialFerryFactoryLane) {
          IAiTransport* const targetTransport = targetUnit->AiTransport;
          if (targetUnit->IsDead() || targetUnit->IsBeingBuilt() || targetTransport == nullptr) {
            return false;
          }

          if (targetUnit == unit || targetTransport->TransportCanCarryUnit(unit)) {
            return true;
          }

          (void)targetUnit->RunScript("OnTransportReject");
          return false;
        }

        if (targetUnit->IsInCategory("FERRYBEACON") && GetTransportFerryBeacon(unit) == targetUnit) {
          return false;
        }

        if (unit->IsMobile() && !HasBlueprintInCategory(sim, unit->GetBlueprint(), "TRANSPORTATION")) {
          return true;
        }

        return false;
      }
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits: {
        if ((!unit->IsMobile() && !unit->IsInCategory("AIRSTAGINGPLATFORM")) || GetTransportedBy(unit) != nullptr
            || unit->IsInCategory("PODS")) {
          return false;
        }

        if (selectedUnits.Empty()) {
          return false;
        }

        Unit* candidateTransport = nullptr;
        for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
          Unit* const candidate = static_cast<Unit*>(*it);
          if (candidate == nullptr || candidate->IsDead() || candidate->IsBeingBuilt() || candidate->AiTransport == nullptr) {
            continue;
          }

          candidateTransport = candidate;
          Unit* const targetUnit = ResolveTargetUnit(targetEntity);
          if (targetUnit == nullptr) {
            if (candidateTransport != unit) {
              (void)candidateTransport->RunScript("OnTransportReject");
            }
            return false;
          }

          if (!candidate->AiTransport->TransportCanCarryUnit(targetUnit)) {
            continue;
          }

          if (candidate->mVarDat.mLayerMask == LAYER_Seabed) {
            return false;
          }

          return true;
        }

        if (candidateTransport != nullptr && candidateTransport != unit) {
          (void)candidateTransport->RunScript("OnTransportReject");
        }
        return false;
      }
      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
        return unit->mVarDat.mLayerMask != LAYER_Seabed && (unit->AiTransport != nullptr || GetTransportedBy(unit) != nullptr);
      case EUnitCommandType::UNITCOMMAND_Upgrade: {
        // Engine addition: a checked downcast. `mBlueprint` holds whatever
        // `CDecoder::DecodeCommandData` resolved through `GetEntityBlueprint`,
        // which also finds prop and projectile blueprints; the tests below read
        // `General`, i.e. past the end of such a blueprint. A non-unit blueprint
        // is no upgrade target, the same answer as no blueprint at all.
        const RUnitBlueprint* const upgradeBlueprint =
          dynamic_cast<const RUnitBlueprint*>(static_cast<const REntityBlueprint*>(commandIssueData.mBlueprint));
        const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
        if (upgradeBlueprint == nullptr || unitBlueprint == nullptr) {
          return false;
        }

        // 0x006F00A9: the arm goes straight from the blueprint lookup to the
        // SeedUnit / UpgradesTo / UpgradesFromBase tests. There is no buildable-
        // category gate here, so a later tier (T1 mex -> T3 mex, issued after a
        // queued T2 by FAF's IssueUpgradeOrders) is accepted through
        // UpgradesFromBase.
        const char* const seedUnitId = upgradeBlueprint->General.SeedUnit.name.c_str();
        if (seedUnitId != nullptr && seedUnitId[0] != '\0') {
          // 0x006F00DD..0x006F0102: one compare, the unit's own blueprint id.
          if (!EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), seedUnitId)) {
            return false;
          }
        } else {
          const char* const unitUpgradesTo = unitBlueprint->General.UpgradesTo.name.c_str();
          if (unitUpgradesTo == nullptr || unitUpgradesTo[0] == '\0') {
            return false;
          }

          const char* const requiredSourceId = upgradeBlueprint->General.UpgradesFromBase.name.c_str();
          if (!EqualsNoCase(requiredSourceId, "none")) {
            if (!EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), requiredSourceId)
                && !EqualsNoCase(unitBlueprint->General.UpgradesFromBase.name.c_str(), requiredSourceId)) {
              return false;
            }
          } else if (!EqualsNoCase(unitUpgradesTo, upgradeBlueprint->mBlueprintId.c_str())
                     && !EqualsNoCase(unitUpgradesTo, upgradeBlueprint->General.UpgradesFrom.name.c_str())) {
            return false;
          }
        }

        unit->mVarDat.mRequestRefreshUI = 1;
        CUnitCommand* const lastCommand = queue != nullptr ? queue->GetLastCommand() : nullptr;
        if (lastCommand != nullptr && lastCommand->mVarDat.mCmdType == commandIssueData.mCommandType) {
          const REntityBlueprint* const lastBlueprint = lastCommand->mConstDat.blueprint;
          if (lastBlueprint != nullptr && EqualsNoCase(lastBlueprint->mBlueprintId.c_str(), upgradeBlueprint->mBlueprintId.c_str())) {
            return false;
          }
        }

        return true;
      }
      case EUnitCommandType::UNITCOMMAND_KillSelf:
        return !unit->IsBeingBuilt() && unit->RunScriptUnitBool("CheckCanBeKilled", unit);
      case EUnitCommandType::UNITCOMMAND_OverCharge:
        return HasCommandCap(unit, RULEUCC_Overcharge);
      case EUnitCommandType::UNITCOMMAND_SpecialAction:
        return HasCommandCap(unit, RULEUCC_SpecialAction);
      default:
        return true;
    }
  }

  /**
   * `REntityBlueprint::mBlueprintId` (+0x08) of the entity's blueprint:
   * `[bp+0x20]` capacity test, `[bp+0x0C]` buffer (0x0074A9FE, 0x0068BF9A).
   */
  [[maybe_unused]] const char* ResolveBlueprintIdCString(const Entity* entity)
  {
    if (!entity || !entity->BluePrint) {
      return "";
    }

    return entity->BluePrint->mBlueprintId.raw_data_unsafe();
  }


  /**
   * Address: 0x00744C90 (FUN_00744C90, func_ArchiveWriteLuaObj)
   *
   * What it does:
   * Writes all key/value lanes from one Lua table iterator into archive object
   * stream as `LuaObject` entries, then writes one trailing nil marker object.
   */
  [[maybe_unused]] LuaPlus::LuaObject* func_ArchiveWriteLuaObj(gpg::WriteArchive* const archive, LuaPlus::LuaObject* const tableObject)
  {
    if (!archive || !tableObject) {
      return tableObject;
    }

    gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
    if (!luaObjectType) {
      luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = luaObjectType;
    }

    gpg::RRef nullOwner{};
    for (LuaPlus::LuaTableIterator iter(tableObject, 1); !iter.m_isDone; iter.Next()) {
      archive->Write(luaObjectType, &iter.m_keyObj, nullOwner);
      archive->Write(luaObjectType, &iter.m_valueObj, nullOwner);
    }

    LuaPlus::LuaObject nilObject{};
    nilObject.AssignNil(tableObject->m_state);
    archive->Write(luaObjectType, &nilObject, nullOwner);
    return tableObject;
  }
}

namespace
{

  static_assert(offsetof(CUnitCommandQueue, mCommandVec) == 0x0C, "CUnitCommandQueue::mCommandVec offset must be 0x0C");
  static_assert(
    offsetof(CUnitCommand, mVarDat) + offsetof(SSTICommandVariableData, mCmdType) == 0x98,
    "CUnitCommand's command type must sit at +0x98 (0x00764C80)"
  );
  static_assert(offsetof(CUnitCommand, mTarget) == 0x11C, "CUnitCommand::mTarget offset must be 0x11C (0x00764CCE)");

  [[maybe_unused]] void AdvanceCoords(Entity* entity)
  {
    if (!entity) {
      return;
    }

    entity->AdvanceCoords();
  }
}



namespace
{
  struct DumpUnitsCountEntry
  {
    const RUnitBlueprint* blueprint = nullptr;
    int count = 0;
  };

  static_assert(sizeof(DumpUnitsCountEntry) == 8, "DumpUnitsCountEntry size must be 8");
  static_assert(std::is_trivially_copyable_v<DumpUnitsCountEntry>,
                "DumpUnitsCountEntry must be trivially copyable for the msvc8 _Insert_n memmove lane");
  [[nodiscard]] moho::RRuleGameRulesImpl* ResolveLuaBlueprintRules(LuaPlus::LuaState* state) noexcept;
  [[nodiscard]] moho::RRuleGameRulesImpl* ResolveLuaBlueprintRules(LuaPlus::LuaState* const state) noexcept
  {
    if (moho::RRuleGameRulesImpl* const rules = moho::BlueprintLoaderContext().mRules; rules != nullptr) {
      return rules;
    }
    return ResolveRulesImpl(state);
  }

  // Helper block for the blueprint registration chain.
  //
  // Every one of FUN_005289D0 (register category membership), FUN_00531D80
  // (unit blueprint create/find path), FUN_00532080 (prop blueprint
  // create/find path) and FUN_00532380 (projectile blueprint create/find
  // path) is a real, standalone binary function boundary with its own real
  // callers (confirmed via each token's `.xrefs.txt`), not compiler-emitted
  // glue or inlined-away logic. FUN_00531D80/FUN_00532080/FUN_00532380 are
  // recovered below as `CreateOrGet*BlueprintFromState` (see their own
  // `Address:` blocks). FUN_005289D0 is recovered immediately below as
  // `RegisterBlueprintCategoryMembership` (see its `Address:` block for the
  // full evidence trail); a prior pass here had incorrectly claimed none of
  // the four carried standalone boundaries and left FUN_005289D0's mapping
  // uncited -- that claim did not hold even for this block's own siblings
  // (`AddCategoryMemberBit`, `AppendBlueprintOrdinal` and
  // `RegisterBlueprintInCategoryMaps` below already cite their own
  // `FUN_005555C0`/`FUN_005347A0`/`FUN_00529B30` addresses).
  // CategoryLookupValue/CategoryLookupMap/EntityCategoryLookupTableView used
  // to be defined here as a second, per-TU-only copy of the exact same
  // binary object RRuleGameRules.cpp's `EntityCategoryLookupTable`
  // models (`RRuleGameRulesImpl::mEntityCategoryLookup`, +0xC4) -- this
  // anonymous namespace's version reached it read the same live object
  // through `ResolveEntityCategoryLookupTable`'s `reinterpret_cast` below.
  // Per the CLAUDE.md duplicate-layout contract ("pick a single owning
  // reconstructed definition"), that duplication is gone: the real type
  // (identical layout, identical evidence -- 8-byte-aligned node, value at
  // node+0x10, colour/isNil at node+0x58/0x59, all independently
  // re-verified against the raw decompiles during the RRuleGameRules.cpp
  // migration this promotion is part of) now lives once, in
  // `moho::CategoryLookupValue`/`moho::CategoryLookupMap`/
  // `moho::EntityCategoryLookupTable` (RRuleGameRules.h), and
  // this file uses that shared definition directly instead of a
  // `reinterpret_cast`-punned twin. `RbTree.h`'s `insert_unique`/`insert_at`/
  // `buy_node`/`rb_decrement`/`find_node` citations for this instantiation
  // (below, on `AddCategoryMemberBit`) are unaffected -- same type, same
  // addresses, just one definition instead of two.

  /**
   * Address: 0x005347A0 (FUN_005347A0, fa::vector<Moho::RBlueprint*>::push_back)
   *
   * IDA signature:
   * unsigned int __usercall sub_5347A0@<eax>(RBlueprint **value@<eax>,
   *                                          std::vector_RBlueprint_P *vec);
   *
   * What it does:
   * Appends one blueprint pointer to the by-ordinal registry at `rules + 0xB4`
   * (`add ecx, 0B4h` at 0x00531FE9 in `func_CreateRUnitBlueprint`). The append
   * is the legacy container's own `push_back`; on the capacity-full path MSVC8
   * routes it into the `vector<RBlueprint*>::insert(end(), 1, value)` lane
   * emitted at FUN_00535D60.
   *
   * The parameter stays `void*` because the recovered `REntityBlueprint`
   * models the shared blueprint header by layout duplication rather than by
   * deriving from `RBlueprint`, so `RUnitBlueprint*` has no implicit
   * conversion to the registry's element type yet. The binary stores the raw
   * pointer value either way.
   */
  void AppendBlueprintOrdinal(RRuleGameRulesImpl& rules, void* const blueprintObject)
  {
    if (blueprintObject == nullptr) {
      return;
    }

    // push_back's capacity-full path is `fa::vector<RBlueprint*>::insert`
    // (FUN_00535D60), reached through the binary's push_back at FUN_005347A0.
    rules.mBlueprintsByOrdinal.push_back(static_cast<RBlueprint*>(blueprintObject));
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) -- `mMaps` lane
   *
   * What it does:
   * Inserts the newly registered blueprint's ordinal into every currently
   * connected Lua export binding's pending-ordinal set
   * (`RRuleGameRulesImpl::mMaps[i].mPendingBlueprintOrdinals`), so
   * `RRuleGameRulesImpl::UpdateLuaState`'s next `SynchronizeBlueprintTable`
   * pass for that target state knows this blueprint needs to be (re-)pushed
   * -- `UpdateLuaState` clears the set right after synchronizing
   * (RRuleGameRules.cpp), matching a pending/dirty-set role.
   *
   * The binary performs this as the loop at 0x00529BE3-0x00529C0B, calling
   * `func_MapInsert` / `FUN_0052BC60` (`fa::detail::rb_tree<...>::
   * insert_unique` for the `fa::set<uint32_t>` embedded at
   * `RRuleGameRulesLuaExportBinding::mPendingBlueprintOrdinals` -- see the
   * citation block on `insert_unique` in RbTree.h) on `binding + 4` for
   * every existing `[mMaps.begin(), mMaps.end())` binding, using the
   * blueprint's `mBlueprintOrdinal` (+0x5C) as the key.
   *
   * `mMaps` is a real `fa::vector<RRuleGameRulesLuaExportBinding>`
   * (RRuleGameRules.h); this walk uses its own `begin()`/`end()` instead of
   * the hand-rolled `mBegin`/`mEnd` pointer fields the now-removed
   * `RRuleGameRulesLuaExportBindingArray` used to expose.
   */
  void RegisterBlueprintInCategoryMaps(RRuleGameRulesImpl& rules, void* const blueprintObject)
  {
    if (blueprintObject == nullptr) {
      return;
    }

    const auto* const blueprint = reinterpret_cast<const RBlueprint*>(blueprintObject);
    const auto ordinal = static_cast<std::uint32_t>(blueprint->mBlueprintOrdinal);

    for (RRuleGameRulesLuaExportBinding& binding : rules.mMaps) {
      (void)binding.mPendingBlueprintOrdinals.insert(ordinal);
    }
  }

  void InitMeshBlueprintFromLua(LuaPlus::LuaObject& luaBlueprint, RMeshBlueprint* const blueprint)
  {
    gpg::RRef destination{};
    destination = gpg::MakeRRef<moho::RMeshBlueprint>(blueprint);

    LuaPlus::LuaObject source(luaBlueprint);
    (void)SCR_LuaBuildObject(source, destination, true);

    blueprint->OnInitBlueprint();

    gpg::RRef resolved{};
    resolved = gpg::MakeRRef<moho::RMeshBlueprint>(blueprint);
    SCR_RObjectToLuaMerge(resolved, luaBlueprint);
  }

  [[nodiscard]] LuaPlus::LuaObject EnsureLuaBlueprintTable(LuaPlus::LuaState* const state)
  {
    if (!state) {
      return {};
    }

    LuaPlus::LuaObject allBlueprints = state->GetGlobal("__blueprints");
    if (allBlueprints.IsTable()) {
      return allBlueprints;
    }

    LuaPlus::LuaObject globals = state->GetGlobals();
    LuaPlus::LuaObject replacement{};
    replacement.AssignNewTable(state, 0, 0);
    globals.SetObject("__blueprints", replacement);
    return state->GetGlobal("__blueprints");
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) - by-ordinal lane
   *
   * What it does:
   * Ground truth publishes the Lua blueprint object into `__blueprints`
   * TWICE: first by ordinal (`__blueprints[mBlueprintOrdinal] = luaBlueprint`,
   * read directly off `FUN_00529B30`'s own pseudocode: `SetObject(Global,
   * mBlueprintOrdinal, a1)`), then by string name. This function previously
   * only recovered the by-name half; the by-ordinal `SetObject` call below
   * completes it. `RBlueprint::GetLuaBlueprint` (RBlueprint.cpp, ground
   * truth FUN_0050DF90) reads back ONLY via the ordinal index
   * (`__blueprints[mBlueprintOrdinal]`) - every Lua-side `unit:GetBlueprint()`
   * call (cfunc_UserUnitGetBlueprintL/cfunc_EntityGetBlueprintL, both call
   * this same GetLuaBlueprint) depends on this half existing.
   */
  void PublishLuaBlueprint(
    LuaPlus::LuaObject& luaBlueprint,
    void* const blueprintObject,
    RRuleGameRulesImpl* const rules
  )
  {
    const RBlueprint* const blueprint = reinterpret_cast<const RBlueprint*>(blueprintObject);
    if (!rules || !rules->mLuaState || !blueprint) {
      return;
    }

    LuaPlus::LuaObject allBlueprints = EnsureLuaBlueprintTable(rules->mLuaState);
    if (!allBlueprints.IsTable()) {
      return;
    }

    allBlueprints.SetObject(blueprint->mBlueprintOrdinal, luaBlueprint);
    allBlueprints.SetObject(blueprint->mBlueprintId.c_str(), luaBlueprint);
  }

  [[nodiscard]] fa::string ResolveNormalizedBlueprintId(const LuaPlus::LuaObject& blueprintSpec)
  {
    LuaPlus::LuaObject idObject = blueprintSpec.GetByName("BlueprintId");
    const char* const rawId = idObject.GetString();
    return gpg::STR_ToLower(rawId ? rawId : "");
  }

  /**
   * Address: 0x00529B30 (FUN_00529B30, func_Add__blueprints) -- by-ordinal
   * and by-name Lua publication lanes
   *
   * What it does:
   * The binary's blueprint registration chain calls `func_Add__blueprints`
   * after each blueprint registration to publish the blueprint into
   * `__blueprints` Lua global by ordinal and by string-name keys, then
   * iterate `rules->mMaps` and register the blueprint's ordinal into every
   * connected export binding's pending set. The recovered code retains the
   * by-string-name Lua publication via `PublishLuaBlueprint`, the
   * ordinal-vector append via `AppendBlueprintOrdinal`, and (now that
   * `RRuleGameRulesImpl::mMaps` is modeled -- see RRuleGameRules.h) the
   * `mMaps` iteration via `RegisterBlueprintInCategoryMaps`, which is what
   * `func_MapInsert` / `FUN_0052BC60`'s role in this loop absorbs into.
   *
   * The by-ordinal Lua `SetObject` path is still elided: the category
   * bit-set / Lua ordinal publication for that specific lane is routed
   * through `mEntityCategoryLookup` + `BlueprintOrdinalVector`, which take
   * a different shape than the binary's flat array here.
   */
  template <typename TBlueprint, typename Initializer>
  [[nodiscard]] TBlueprint* GetOrCreateRegisteredBlueprint(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules,
    RRuleGameRulesBlueprintMap& map,
    const char* const blueprintTypeName,
    Initializer initializer
  )
  {
    if (!state || !state->m_state || !rules) {
      return nullptr;
    }

    LuaPlus::LuaObject blueprintSpec(LuaPlus::LuaStackObject(state, 1));
    const fa::string normalizedId = ResolveNormalizedBlueprintId(blueprintSpec);

    const fa::string logContextText =
      gpg::STR_Printf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    gpg::ScopedLogContext logScope(logContextText);
    if (CFG_GetArgOption("/spewbp", 0u, nullptr)) {
      gpg::Logf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    }

    TBlueprint* blueprint = nullptr;
    if (const auto found = map.find(normalizedId); found != map.end()) {
      blueprint = static_cast<TBlueprint*>(found->second);
    }

    if (!blueprint) {
      RResId resourceId{};
      gpg::STR_CopyFilename(&resourceId.name, &normalizedId);

      blueprint = new (std::nothrow) TBlueprint(rules, resourceId);
      if (!blueprint) {
        return nullptr;
      }

      const auto inserted = map.insert(RRuleGameRulesBlueprintMap::value_type(normalizedId, blueprint));
      if (!inserted.second) {
        delete blueprint;
        return nullptr;
      }

      AppendBlueprintOrdinal(*rules, blueprint);
      RegisterBlueprintInCategoryMaps(*rules, blueprint);
    }

    initializer(blueprintSpec, blueprint);
    PublishLuaBlueprint(blueprintSpec, blueprint, rules);
    return blueprint;
  }

  template <typename TBlueprint, typename RefBuilder>
  [[nodiscard]] TBlueprint* GetOrCreateRegisteredEffectBlueprint(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules,
    RRuleGameRulesBlueprintMap& map,
    const char* const blueprintTypeName,
    RefBuilder refBuilder
  )
  {
    if (!state || !state->m_state || !rules) {
      return nullptr;
    }

    LuaPlus::LuaObject blueprintSpec(LuaPlus::LuaStackObject(state, 1));
    const fa::string normalizedId = ResolveNormalizedBlueprintId(blueprintSpec);

    const fa::string logContextText =
      gpg::STR_Printf("Initializing %s blueprint for %s", blueprintTypeName, normalizedId.c_str());
    gpg::ScopedLogContext logScope(logContextText);

    TBlueprint* blueprint = nullptr;
    if (const auto found = map.find(normalizedId); found != map.end()) {
      blueprint = static_cast<TBlueprint*>(found->second);
    }

    if (!blueprint) {
      blueprint = new (std::nothrow) TBlueprint();
      if (!blueprint) {
        return nullptr;
      }

      blueprint->mOwnerRules = rules;
      gpg::STR_CopyFilename(&blueprint->BlueprintId.name, &normalizedId);

      const auto inserted = map.insert(RRuleGameRulesBlueprintMap::value_type(normalizedId, blueprint));
      if (!inserted.second) {
        delete blueprint;
        return nullptr;
      }
    }

    gpg::RRef destination{};
    (void)refBuilder(&destination, blueprint);

    LuaPlus::LuaObject source(blueprintSpec);
    (void)SCR_LuaBuildObject(source, destination, true);
    return blueprint;
  }

  /**
   * Address: 0x00532680 (FUN_00532680, func_RegisterMeshBlueprint)
   *
   * What it does:
   * Creates or resolves one mesh blueprint from Lua stack lane 1, applies Lua
   * payload fields, and publishes the merged object into `__blueprints`.
   */
  [[nodiscard]] RMeshBlueprint* CreateOrGetMeshBlueprintFromState(
    LuaPlus::LuaState* const state,
    RRuleGameRulesImpl* const rules
  )
  {
    return GetOrCreateRegisteredBlueprint<RMeshBlueprint>(
      state,
      rules,
      rules->mMeshBlueprints,
      "mesh",
      [](LuaPlus::LuaObject& blueprintSpec, RMeshBlueprint* const meshBlueprint) {
        InitMeshBlueprintFromLua(blueprintSpec, meshBlueprint);
      }
    );
  }

  [[maybe_unused]] int RegisterMeshBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    RMeshBlueprint* const blueprint = CreateOrGetMeshBlueprintFromState(state, rules);
    (void)blueprint;
    return 0;
  }

  /**
   * Address: 0x00532980 (FUN_00532980, func_RegisterTrailEmitterBlueprint)
   *
   * What it does:
   * Creates or resolves one trail-emitter blueprint from Lua stack lane 1,
   * then applies reflected field values from the Lua object into that
   * blueprint instance.
   */
  [[maybe_unused]] int RegisterTrailEmitterBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<RTrailBlueprint>(
      state,
      rules,
      rules->mTrailBlueprints,
      "trail emitter",
      [](gpg::RRef* const out, RTrailBlueprint* const trailBlueprint) {
        *out = gpg::MakeRRef<moho::RTrailBlueprint>(trailBlueprint);
        return out;
      }
    );
    return 0;
  }

  /**
   * Address: 0x00532C10 (FUN_00532C10, func_RegisterEmitterBlueprint)
   *
   * What it does:
   * Creates or resolves one particle-emitter blueprint from Lua stack lane 1,
   * then applies reflected field values from the Lua object into that
   * blueprint instance.
   */
  [[maybe_unused]] int RegisterEmitterBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<REmitterBlueprint>(
      state,
      rules,
      rules->mEmitterBlueprints,
      "particle emitter",
      [](gpg::RRef* const out, REmitterBlueprint* const emitterBlueprint) {
        *out = gpg::MakeRRef<moho::REmitterBlueprint>(emitterBlueprint);
        return out;
      }
    );
    return 0;
  }

  /**
   * Address: 0x00532EC0 (FUN_00532EC0, func_RegisterBeamBlueprint)
   *
   * What it does:
   * Creates or resolves one beam blueprint from Lua stack lane 1, then applies
   * reflected field values from the Lua object into that blueprint instance.
   */
  [[maybe_unused]] int RegisterBeamBlueprintFromState(LuaPlus::LuaState* const state)
  {
    RRuleGameRulesImpl* const rules = ResolveLuaBlueprintRules(state);
    if (!rules) {
      return 0;
    }

    (void)GetOrCreateRegisteredEffectBlueprint<RBeamBlueprint>(
      state,
      rules,
      rules->mBeamBlueprints,
      "beam effect",
      [](gpg::RRef* const out, RBeamBlueprint* const beamBlueprint) {
        *out = gpg::MakeRRef<moho::RBeamBlueprint>(beamBlueprint);
        return out;
      }
    );
    return 0;
  }
  [[maybe_unused]] void TickBlueprintLoaderProgressFromLoaderContext()
  {
    moho::CBackgroundTaskControl* const initHandler = moho::BlueprintLoaderContext().mInitHandler;
    if (initHandler != nullptr && initHandler->mHandle != nullptr) {
      initHandler->mHandle->UpdateLoadingProgress();
    }
  }
}


namespace moho
{
  extern bool dbg_RulesTraceAlways;
  extern bool sim_ParallelCoords;
  extern bool sim_ReconOverlap;
  extern bool sim_ParallelUnitSyncRefresh;
  extern bool sim_ChecksumBatching;
#if FAF_SERVER_MODE
  extern CSyncObserver* sSyncObserver;
  extern std::mutex sSyncObserverLock;
  extern ISyncRouting* sSyncRouting;
#endif
}
