// Engine addition (dedicated-server plan WPL.4, WPR.11): the user world's
// command issuing (ISSUE_Command, ISSUE_SetCommandTarget,
// ISSUE_DecreaseCommandCount, the session's CommandManager and its
// UserCommandIssueHelper bookkeeping), moved unchanged out of Sim.cpp. It runs
// on the client: the selection, the focus army and the local command echo.
#include "moho/sim/Sim.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/SimDriver.h"

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
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CUserSoundManager.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
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
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
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
#include "moho/ui/CUIManager.h"
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

using namespace moho;

namespace moho
{
  /**
   * Address: 0x008B00A0 (FUN_008B00A0, func_DecodeEntIdSet)
   *
   * IDA signature:
   * Moho::EntIdSet *__cdecl func_DecodeEntIdSet(Moho::EntIdSet *a1, gpg::fastvector_UserUnit *a2);
   *
   * What it does:
   * Builds an `EntIdSet` (BVSet<EntId,EntIdUniverse>) from a list of selected
   * user units: resets `out`'s bit-set to empty, then walks `units` and inserts
   * each unit's entity id into the set. Every entity id must share the same
   * high-nibble type (`id >> 28`) as the first unit; a mismatch is a fatal
   * `gpg::Die`, matching CDecoder::DecodeEntIdSet's wire-decode guard.
   */
  void func_DecodeEntIdSet(
    moho::BVSet<moho::EntId, moho::EntIdUniverse>& out, const gpg::fastvector<moho::UserUnit*>& units
  )
  {
    // out->mSet default-empty: mFirstWordIndex/reserved cleared, SBO words
    // self-referential and empty (asm 0x8B00D0..0x8B00E1).
    out.Bits() = moho::BVIntSet{};

    if (units.begin() == units.end()) {
      return;
    }

    // The packed entity id is `UserEntity::mParams.mEntityId` ([unit+0x44]).
    const auto entityIdOf = [](const moho::UserUnit* const unit) noexcept -> std::uint32_t {
      return static_cast<std::uint32_t>(unit->mParams.mEntityId);
    };

    // The shared id type is taken from the first unit and compared against
    // every element (asm reloads v5 from v7 == first nibble each iteration).
    const std::uint32_t firstType = entityIdOf(units.front()) >> 28u;

    for (moho::UserUnit* const unit : units) {
      const std::uint32_t entityId = entityIdOf(unit);
      const std::uint32_t entityType = entityId >> 28u;
      if (firstType != entityType) {
        gpg::Die(
          "Attempt to construct EntIdSet with different types of IDs (%d and %d) in DecodeEntIdSet",
          firstType,
          entityType
        );
      }

      (void)out.Bits().Add(entityId);
    }
  }
} // namespace moho

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  /**
   * The shared body of `QueueCommandIssueSelectUnitEvent` (0x008B4720) and
   * `QueueCommandIssueDeselectUnitEvent` (0x008B4880), which differ only in
   * the event kind. Adds `unit` to the newest local edit when that edit is already a
   * `kind` edit for `cmdId` (the back of the deque, index `off + size - 1`
   * wrapped once at 0x008B474D..0x008B4762); otherwise queues a fresh empty
   * one first. The unit goes in through `WeakSet<UserUnit>::Add` (0x00822270).
   */
  void QueueCommandIssueUnitEvent(
    UserCommandIssueHelper& helper, const CmdId cmdId, const ECommandIssueEvent kind, UserUnit* const unit
  )
  {
    msvc8::deque<UserCommandIssueLocalEvent>& events = helper.mLocalQueue;
    if (events.empty() || events.back().mType != kind || events.back().mCmdId != cmdId) {
      const UserCommandIssueLocalEvent event(cmdId, kind);
      events.push_back(event);
    }

    (void)events.back().mUnits.Add(unit);
  }

  /**
   * Address: 0x008BECD0 (FUN_008BECD0, sub_8BECD0)
   *
   * What it does:
   * Converts one UI-side command target (`moho::UserTarget`,
   * moho/command/UserTarget.h) into the sim-side network payload
   * `SSTITarget`. `Entity` targets resolve the owning `UserEntity`'s stable
   * id (`SCreateEntityParams::mEntityId` at `UserEntity::mParams`, decoded
   * through the same `ownerLinkSlot - 8` weak-owner convention used
   * throughout UserUnit.cpp) or the sentinel id `0xF0000000` when the link
   * slot is null or still the empty-slot tombstone (`== 8`); `Position`
   * targets copy the inline position; any other target type maps to
   * `AITARGET_None` with the sentinel id. Sole caller is
   * `Moho::ISSUE_SetCommandTarget` (0x008B0EE0).
   */
  [[nodiscard]] SSTITarget ConvertUserCommandTargetToSSTITarget(const UserTarget& source) noexcept
  {
    constexpr std::uint32_t kUnresolvedTargetEntityId = 0xF0000000u;

    SSTITarget result{};
    if (source.targetType == UserTargetType::Entity) {
      result.mType = EAiTargetType::AITARGET_Entity;
      result.mEntityId = kUnresolvedTargetEntityId;
      if (const UserEntity* const entity = source.targetEntity.GetObjectPtr(); entity != nullptr) {
        result.mEntityId = entity->mParams.mEntityId;
      }
    } else if (source.targetType == UserTargetType::Position) {
      result.mType = EAiTargetType::AITARGET_Ground;
      result.mEntityId = kUnresolvedTargetEntityId;
      result.mPos = source.position;
    } else {
      result.mType = EAiTargetType::AITARGET_None;
      result.mEntityId = kUnresolvedTargetEntityId;
    }
    return result;
  }
  /**
   * Address: 0x008B49D0 (FUN_008B49D0, sub_8B49D0)
   *
   * What it does:
   * Queues one local "decrease count" edit of `deltaCount`.
   *
   * Address: 0x008B4960 (FUN_008B4960 -- the "increase count" sibling, the same
   * body with kind 1; zero callers and no references in the image, a
   * linker-retained copy nothing runs.)
   */
  void QueueCommandIssueDecreaseCountEvent(UserCommandIssueHelper& helper, const CmdId cmdId, const std::int32_t deltaCount)
  {
    UserCommandIssueLocalEvent event(cmdId, ECommandIssueEvent::DecreaseCount);
    event.mCount = deltaCount;
    helper.mLocalQueue.push_back(event);
  }
  /**
   * Address: 0x008B4A40 (FUN_008B4A40, sub_8B4A40)
   *
   * What it does:
   * Queues one local "set target" edit on the helper: the event is built
   * (0x008B3DC0), its target assigned from `target` (`UserTarget`'s implicit
   * copy assignment, 0x008B3E50), pushed (0x008B4E80) and destroyed
   * (0x008B4800). Sole caller is `Moho::ISSUE_SetCommandTarget` (0x008B0EE0).
   */
  void QueueCommandIssueSetTargetEvent(UserCommandIssueHelper& helper, const CmdId cmdId, const UserTarget& target)
  {
    UserCommandIssueLocalEvent event(cmdId, ECommandIssueEvent::SetTarget);
    event.mTarget = target;
    helper.mLocalQueue.push_back(event);
  }
  /**
   * Address: 0x008B4AC0 (FUN_008B4AC0, sub_8B4AC0)
   *
   * IDA signature:
   * void __stdcall sub_8B4AC0(int arg0, int a2, int a3);
   *
   * What it does:
   * Queues one local "set command type" edit (`mCommandType` at event+0x30,
   * 0x008B4AF8). Sole caller is `Moho::ReissueCommandIssueEntryAsType`.
   */
  void QueueCommandIssueSetTypeEvent(
    UserCommandIssueHelper& helper, const CmdId cmdId, const EUnitCommandType newCommandType
  )
  {
    UserCommandIssueLocalEvent event(cmdId, ECommandIssueEvent::SetCommandType);
    event.mCommandType = newCommandType;
    helper.mLocalQueue.push_back(event);
  }
} // namespace


// External linkage: moho::ISSUE_FactoryCommand (CWldSession.cpp) references
// this as moho::, so an anonymous-namespace body here could never resolve it.
namespace moho
{
  /**
   * Address: 0x008B5B50 (FUN_008B5B50, struct_CommandManager::NextCmdId)
   *
   * What it does:
   * Allocates one next command low-id from the manager id-pool (released set
   * first, then sequential cursor), packs the active source byte into high bits,
   * and writes the resulting command id to `outCommandId`.
   */
  [[nodiscard]] std::uint32_t* AllocatePackedCommandIdFromManager(
    CommandManager* const commandManager,
    std::uint32_t* const outCommandId
  ) noexcept
  {
    if (commandManager->mSourceId == 0xFFu) {
      *outCommandId = std::numeric_limits<std::uint32_t>::max();
      return outCommandId;
    }

    std::uint32_t nextLowId = 0u;
    if (commandManager->mIdPool.mReleasedLows.mWords.begin() == commandManager->mIdPool.mReleasedLows.mWords.end()) {
      nextLowId = static_cast<std::uint32_t>(commandManager->mIdPool.mNextLowId++);
    } else {
      nextLowId = commandManager->mIdPool.mReleasedLows.GetNext(std::numeric_limits<std::uint32_t>::max());
      (void)commandManager->mIdPool.mReleasedLows.Remove(nextLowId);
    }

    *outCommandId = nextLowId | (static_cast<std::uint32_t>(commandManager->mSourceId) << 24u);
    return outCommandId;
  }
} // namespace moho
// External linkage, not internal: CWldSession.cpp calls this as
// moho::ISSUE_SetCommandTarget from three sites, so an anonymous-namespace
// body here could never resolve them - it was one of the LNK2019s /FORCE
// swallows into live call sites pointing at nothing.
namespace moho
{
  /**
   * Address: 0x008B0EE0 (FUN_008B0EE0, ?ISSUE_SetCommandTarget@Moho@@YAXPAVUserCommand@1@ABVUserTarget@1@@Z)
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_SetCommandTarget(Moho::UserCommand* helper, Moho::UserTarget const& target);
   *
   * What it does:
   * Client/UI-side command-target keystone, the `ISSUE_Command` family's
   * counterpart for redirecting a command already in flight. Resolves the
   * target's world position and gates it against the same no-rush timer/
   * radius rule `ISSUE_Command` applies (skipped outright when the target is
   * `None`, or when the resolved position is invalid/no focus army is set);
   * once past the gate (or bypassed via an invalid position/focus army),
   * further gates on the helper's own command type: when it is not the
   * pickup-style type (raw ordinal `22`; no named `EUnitCommandType`
   * enumerator has been recovered for it yet), the retarget always proceeds.
   * When it is that type, the retarget proceeds only if the target resolves
   * to a live entity in one of `FERRYBEACON`/`TRANSPORTATION`/
   * `AIRSTAGINGPLATFORM` - any other entity (or a non-entity target) is
   * silently rejected. On proceed: converts the target to `SSTITarget` and
   * publishes it through the active sim driver, then queues the matching
   * local "set-target" update event via `QueueCommandIssueSetTargetEvent`.
   */
  void ISSUE_SetCommandTarget(UserCommandIssueHelper* const helper, const UserTarget& target)
  {
    CWldSession* const session = WLD_GetActiveSession();
    auto* const playableMap = session->mWldMap->mTerrainRes->mMap;

    bool shouldRetarget = (target.targetType == UserTargetType::None);
    if (!shouldRetarget) {
      const Wm3::Vector3<float> targetPosition = ResolvePositionFromTarget(target);
      if (!IsValidVector3f(targetPosition)) {
        shouldRetarget = true;
      } else if (session->FocusArmy >= 0) {
        if (UserArmy* const focusArmyByIndex = session->userArmies[static_cast<std::size_t>(session->FocusArmy)];
            focusArmyByIndex != nullptr) {
          const bool insidePlayableArea = focusArmyByIndex->mVarDat.mUseWholeMap != 0u || playableMap == nullptr ||
            playableMap->IsPlayable(targetPosition);
          if (insidePlayableArea) {
            const UserArmy* const focusArmy = session->GetFocusArmy();
            if (focusArmy->mVarDat.mNoRushTimer <= 0) {
              shouldRetarget = true;
            } else {
              const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPosition.x;
              const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPosition.z;
              const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
              shouldRetarget = (distance <= focusArmy->mVarDat.mNoRushRadius);
            }
          }
        }
      }
    }

    if (!shouldRetarget) {
      return;
    }

    // Command-type gate: only the pickup-style command type (raw ordinal 22;
    // see this function's own doc comment) restricts retargeting to a live
    // entity in one of the three transport-ish categories below. Every other
    // command type retargets unconditionally.
    if (ResolveCommandIssueHelperCommandType(*helper) == static_cast<EUnitCommandType>(22)) {
      if (target.targetType == UserTargetType::Entity && target.targetEntity.HasValue()) {
        UserEntity* const targetEntity = DecodeEntityFromCommandTargetIfEntity(&target);
        const bool isEligibleEntity = targetEntity->IsInCategory(msvc8::string("FERRYBEACON", 11u)) ||
          targetEntity->IsInCategory(msvc8::string("TRANSPORTATION", 14u)) ||
          targetEntity->IsInCategory(msvc8::string("AIRSTAGINGPLATFORM", 18u));
        if (!isEligibleEntity) {
          return;
        }
      }
      // Entity link is null/tombstone, or the target isn't an Entity at all:
      // the binary falls out of the `if (*a2 == 1)`/`if (v8)`/`if (v8)` chain
      // without ever reaching the category checks or the reject, i.e. it
      // reaches the end of the function without dispatching either.
      else {
        return;
      }
    }

    // The local "set-target" event is keyed by the cookie the driver hands
    // back - `CSimDriver::SetCommandTarget` returns `mNextIssueBeat`, the beat
    // the retarget takes effect on - not by the helper's own command id. The
    // binary threads it through a hidden return buffer and feeds that same
    // dword straight into the event:
    //
    //   0x008B118C  lea   eax, [esp+9Ch+var_78]   ; return buffer
    //   0x008B1190  push  eax
    //   0x008B1191  call  edx                     ; ISTIDriver::SetCommandTarget
    //   0x008B1193  mov   eax, [esp+94h+var_78]   ; the returned cookie
    //   0x008B1199  push  esi                     ; helper
    //   0x008B119A  call  sub_8B4A40              ; queue the local event
    //
    // which is the same shape `ISSUE_DecreaseCommandCount` already uses for
    // its own `resultCookie`. Passing the command id instead put a command id
    // where the drain expects a beat.
    CmdId resultCookie = helper->mConstantData.cmd;
    if (ISTIDriver* const simDriver = WLD_GetDriver()) {
      resultCookie = simDriver->SetCommandTarget(helper->mConstantData.cmd, ConvertUserCommandTargetToSSTITarget(target));
    }
    QueueCommandIssueSetTargetEvent(*helper, resultCookie, target);
  }
} // namespace moho
namespace moho
{
  /**
   * Address: 0x008B4AC0 (FUN_008B4AC0, sub_8B4AC0)
   *
   * What it does:
   * Bridge for the recovered Sim.cpp-local `QueueCommandIssueSetTypeEvent`
   * worker (see that function's own doc comment for the full binary
   * evidence): reissues one already-queued command-issue entry's command
   * id/type in place. Exposed (declared in CWldSession.h) so
   * `UserUnit.h`'s `RestartQueuedCommandsFromHelper` - and through it the
   * mouse-drag "restart as Patrol/FormPatrol" keystone
   * (`RestartMoveCommandAsPatrol`, CWldSession.cpp) - can reissue an
   * in-flight order without owning the local ring-queue event mechanics.
   */
  void ReissueCommandIssueEntryAsType(
    UserCommandIssueHelper& helper,
    const CmdId newCmdId,
    const EUnitCommandType newCommandType
  ) noexcept
  {
    QueueCommandIssueSetTypeEvent(
      helper, newCmdId, newCommandType
    );
  }

  /**
   * Address: 0x008B58A0 (FUN_008B58A0, struct_CommandManager::struct_CommandManager)
   *
   * What it does:
   * Stands up an empty manager for one command source. Both sub-objects build
   * themselves: `IdPool` seeds its recycle history and the command map stands
   * up its own head sentinel.
   */
  CommandManager::CommandManager(const std::uint32_t sourceId)
    : mIdPool()
    , mSourceId(static_cast<std::uint8_t>(sourceId))
    , pad_0CB1_0CB4{}
    , mCommands()
  {}

  /**
   * Address: 0x008B5A70 (FUN_008B5A70, struct_CommandManager::FindDataFor /
   * struct_CommandManager::NewCommand)
   *
   * What it does:
   * Finds an existing helper for one command id or constructs and inserts a
   * new command-issue helper, then marks reused helper variable data dirty.
   *
   * Real disassembly calls `std::map_CmdId_CommandIssueHelper::find`
   * (FUN_008B6160) then, on a miss, `sub_8B5DF0` (`insert(const value_type&)`)
   * -- both cited on `rb_tree::find_node`/`insert_unique` in `RbTree.h` for
   * this `msvc8::map<CmdId, UserCommandIssueHelper*>` instantiation
   * (`CommandManager::mCommands`, `CommandManager.h`). This used to reach in
   * through a bespoke `CommandDbMapStorageView`/`CommandDbMapNodeView` pair
   * (`CommandIssueMapOf` + `FindCommandNode`/`InsertCommandNode`) that
   * hand-walked the same real member instead of calling it.
   */
  [[nodiscard]] UserCommandIssueHelper* FindOrCreateCommandIssueHelper(
    CommandManager& commandManager,
    const SSTICommandConstantData& constantData,
    const std::uint8_t deleteWhenDue,
    const std::int32_t dueSeqNo
  )
  {
    const CmdId commandId = static_cast<CmdId>(constantData.cmd);
    const auto it = commandManager.mCommands.find(commandId);
    if (it == commandManager.mCommands.end()) {
      auto* const helper = new UserCommandIssueHelper(constantData, deleteWhenDue, dueSeqNo);
      commandManager.mCommands.insert({commandId, helper});
      return helper;
    }

    UserCommandIssueHelper* const helper = it->second;
    helper->mVariableDataDirty = 1u;
    helper->mDeleteWhenDue = 0u;
    return helper;
  }

  /**
   * Address: 0x008B5C20 (FUN_008B5C20, struct_CommandManager::DeleteCommands)
   *
   * What it does:
   * Deletes command-issue helpers for each supplied command id and recycles
   * ids that belong to the manager's active source byte.
   *
   * Real disassembly calls `std::map_CmdId_CommandIssueHelper::find`
   * (FUN_008B6160, cited on `rb_tree::find_node` in `RbTree.h`) then deletes
   * the mapped helper directly -- it does not erase the node from
   * `mCommands` afterward, leaving a dangling entry behind; that is the
   * binary's own behaviour (every id passed here also gets queued for id-pool
   * recycling below, so a stale map entry never resolves to a live helper
   * again), preserved exactly rather than "fixed" with an added `.erase()`.
   */
  void DeleteCommandIssueHelpers(
    CommandManager& commandManager,
    const msvc8::vector<CmdId>& commandIds
  ) noexcept
  {
    for (const CmdId* cursor = commandIds.begin(); cursor != commandIds.end(); ++cursor) {
      const CmdId commandId = *cursor;
      const auto it = commandManager.mCommands.find(commandId);
      if (it != commandManager.mCommands.end()) {
        delete it->second;
      }

      const std::uint32_t rawCommandId = static_cast<std::uint32_t>(commandId);
      if (static_cast<std::uint8_t>(rawCommandId >> 24u) == commandManager.mSourceId) {
        commandManager.mIdPool.QueueReleasedLowId(rawCommandId & 0x00FFFFFFu);
      }
    }
  }

  /**
   * Address: 0x008B5CF0 (FUN_008B5CF0)
   *
   * What it does:
   * Advances every command-issue helper to the current beat and then ticks
   * the manager id-pool recycle history.
   *
   * Real disassembly walks `mCommands` in ascending-key order via an inlined
   * successor step (the same walk `msvc8::map`'s iterator performs through
   * `rb_increment`), calling `AdvanceLocalEventsToBeat` on each mapped helper.
   *
   * It reads the mapped helper *before* that successor step (0x008B5D08 loads
   * it, and only 0x008B5D48 calls 0x008B4C20) because a helper whose due
   * sequence has arrived destroys itself, and `~UserCommandIssueHelper`
   * (0x008B3F80) erases its own node from this map. A range-for increments
   * after the body, so it walked a freed node the moment any helper retired.
   */
  void AdvanceCommandIssueHelpersToBeat(
    CommandManager& commandManager,
    const std::int32_t beat
  ) noexcept
  {
    for (auto entry = commandManager.mCommands.begin(); entry != commandManager.mCommands.end();) {
      UserCommandIssueHelper* const helper = entry->second;
      ++entry;
      helper->AdvanceLocalEventsToBeat(beat);
    }

    commandManager.mIdPool.Update();
  }
} // namespace moho
namespace moho
{
  /**
   * Address: 0x008B4720 (FUN_008B4720, sub_8B4720)
   *
   * What it does:
   * IDA signature:
   * int __userpurge sub_8B4720@<eax>(_DWORD *ebx0@<ebx>, int a2, unsigned int a3);
   *   ebx = UserCommandIssueHelper*, a2 = CmdId, a3 = UserUnit*
   *
   * What it does:
   * Adds `unit` to the helper's newest "select unit" edit for `cmdId`,
   * queueing a fresh one first when the newest edit is anything else.
   */
  void QueueCommandIssueSelectUnitEvent(UserCommandIssueHelper* const helper, const CmdId cmdId, UserUnit* const unit)
  {
    ::QueueCommandIssueUnitEvent(*helper, cmdId, ECommandIssueEvent::SelectUnit, unit);
  }

  /**
   * Address: 0x008B4880 (FUN_008B4880, sub_8B4880)
   *
   * What it does:
   * The "deselect unit" twin of `QueueCommandIssueSelectUnitEvent`.
   */
  void QueueCommandIssueDeselectUnitEvent(UserCommandIssueHelper* const helper, const CmdId cmdId, UserUnit* const unit)
  {
    ::QueueCommandIssueUnitEvent(*helper, cmdId, ECommandIssueEvent::DeselectUnit, unit);
  }
} // namespace moho

namespace moho
{
  /**
   * Address: 0x008B0EB0 (FUN_008B0EB0)
   * Mangled: ?ISSUE_DecreaseCommandCount@Moho@@YAXPAVUserCommand@1@H@Z
   *
   * IDA signature:
   * void __usercall Moho::ISSUE_DecreaseCommandCount(
   *     int a1@<ecx>, Moho::UserCommand *a2@<edi>, int a3@<esi>);
   *
   * What it does:
   * Marshals a `DecreaseCommandCount` for `helper`'s own command id through the
   * active sim driver (`sSimDriver`, vtable +0x70 at 0x008B0EBC), then records
   * the matching local decrease-count update event against the *cookie the
   * driver returned* - not the input command id - exactly as
   * `cfunc_DeleteCommandL` (0x00843FA0) does for the Lua-facing path. The
   * binary dereferences the driver global without a null test.
   *
   * `Moho::UserCommand*` is the mangled parameter type; the object is the
   * command-issue helper (`[helper+0x04]` is `mConstantData.cmd`, and the
   * update event is appended to the helper's own local ring queue).
   */
  void ISSUE_DecreaseCommandCount(UserCommandIssueHelper* const helper, const int count)
  {
    ISTIDriver* const simDriver = WLD_GetDriver();
    const CmdId resultCookie = simDriver->DecreaseCommandCount(helper->mConstantData.cmd, count);
    QueueCommandIssueDecreaseCountEvent(*helper, resultCookie, count);
  }

  /**
   * Address: 0x008B0180 (FUN_008B0180)
   * Mangled: ?ISSUE_Command@Moho@@YAXABV?$fastvector@PAVUserUnit@Moho@@@gpg@@USSTICommandIssueData@1@_N@Z
   *
   * IDA signature:
   * void __cdecl Moho::ISSUE_Command(gpg::fastvector<UserUnit*> const& units,
   *                                 Moho::SSTICommandIssueData data, bool clearQueue);
   *
   * What it does:
   * Client/UI-side command-issue keystone. Allocates a packed command id from
   * the active session command manager, early-outs when the id's source byte is
   * the 0xFF overflow marker, gates the issue against the focus army's no-rush
   * rules (map-playable test + no-rush radius on the XZ plane), then dispatches
   * the command to the sim driver, publishes the command-issue helper (constant
   * + variable payload), enqueues it into each selected unit's command-queue
   * manager (respecting the 500-entry depth cap and the clear flag), and finally
   * notifies the UI script layer and dirties the command graph.
   */
  void ISSUE_Command(const gpg::fastvector<UserUnit*>& units, SSTICommandIssueData data, const bool clearQueue)
  {
    CWldSession* const session = WLD_GetActiveSession();

    // mManager == sWldSession->mSessionRes1 in the binary (0x008B01AD/+0x3FC).
    CommandManager* const commandManager = session->mCommandManager;

    // The playable-rect source at terrain-res +0x04 is the live STIMap in this
    // build; STIMap::IsPlayable is the concrete method dispatched at 0x008B030F.
    STIMap* const playableMap = session->mWldMap->mTerrainRes->mMap;

    // Allocate the next command id and stamp it into the issue payload.
    std::uint32_t packedCommandId = 0u;
    data.nextCommandId = static_cast<std::int32_t>(*AllocatePackedCommandIdFromManager(commandManager, &packedCommandId));
    if ((static_cast<std::uint32_t>(data.nextCommandId) & 0xFF000000u) == 0xFF000000u) {
      return; // id-pool exhausted for this command source; nothing to issue.
    }

    // No-rush / playability gate. The command is issued unless the target is a
    // concrete, valid point that violates the focus army's no-rush constraints.
    bool shouldIssue = true;
    if (data.mTarget.mType != EAiTargetType::AITARGET_None) {
      const float kInvalidLane = gpg::NaN;
      Wm3::Vec3f targetPoint{kInvalidLane, kInvalidLane, kInvalidLane};

      if (data.mTarget.mType == EAiTargetType::AITARGET_Entity) {
        if (UserEntity* const targetEntity = session->LookupEntityId(static_cast<EntId>(data.mTarget.mEnt))) {
          targetPoint = targetEntity->mVariableData.mCurTransform.pos_;
        }
        // Missing entity leaves the NaN sentinel -> IsValidVector3f() is false.
      } else {
        targetPoint = data.mTarget.mPos;
      }

      const std::int32_t focusArmyIndex = session->FocusArmy;
      if (IsValidVector3f(targetPoint) && focusArmyIndex >= 0 &&
          session->userArmies[static_cast<std::size_t>(focusArmyIndex)] != nullptr) {
        const UserArmy* const focusArmy = session->GetFocusArmy();
        const bool insidePlayableArea =
          focusArmy->mVarDat.mUseWholeMap != 0u || playableMap == nullptr || playableMap->IsPlayable(targetPoint);

        if (!insidePlayableArea) {
          shouldIssue = false;
        } else if (focusArmy->mVarDat.mNoRushTimer > 0) {
          const float deltaX = (focusArmy->mVarDat.mArmyStart.x + focusArmy->mVarDat.mNoRushOffset.x) - targetPoint.x;
          const float deltaZ = (focusArmy->mVarDat.mArmyStart.y + focusArmy->mVarDat.mNoRushOffset.y) - targetPoint.z;
          const float noRushDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (noRushDistance > focusArmy->mVarDat.mNoRushRadius) {
            shouldIssue = false;
          }
        }
      }
    }

    if (!shouldIssue) {
      return; // No-rush rejection; the by-value `data` destructs on return.
    }

    // The driver returns the beat that acknowledges this issue. Queue edits
    // and the helper's retirement use that beat (0x008B0405/0x008B0451),
    // while the published command keeps its packed source/id identity.
    BVSet<EntId, EntIdUniverse> issuedEntitySet{};
    func_DecodeEntIdSet(issuedEntitySet, units);

    const CmdId issueBeat = WLD_GetDriver()->IssueCommand(issuedEntitySet, data, clearQueue);

    // Publish the constant command descriptor and find/create its helper.
    SSTICommandConstantData commandConstantData{};
    InitializePublishedCommandDescriptorFromIssueData(&commandConstantData, &data);

    UserCommandIssueHelper* const commandHelper =
      FindOrCreateCommandIssueHelper(*commandManager, commandConstantData, 1u, issueBeat);

    // Overwrite the helper's variable payload from the issue data and mark dirty.
    commandHelper->mVariableData = SSTICommandVariableData(data);
    commandHelper->mVariableDataDirty = 1u;

    // Enqueue the published command into each selected unit's command manager.
    // FUN_008B0180 asm 0x008B0540-0x008B0577: the binary gates the per-unit
    // 0x008B0540-0x008B0577 gates the per-unit lane on `clearQueue`, and the
    // two queue-size branches are not the same:
    //
    //   cmp  ecx, 1F4h          ; queue size
    //   jbe  loc_8B0553
    //   cmp  [flag], 0          ; > 500 entries
    //   jz   loc_8B057C         ;   appending -> drop this unit entirely
    //   jmp  loc_8B055C         ;   replacing -> reset, then add
    //   loc_8B0553:             ; <= 500 entries
    //   cmp  [flag], 0
    //   jz   loc_8B0566         ;   appending -> add without resetting
    //   loc_8B055C: reset
    //   loc_8B0566: add
    //
    // That is the ~500-order queue cap: a command that replaces the queue
    // always goes through because it wipes it first, one that appends is
    // refused. Read as a constant "a command was issued" the >500 branch
    // becomes byte-identical to the other one and the cap does nothing, so
    // the flag the binary tests here is `clearQueue`.
    //
    // The same flag is what 0x008B058A hands to `UI_OnCommandIssued`, and the
    // UI contract needs it: `commandmode.lua:OnCommandIssued` ends command
    // mode on exactly `command.Clear` (identically in all three shipped
    // variants - lua.nx2, lua.nx5 and faforever.faf). Notifying `true`
    // unconditionally tore down build mode on the first structure of a
    // shift-held run, so every further placement needed another trip to the
    // construction panel - even though this call already had the right
    // answer: the run's own log shows twenty `BuildMobile` orders issued with
    // `clear=0` while the notification said otherwise.
    for (UserUnit* const unit : units) {
      UserCommandQueue* const unitManager = unit->GetCommandQueue();
      if (unitManager == nullptr) {
        continue;
      }

      if (GetUserUnitManagerQueueSize(unitManager) > 500 && !clearQueue) {
        continue;
      }

      if (clearQueue) {
        ResetUserUnitManagerState(unitManager, issueBeat);
      }
      // The add's last argument is `data.mIndex` (`[esp+0x148]`, i.e. data+0x08
      // once LTCG's `units, clearQueue, data` stack order is accounted for),
      // not the clear flag; -1 appends.
      UserUnitManagerAdd(unitManager, commandHelper, issueBeat, data.mIndex);
    }

    UI_OnCommandIssued(units, data, clearQueue);
    session->DirtyCommandGraph();
  }
} // namespace moho

