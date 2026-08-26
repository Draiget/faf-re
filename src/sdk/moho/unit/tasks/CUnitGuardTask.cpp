#include "moho/unit/tasks/CUnitGuardTask.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitAttackTargetTask.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"
#include "moho/unit/tasks/CFactoryBuildTask.h"
#include "moho/unit/tasks/CUnitFerryTask.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"
#include "moho/unit/tasks/CUnitMoveTask.h"
#include "moho/unit/tasks/CUnitRepairTask.h"
#include "moho/unit/tasks/CUnitUpgradeTask.h"

namespace moho
{
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  /**
   * VFTABLE: 0x00E20510 (`??_7CUnitGuardTaskSerializer@Moho@@6B@`)
   * Also installed as: 0x00E20518 (`??_7?$SerSaveLoadHelper@VCUnitGuardTask@Moho@@@gpg@@6B@`)
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CUnitGuardTask>
   *
   * Binary layout: vtable@0x00 (`gpg::SerHelperBase`), intrusive link pair
   * @0x04-0x0B (`moho::TDatListItem`, inherited via `SerHelperBase`),
   * load/save callback lanes@0x0C-0x13. Total 0x14 bytes.
   */
  class CUnitGuardTaskSerializerHelper : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD0BB0 (FUN_00BD0BB0, dynamic initializer for the global
     * `CUnitGuardTaskSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields and installs process-exit
     * cleanup via `atexit`.
     */
    CUnitGuardTaskSerializerHelper();

    /**
     * Address: 0x006148A0 (FUN_006148A0, gpg::SerSaveLoadHelper<Moho::CUnitGuardTask>::Init)
     *
     * What it does:
     * Resolves `CUnitGuardTask` RTTI and installs this helper's load/save
     * callbacks into the reflected type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };
  static_assert(
    offsetof(CUnitGuardTaskSerializerHelper, mLoadCallback) == 0x0C,
    "CUnitGuardTaskSerializerHelper::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitGuardTaskSerializerHelper, mSaveCallback) == 0x10,
    "CUnitGuardTaskSerializerHelper::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitGuardTaskSerializerHelper) == 0x14, "CUnitGuardTaskSerializerHelper size must be 0x14"
  );

  CUnitGuardTaskSerializerHelper gCUnitGuardTaskSerializer;

  void DeserializeCUnitGuardTaskSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<moho::CUnitGuardTask*>(static_cast<std::uintptr_t>(objectPtr))->MemberDeserialize(archive);
  }

  void SerializeCUnitGuardTaskSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<const moho::CUnitGuardTask*>(static_cast<std::uintptr_t>(objectPtr))->MemberSerialize(archive);
  }

  /**
   * Address: 0x00611090 (FUN_00611090)
   *
   * What it does:
   * Unlinks `CUnitGuardTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  void UnlinkCUnitGuardTaskSerializerNodePrimary()
  {
    gCUnitGuardTaskSerializer.ResetLinks();
  }

  /**
   * Address: 0x006110C0 (FUN_006110C0)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitGuardTaskSerializer` helper storage.
   */
  // Address 0x006110C0 (the "Secondary" unlink/self-link duplicate formerly
  // modeled here) is dead: zero data_refs/call_edges and no source-level
  // caller anywhere in src/sdk/**. UnlinkCUnitGuardTaskSerializerNodePrimary
  // above is the real body -- cleanup_CUnitGuardTaskSerializer_atexit below
  // calls it directly, and that cleanup function is atexit-registered from
  // the ctor.

  void cleanup_CUnitGuardTaskSerializer_atexit()
  {
    UnlinkCUnitGuardTaskSerializerNodePrimary();
  }

  CUnitGuardTaskSerializerHelper::CUnitGuardTaskSerializerHelper()
    : mLoadCallback(&DeserializeCUnitGuardTaskSerializerCallback)
    , mSaveCallback(&SerializeCUnitGuardTaskSerializerCallback)
  {
    (void)std::atexit(&cleanup_CUnitGuardTaskSerializer_atexit);
  }

  void CUnitGuardTaskSerializerHelper::Init()
  {
    gpg::RType* type = moho::CUnitGuardTask::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CUnitGuardTask));
      moho::CUnitGuardTask::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace

namespace
{
  constexpr std::uint64_t kUnitStateMoveAbortMask = 0x80000000ull;

  struct SNavGoalTailDwordQuadRuntimeView
  {
    std::int32_t maxX; // +0x00
    std::int32_t maxZ; // +0x04
    std::int32_t aux0; // +0x08
    std::int32_t aux1; // +0x0C
  };
  static_assert(sizeof(SNavGoalTailDwordQuadRuntimeView) == 0x10, "SNavGoalTailDwordQuadRuntimeView size must be 0x10");

  /**
   * Address: 0x00610E60 (FUN_00610E60)
   *
   * What it does:
   * Stores one primary-command weak-owner link-slot lane from a guard task.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* StoreGuardTaskPrimaryCommandOwnerLinkSlot(
    std::uint32_t* const outWord,
    const moho::CUnitGuardTask* const guardTask
  ) noexcept
  {
    if (outWord == nullptr || guardTask == nullptr) {
      return outWord;
    }

    *outWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(guardTask->mPrimaryCommandRef.ownerLinkSlot));
    return outWord;
  }

  /**
   * Address: 0x00610EB0 (FUN_00610EB0)
   *
   * What it does:
   * Copies one four-dword `SNavGoal` tail lane (`maxX/maxZ/aux0/aux1`) into
   * caller-provided storage.
   */
  [[maybe_unused]] [[nodiscard]] SNavGoalTailDwordQuadRuntimeView* CopySNavGoalTailDwordQuad(
    SNavGoalTailDwordQuadRuntimeView* const outGoalTail,
    const moho::SNavGoal* const sourceGoal
  ) noexcept
  {
    if (outGoalTail == nullptr || sourceGoal == nullptr) {
      return outGoalTail;
    }

    outGoalTail->maxX = sourceGoal->maxX;
    outGoalTail->maxZ = sourceGoal->maxZ;
    outGoalTail->aux0 = sourceGoal->aux0;
    outGoalTail->aux1 = sourceGoal->aux1;
    return outGoalTail;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrCUnitCommandType()
  {
    gpg::RType* type = moho::WeakPtr<moho::CUnitCommand>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      moho::WeakPtr<moho::CUnitCommand>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCAiTargetType()
  {
    gpg::RType* type = moho::CAiTarget::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiTarget));
      moho::CAiTarget::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSNavGoalType()
  {
    gpg::RType* type = moho::SNavGoal::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = type;
    }
    return type;
  }

  [[nodiscard]] const moho::RUnitBlueprint* ResolveUnitBlueprintFromCommand(const moho::CUnitCommand* const command)
  {
    if (command == nullptr || command->mConstDat.blueprint == nullptr) {
      return nullptr;
    }

    return static_cast<const moho::RUnitBlueprint*>(command->mConstDat.blueprint);
  }

  [[nodiscard]] bool IsShieldFocusDamaged(moho::Unit* const unit)
  {
    if (unit == nullptr || !unit->RunScriptBool("ShieldIsOn") || !unit->IsInCategory("SHIELD")) {
      return false;
    }

    moho::Entity* const shieldEntity = unit->GetFocusEntity();
    return shieldEntity != nullptr && shieldEntity->Health < shieldEntity->MaxHealth;
  }

  [[nodiscard]] bool NeedsAssistOrRepairDispatch(moho::Unit* const unit)
  {
    if (unit == nullptr) {
      return false;
    }

    if (unit->IsBeingBuilt() || unit->Health < unit->MaxHealth) {
      return true;
    }

    if (IsShieldFocusDamaged(unit)) {
      return true;
    }

    if (!unit->IsPaused && unit->IsUnitState(moho::UNITSTATE_Enhancing)) {
      return true;
    }

    return !unit->IsPaused && unit->AiSiloBuild != nullptr && unit->IsUnitState(moho::UNITSTATE_SiloBuildingAmmo);
  }

  [[nodiscard]] moho::Unit* ResolveGuardFocusAssistTarget(moho::Unit* const unit, const moho::Unit* const ownerUnit)
  {
    if (unit == nullptr || ownerUnit == nullptr) {
      return nullptr;
    }

    moho::Entity* const focusEntity = unit->GetFocusEntity();
    if (focusEntity == nullptr || unit->IsUnitState(moho::UNITSTATE_Reclaiming)) {
      return nullptr;
    }

    moho::Unit* const focusUnit = focusEntity->IsUnit();
    if (focusUnit == nullptr) {
      return nullptr;
    }

    const bool enemyFocus = focusUnit->ArmyRef != ownerUnit->ArmyRef;
    if (enemyFocus || NeedsAssistOrRepairDispatch(focusUnit)) {
      return focusUnit;
    }

    return nullptr;
  }

  [[nodiscard]] float DistanceSquared(const Wm3::Vector3f& lhs, const Wm3::Vector3f& rhs)
  {
    const float deltaX = lhs.x - rhs.x;
    const float deltaY = lhs.y - rhs.y;
    const float deltaZ = lhs.z - rhs.z;
    return (deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ);
  }

  [[nodiscard]] moho::Unit* ResolveRefuelPlatform(moho::Unit* const unit)
  {
    if (unit == nullptr) {
      return nullptr;
    }

    if (moho::Unit* const stagingPlatform = unit->GetStagingPlatform(); stagingPlatform != nullptr) {
      return stagingPlatform;
    }

    moho::Unit* const assignedTransport = unit->AssignedTransportRef.ResolveObjectPtr<moho::Unit>();
    if (assignedTransport == nullptr || assignedTransport->IsDead() || assignedTransport->DestroyQueued()) {
      return nullptr;
    }

    const moho::IAiTransport* const transport = assignedTransport->AiTransport;
    if (transport == nullptr || !transport->TransportIsAirStagingPlatform()) {
      return nullptr;
    }

    return assignedTransport;
  }

  void UpdateQueuedCommandTarget(
    moho::CUnitCommandQueue* const commandQueue,
    const int commandIndex,
    moho::Entity* const targetEntity
  )
  {
    if (commandQueue == nullptr || commandIndex < 0) {
      return;
    }

    commandQueue->SetCommandTarget(static_cast<unsigned int>(commandIndex), targetEntity);
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitGuardTask::sType = nullptr;

  /**
   * Address: 0x00614D50 (FUN_00614D50)
   *
   * What it does:
   * Deserializes guard-task runtime state in binary read order: base command
   * task payload, dispatch pointer, weak links, target payload, guard-state
   * flags, secondary weak-link/direction lanes, and guard navigation goal.
   */
  void CUnitGuardTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    gpg::RRef commandTaskRef{};
    archive->ReadPointer_CCommandTask(&mCommandTask, &commandTaskRef);

    const gpg::RRef primaryCommandOwnerRef{};
    archive->Read(CachedWeakPtrCUnitCommandType(), &mPrimaryCommandRef, primaryCommandOwnerRef);

    const gpg::RRef commandOwnerRef{};
    archive->Read(CachedWeakPtrCUnitCommandType(), &mCommandRef, commandOwnerRef);

    const gpg::RRef targetOwnerRef{};
    archive->Read(CachedCAiTargetType(), &mTarget, targetOwnerRef);

    archive->ReadBool(&mTrackGuardedUnit);
    archive->ReadBool(&mRefreshGuardedUnitFromNearby);
    archive->ReadBool(&mDisableBestEnemySearch);
    archive->ReadBool(&mDisableReactionState);
    archive->ReadBool(&mPreferTransportRefuel);
    archive->ReadBool(&mAllowFerryBeaconRedirect);
    archive->ReadBool(&mUnknown7A);

    const gpg::RRef secondaryUnitOwnerRef{};
    archive->Read(CachedWeakPtrUnitType(), &mSecondaryUnit, secondaryUnitOwnerRef);

    const gpg::RRef guardDirectionOwnerRef{};
    archive->Read(CachedVector3fType(), &mGuardDirection, guardDirectionOwnerRef);

    const gpg::RRef secondaryDirectionOwnerRef{};
    archive->Read(CachedVector3fType(), &mGuardMoveAnchorPosition, secondaryDirectionOwnerRef);

    const gpg::RRef guardGoalOwnerRef{};
    archive->Read(CachedSNavGoalType(), &mGuardGoal, guardGoalOwnerRef);
  }

  /**
   * Address: 0x00614F80 (FUN_00614F80)
   *
   * What it does:
   * Serializes guard-task runtime state in binary write order: base command
   * task payload, dispatch pointer, weak links, target payload, guard-state
   * flags, secondary weak-link/direction lanes, and guard navigation goal.
   */
  void CUnitGuardTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);

    gpg::RRef commandTaskRef{};
    (void)gpg::RRef_CCommandTask(&commandTaskRef, mCommandTask);
    gpg::WriteRawPointer(archive, commandTaskRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->Write(CachedWeakPtrCUnitCommandType(), &mPrimaryCommandRef, ownerRef);
    archive->Write(CachedWeakPtrCUnitCommandType(), &mCommandRef, ownerRef);
    archive->Write(CachedCAiTargetType(), &mTarget, ownerRef);

    archive->WriteBool(mTrackGuardedUnit);
    archive->WriteBool(mRefreshGuardedUnitFromNearby);
    archive->WriteBool(mDisableBestEnemySearch);
    archive->WriteBool(mDisableReactionState);
    archive->WriteBool(mPreferTransportRefuel);
    archive->WriteBool(mAllowFerryBeaconRedirect);
    archive->WriteBool(mUnknown7A);

    archive->Write(CachedWeakPtrUnitType(), &mSecondaryUnit, ownerRef);
    archive->Write(CachedVector3fType(), &mGuardDirection, ownerRef);

    archive->Write(CachedVector3fType(), &mGuardMoveAnchorPosition, ownerRef);

    archive->Write(CachedSNavGoalType(), &mGuardGoal, ownerRef);
  }

  // Addresses 0x00614B40/0x00614B90 (the "ThunkA"/"ThunkB" serializer-save
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // `SerializeCUnitGuardTaskSerializerCallback` above (wired into
  // `CUnitGuardTaskSerializerHelper`'s ctor) already forwards into
  // `CUnitGuardTask::MemberSerialize` and is the real, atexit-registered
  // body.

  /**
   * Address: 0x006110F0 (FUN_006110F0, Moho::CUnitGuardTask::CUnitGuardTask)
   *
   * What it does:
   * Initializes guard-task command/listener lanes, clears weak references,
   * resets target payload, and zeros guard-goal rectangle state.
   */
  CUnitGuardTask::CUnitGuardTask()
    : CCommandTask()
    , CUnitGuardTaskReservedSlot()
    , Listener<ECommandEvent>()
    , mCommandTask(nullptr)
    , mPrimaryCommandRef{}
    , mCommandRef{}
    , mTarget{}
    , mTrackGuardedUnit(false)
    , mRefreshGuardedUnitFromNearby(false)
    , mDisableBestEnemySearch(false)
    , mDisableReactionState(false)
    , mPreferTransportRefuel(false)
    , mAllowFerryBeaconRedirect(false)
    , mUnknown7A(false)
    , mPad007B(0)
    , mSecondaryUnit{}
    , mGuardDirection(Wm3::Vector3f::Zero())
    , mGuardMoveAnchorPosition(Wm3::Vector3f::Zero())
    , mGuardGoal{}
  {
    mTarget.targetType = EAiTargetType::AITARGET_None;
    mTarget.targetEntity.ClearLinkState();
    mTarget.position = Wm3::Vector3f::Zero();
    mTarget.targetPoint = -1;
    mTarget.targetIsMobile = false;

    mGuardGoal.minX = 0;
    mGuardGoal.minZ = 0;
    mGuardGoal.maxX = 0;
    mGuardGoal.maxZ = 0;
    mGuardGoal.aux0 = 0;
    mGuardGoal.aux1 = 0;
    mGuardGoal.aux2 = 0;
    mGuardGoal.aux3 = 0;
    mGuardGoal.mLayer = static_cast<ELayer>(0);
  }

  namespace
  {
    struct CUnitCommandCommandEventLinkView
    {
      std::uint8_t pad_0000_0034[0x34];
      moho::Broadcaster mCommandEventListenerHead;
    };

    static_assert(
      offsetof(CUnitCommandCommandEventLinkView, mCommandEventListenerHead) == 0x34,
      "CUnitCommandCommandEventLinkView::mCommandEventListenerHead offset must be 0x34"
    );

    /**
     * Resolves the command-event broadcaster list head embedded at offset 0x34
     * of a `CUnitCommand`, used to register a guard task's command-event
     * listener on the command it is linked to.
     */
    [[nodiscard]] moho::Broadcaster* CommandEventListenerHead(moho::CUnitCommand* const command) noexcept
    {
      if (command == nullptr) {
        return nullptr;
      }

      auto* const view = reinterpret_cast<CUnitCommandCommandEventLinkView*>(command);
      return &view->mCommandEventListenerHead;
    }
  } // namespace

  /**
   * Address: 0x006111E0 (FUN_006111E0, Moho::CUnitGuardTask::CUnitGuardTask)
   *
   * IDA signature:
   * Moho::CUnitGuardTask* __thiscall Moho::CUnitGuardTask::CUnitGuardTask(
   *   Moho::IAiCommandDispatchImpl* dispatch, Moho::CUnitGuardTask* this,
   *   Moho::CAiTarget* target);
   *
   * What it does:
   * Constructs one dispatch-bound guard task. Binds the linked-command weak
   * reference to the owner's current queue-head command and registers the
   * embedded command-event listener on that command's broadcaster chain, copies
   * the guard target payload, sets the owner's Guarding state bit, refreshes the
   * guarded-unit lanes, then classifies the owner/guarded unit
   * (factory/shield/silo/engineer/no-formation) to seed the guard-behavior flags
   * and initial task state.
   */
  CUnitGuardTask::CUnitGuardTask(IAiCommandDispatchImpl* const dispatch, CAiTarget* const target)
    : CCommandTask(dispatch)
    , CUnitGuardTaskReservedSlot()
    , Listener<ECommandEvent>()
    , mCommandTask(dispatch)
    , mPrimaryCommandRef{}
    , mCommandRef{}
    , mTarget{}
    , mTrackGuardedUnit(false)
    , mRefreshGuardedUnitFromNearby(false)
    , mDisableBestEnemySearch(false)
    , mDisableReactionState(false)
    , mPreferTransportRefuel(false)
    , mAllowFerryBeaconRedirect(false)
    , mUnknown7A(false)
    , mPad007B(0)
    , mSecondaryUnit{}
    , mGuardDirection(Wm3::Vector3f::Zero())
    , mGuardMoveAnchorPosition(Wm3::Vector3f::Zero())
    , mGuardGoal{}
  {
    Listener<ECommandEvent>::mListenerLink.ListResetLinks();

    // Copy the guard target payload, link-inserting the target entity into its
    // owner chain (matches the binary's field-by-field target copy).
    mTarget.targetType = target->targetType;
    mTarget.targetEntity.ResetFromObject(target->targetEntity.GetObjectPtr());
    mTarget.position = target->position;
    mTarget.targetPoint = target->targetPoint;
    mTarget.targetIsMobile = target->targetIsMobile;

    mGuardGoal.minX = 0;
    mGuardGoal.minZ = 0;
    mGuardGoal.maxX = 0;
    mGuardGoal.maxZ = 0;
    mGuardGoal.aux0 = 0;
    mGuardGoal.aux1 = 0;
    mGuardGoal.aux2 = 0;
    mGuardGoal.aux3 = 0;
    mGuardGoal.mLayer = static_cast<ELayer>(0);

    Unit* const unit = mUnit;
    unit->UnitStateMask |= (1ull << UNITSTATE_Guarding);

    // Bind the linked-command weak reference to the owner's current queue-head
    // command, then register this task's embedded command-event listener on that
    // command's broadcaster chain.
    CUnitCommand* headCommand = nullptr;
    if (CUnitCommandQueue* const commandQueue = unit->CommandQueue;
        commandQueue != nullptr && commandQueue->mCommandVec.size() > 0u) {
      headCommand = commandQueue->mCommandVec[0].GetObjectPtr();
    }
    mCommandRef.ResetFromObject(headCommand);
    if (CUnitCommand* const linkedCommand = mCommandRef.GetObjectPtr(); linkedCommand != nullptr) {
      if (Broadcaster* const commandListenerHead = CommandEventListenerHead(linkedCommand);
          commandListenerHead != nullptr) {
        Listener<ECommandEvent>::mListenerLink.ListLinkBefore(commandListenerHead);
      }
    }

    RefreshGuardedUnitFromTarget();

    // A being-built or upgrading guarded unit that is not itself a
    // factory/shield/silo/mobile structure flags the "guarded unit is under
    // construction" behavior lane.
    if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr(); guardedUnit != nullptr) {
      if (guardedUnit->IsBeingBuilt() || guardedUnit->IsUnitState(UNITSTATE_Upgrading)) {
        const bool guardedIsStructureType = guardedUnit->IsInCategory("FACTORY") ||
          guardedUnit->IsInCategory("SHIELD") || guardedUnit->IsInCategory("SILO") ||
          guardedUnit->IsMobile();
        if (!guardedIsStructureType) {
          mUnknown7A = true;
        }
      }
    }

    // Immobile owners that must unpack before acting drop any desired attack
    // target so the guard task takes exclusive control.
    if (unit->IsUnitState(UNITSTATE_Immobile)) {
      if (unit->GetBlueprint()->AI.NeedUnpack) {
        if (CAiAttackerImpl* const attacker = unit->AiAttacker; attacker != nullptr) {
          CAiTarget clearedTarget{};
          clearedTarget.targetPoint = -1;
          clearedTarget.targetIsMobile = false;
          attacker->SetDesiredTarget(&clearedTarget);
        }
      }
    }

    mTaskState = TASKSTATE_Processing;

    // No-formation owners and transport-refuel guards skip the structure-role
    // classification below.
    if (mPreferTransportRefuel || unit->IsInCategory("NOFORMATION")) {
      return;
    }

    // Immobile factory owners refresh their guarded unit from nearby scans.
    if (unit->IsInCategory("FACTORY") && !unit->IsMobile()) {
      mRefreshGuardedUnitFromNearby = true;
      return;
    }

    // Engineer owners only continue when a guarded unit is present.
    if (!unit->IsInCategory("ENGINEER") || mSecondaryUnit.GetObjectPtr() == nullptr) {
      return;
    }

    // An engineer guarding an engineer suppresses the reaction state.
    if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
        guardedUnit != nullptr && guardedUnit->IsInCategory("ENGINEER")) {
      mDisableReactionState = true;
      return;
    }

    // An engineer guarding a factory prepares before acting and suppresses the
    // best-enemy search.
    if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
        guardedUnit != nullptr && guardedUnit->IsInCategory("FACTORY")) {
      mTaskState = TASKSTATE_Preparing;
      mDisableBestEnemySearch = true;
    }
  }

  /**
   * Address: 0x006147F0 (FUN_006147F0, Moho::CUnitGuardTask::operator new)
   *
   * IDA signature:
   * Moho::CUnitGuardTask* __cdecl Moho::CUnitGuardTask::operator new(
   *   Moho::IAiCommandDispatchImpl* dispatch, Moho::CAiTarget* target);
   *
   * What it does:
   * Allocates one guard-task object (0xC0 bytes) and, on success, forwards the
   * dispatch/target arguments into in-place construction.
   */
  CUnitGuardTask* CUnitGuardTask::Create(IAiCommandDispatchImpl* const dispatch, CAiTarget* const target)
  {
    void* const storage = ::operator new(sizeof(CUnitGuardTask));
    if (storage == nullptr) {
      return nullptr;
    }

    return ::new (storage) CUnitGuardTask(dispatch, target);
  }

  /**
   * Address: 0x00611850 (FUN_00611850, ??1CUnitGuardTask@Moho@@QAE@@Z)
   * Address: 0x006111C0 (FUN_006111C0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * IDA signature:
   * void __thiscall Moho::CUnitGuardTask::~CUnitGuardTask(Moho::CUnitGuardTask *this);
   *
   * What it does:
   * Clears owner unit guard/guard-busy state bits, drops the guarded-unit
   * association, zeros the unit's guarded-position lane, detaches the embedded
   * command-event listener from the linked command's broadcaster chain when
   * bound, releases any rebuild-structure bookkeeping on the owner builder,
   * frees the reserved ogrid footprint when one is held, dispatches one
   * navigator move-abort plus speed-through refresh when the unit moved this
   * tick, and unlinks the secondary-unit / target-entity / primary / linked
   * weak-command lanes before tearing down the embedded command-task base
   * slice.
   */
  CUnitGuardTask::~CUnitGuardTask()
  {
    if (Unit* const unit = mUnit; unit != nullptr) {
      // Drop the two guard-state bits this task owns on the owner unit.
      unit->UnitStateMask &= ~(1ull << UNITSTATE_GuardBusy);
      unit->UnitStateMask &= ~(1ull << UNITSTATE_Guarding);

      // Release the guarded-unit association and zero the cached guard pos.
      unit->SetGuardedUnit(nullptr);
      unit->GuardedPos = Wm3::Vector3f::Zero();
    }

    // If we still hold a linked command, detach the embedded command-event
    // listener from that command's broadcaster chain. The compiler inlines
    // both the unlink-from-ring and the self-link-reset.
    if (mCommandRef.GetObjectPtr() != nullptr) {
      Listener<ECommandEvent>::mListenerLink.ListUnlink();
    }

    if (Unit* const unit = mUnit; unit != nullptr) {
      if (IAiBuilder* const builder = unit->AiBuilder; builder != nullptr) {
        // Slot 21 on IAiBuilder — finalise any rebuild-structure bookkeeping
        // (decompiler synonym "ClearBuilding").
        builder->BuilderClearRebuildStructure();
      }

      // Release the ogrid footprint reservation when a guard move-anchor was
      // staked (non-zero indicates an active reservation). Compare uses the
      // engine's 1e-5 epsilon, matching binary semantics.
      const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
      if (Wm3::Vector3f::Compare(&mGuardMoveAnchorPosition, &zero)) {
        unit->FreeOgridRect();
      }

      if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
        // Issue one navigator-side abort iff the unit moved this tick.
        if (Wm3::Vector3f::Compare(&unit->Position, &unit->PrevPosition)) {
          navigator->AbortMove();
        }
        unit->UpdateSpeedThroughStatus();
      }
    }

    // Reverse-declaration-order weak-pointer teardown emitted explicitly in
    // the binary: mSecondaryUnit (+0x7C) → mTarget.targetEntity (+0x58) →
    // mCommandRef (+0x4C) → mPrimaryCommandRef (+0x44). The non-targetEntity
    // WeakPtr<T> generic destructor is trivial in our recovered template, so
    // each owner-chain detach is explicit here. CAiTarget's compiler-emitted
    // member destructor will redundantly attempt mTarget.targetEntity unlink
    // after this body returns; the second call is a safe no-op once the slot
    // is cleared below.
    mSecondaryUnit.UnlinkFromOwnerChain();
    mTarget.targetEntity.UnlinkFromOwnerChain();
    mTarget.targetEntity.ClearLinkState();
    mCommandRef.UnlinkFromOwnerChain();
    mPrimaryCommandRef.UnlinkFromOwnerChain();

    // Embedded Listener<ECommandEvent> sub-object teardown: detach the
    // listener-link from whatever ring it sits in (typically already
    // self-linked after the conditional unlink above) and reset to singleton.
    Listener<ECommandEvent>::mListenerLink.ListUnlink();
  }

  /**
   * Address: 0x00611A40 (FUN_00611A40)
   *
   * What it does:
   * Refreshes guarded-unit weak lanes and guard direction from current target
   * payload, including transport/refuel/ferry preference flags.
   */
  void CUnitGuardTask::RefreshGuardedUnitFromTarget()
  {
    if (Entity* const targetEntity = mTarget.GetEntity(); targetEntity != nullptr) {
      if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
        bool shouldBindGuardedUnit = true;
        if (!targetUnit->IsDead() && mUnit != nullptr && mUnit->IsInCategory("REBUILDER")) {
          shouldBindGuardedUnit = false;
        }

        if (shouldBindGuardedUnit) {
          mTrackGuardedUnit = true;
          mSecondaryUnit.Set(targetUnit);

          if (mUnit != nullptr && mUnit->IsInCategory("TRANSPORTATION")) {
            const bool isStationaryFactoryBuilder =
              targetUnit->IsInCategory("FACTORY")
              && targetUnit->AiBuilder != nullptr
              && !targetUnit->IsMobile();

            if (isStationaryFactoryBuilder) {
              mPreferTransportRefuel = true;
            } else if (targetUnit->IsInCategory("TRANSPORTATION") || targetUnit->IsInCategory("FERRYBEACON")) {
              mAllowFerryBeaconRedirect = true;
            }
          }

          if (mUnit != nullptr) {
            mUnit->SetGuardedUnit(mSecondaryUnit.GetObjectPtr());
          }
        }
      }
    }

    const Wm3::Vector3f targetPosition = mTarget.GetTargetPosGun(false);
    mGuardDirection = targetPosition;
    if (mUnit != nullptr) {
      mUnit->GuardedPos = targetPosition;
    }
  }

  /**
   * Address: 0x006147B0 (FUN_006147B0, Moho::CUnitGuardTask::OnEvent)
   *
   * What it does:
   * See the header declaration for the full behavior summary.
   */
  void CUnitGuardTask::OnEvent(const ECommandEvent /*event*/)
  {
    CUnitCommand* const linkedCommand = mCommandRef.GetObjectPtr();
    if (linkedCommand == nullptr) {
      return;
    }

    mTarget = linkedCommand->mTarget;
    RefreshGuardedUnitFromTarget();
  }

  /**
   * Address: 0x00611CD0 (FUN_00611CD0)
   *
   * What it does:
   * Walks the guarded-unit chain and chooses the unit that should source
   * guard-follow-up commands while avoiding previously visited units.
   */
  Unit* CUnitGuardTask::ResolveGuardCommandSourceUnit(
    Unit* guardedUnit,
    SEntitySetTemplateUnit& visitedUnits
  ) const
  {
    Unit* candidate = guardedUnit;
    if (candidate == nullptr) {
      return mUnit;
    }

    while (true) {
      if (visitedUnits.ContainsUnit(candidate)) {
        return mUnit;
      }

      CUnitCommandQueue* const commandQueue = candidate->CommandQueue;
      if (commandQueue == nullptr) {
        break;
      }

      const std::size_t commandCount = commandQueue->mCommandVec.size();
      const bool useCandidate =
        (candidate == mUnit && commandCount > 0u)
        || (commandCount > 1u)
        || (commandCount > 0u && candidate->RepeatQueueEnabled);
      if (useCandidate) {
        return candidate;
      }

      (void)visitedUnits.AddUnit(candidate);
      candidate = candidate->GetGuardedUnit();
      if (candidate == nullptr) {
        return mUnit;
      }
    }

    return mUnit;
  }

  /**
   * Address: 0x00611DA0 (FUN_00611DA0)
   *
   * What it does:
   * Computes and reserves one guard move-anchor world position when the
   * cached move-anchor lane is still zero, then returns that lane.
   */
  Wm3::Vector3f CUnitGuardTask::EnsureReservedGuardMoveAnchorPosition()
  {
    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (!Wm3::Vector3f::Compare(&mGuardMoveAnchorPosition, &zero)) {
      if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr(); guardedUnit != nullptr) {
        mGuardMoveAnchorPosition = guardedUnit->GetPosition();

        const SCoordsVec2 guardedPos2d{mGuardMoveAnchorPosition.x, mGuardMoveAnchorPosition.z};
        gpg::Rect2f guardedSkirt = guardedUnit->GetBlueprint()->GetSkirtRect(guardedPos2d);
        const bool useWholeMap = (mUnit != nullptr && mUnit->ArmyRef != nullptr) ? mUnit->ArmyRef->UseWholeMap() : false;
        if (mUnit != nullptr) {
          (void)PrepareMove(0, mUnit, &mGuardMoveAnchorPosition, &guardedSkirt, useWholeMap);
        }
      }

      if (mUnit != nullptr) {
        const SFootprint& footprint = mUnit->GetFootprint();
        const float reserveX0f = mGuardMoveAnchorPosition.x - static_cast<float>(footprint.mSizeX) * 0.5f;
        const float reserveZ0f = mGuardMoveAnchorPosition.z - static_cast<float>(footprint.mSizeZ) * 0.5f;

        gpg::Rect2i reserveRect{};
        reserveRect.x0 = static_cast<std::int16_t>(static_cast<int>(reserveX0f));
        reserveRect.z0 = static_cast<std::int16_t>(static_cast<int>(reserveZ0f));
        reserveRect.x1 = reserveRect.x0 + static_cast<int>(footprint.mSizeX);
        reserveRect.z1 = reserveRect.z0 + static_cast<int>(footprint.mSizeZ);
        mUnit->ReserveOgridRect(reserveRect);
      }
    }

    return mGuardMoveAnchorPosition;
  }

  /**
   * Address: 0x00611F30 (FUN_00611F30)
   *
   * What it does:
   * Resolves one rebuilder guard anchor from queued guard commands, caches it
   * into the secondary guard-anchor lane, and reserves owner ogrid space.
   */
  Wm3::Vector3f CUnitGuardTask::ResolveRebuilderGuardQueueAnchorPosition()
  {
    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (!Wm3::Vector3f::Compare(&mGuardMoveAnchorPosition, &zero)) {
      if (mUnit == nullptr) {
        return mGuardMoveAnchorPosition;
      }

      const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
      Wm3::Vector3f nearestGuardTarget = zero;
      float nearestDistance = std::numeric_limits<float>::infinity();

      if (CUnitCommandQueue* const commandQueue = mUnit->CommandQueue; commandQueue != nullptr) {
        const std::size_t commandCount = commandQueue->mCommandVec.size();
        for (std::size_t index = 0; index < commandCount; ++index) {
          CUnitCommand* const command = commandQueue->mCommandVec[index].GetObjectPtr();
          if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Guard) {
            continue;
          }

          const Wm3::Vector3f targetPosition = command->mTarget.GetTargetPosGun(false);
          const float deltaX = targetPosition.x - ownerPosition.x;
          const float deltaZ = targetPosition.z - ownerPosition.z;
          const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
          if (distance < nearestDistance) {
            nearestDistance = distance;
            nearestGuardTarget = targetPosition;
          }
        }
      }

      if (Wm3::Vector3f::Compare(&nearestGuardTarget, &zero)) {
        mGuardMoveAnchorPosition = nearestGuardTarget;

        gpg::Rect2f guardSkirt{};
        const bool useWholeMap = (mUnit->ArmyRef != nullptr) ? mUnit->ArmyRef->UseWholeMap() : false;
        (void)PrepareMove(0, mUnit, &mGuardMoveAnchorPosition, &guardSkirt, useWholeMap);

        const SFootprint& footprint = mUnit->GetFootprint();
        const float reserveX0 = mGuardMoveAnchorPosition.x - static_cast<float>(footprint.mSizeX) * 0.5f;
        const float reserveZ0 = mGuardMoveAnchorPosition.z - static_cast<float>(footprint.mSizeZ) * 0.5f;
        gpg::Rect2i reserveRect{};
        reserveRect.x0 = static_cast<std::int16_t>(static_cast<int>(reserveX0));
        reserveRect.z0 = static_cast<std::int16_t>(static_cast<int>(reserveZ0));
        reserveRect.x1 = reserveRect.x0 + static_cast<int>(footprint.mSizeX);
        reserveRect.z1 = reserveRect.z0 + static_cast<int>(footprint.mSizeZ);
        mUnit->ReserveOgridRect(reserveRect);
      }
    }

    return mGuardMoveAnchorPosition;
  }

  /**
   * Address: 0x00612220 (FUN_00612220)
   *
   * What it does:
   * Resolves the current guard reference world position from guarded-unit,
   * rebuilder queue, or queue-head command lanes.
   */
  Wm3::Vector3f CUnitGuardTask::ResolveGuardReferencePosition()
  {
    if (mUnit == nullptr) {
      return mGuardDirection;
    }

    if (mTrackGuardedUnit) {
      if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr(); guardedUnit != nullptr) {
        if (mUnit->IsInCategory("ENGINEER")) {
          return EnsureReservedGuardMoveAnchorPosition();
        }

        if (guardedUnit->GuardFormation != nullptr) {
          if (mUnit->mIsAir) {
            return guardedUnit->GetPosition();
          }
          return mUnit->mInfoCache.mFormationHeadingHint;
        }

        if (guardedUnit->IsIdleState()) {
          return mUnit->GetPosition();
        }
      }
    } else if (mUnit->AiBuilder != nullptr && mUnit->IsInCategory("REBUILDER")) {
      return ResolveRebuilderGuardQueueAnchorPosition();
    }

    if (CUnitCommandQueue* const commandQueue = mUnit->CommandQueue;
        commandQueue != nullptr && commandQueue->mCommandVec.size() > 0u) {
      if (CUnitCommand* const headCommand = commandQueue->mCommandVec[0].GetObjectPtr();
          headCommand != nullptr && mUnit->SimulationRef != nullptr && mUnit->SimulationRef->mMapData != nullptr) {
        SOCellPos commandCell{};
        if (const SOCellPos* const headCell = CUnitCommand::GetPosition(headCommand, mUnit, &commandCell);
            headCell != nullptr) {
          const SFootprint& footprint = mUnit->GetFootprint();
          return COORDS_ToWorldPos(
            mUnit->SimulationRef->mMapData,
            *headCell,
            static_cast<ELayer>(footprint.mOccupancyCaps),
            footprint.mSizeX,
            footprint.mSizeZ
          );
        }
      }
    }

    return mGuardDirection;
  }

  /**
   * Address: 0x00612480 (FUN_00612480)
   *
   * What it does:
   * Returns whether owner distance to the current guard reference position
   * exceeds guarded-footprint threshold plus `extraRange`.
   */
  bool CUnitGuardTask::IsOutsideGuardReferenceRange(const float extraRange)
  {
    if (mUnit == nullptr) {
      return false;
    }

    float guardedExtentThreshold = 1.0f;
    if (mTrackGuardedUnit) {
      if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr(); guardedUnit != nullptr) {
        const SFootprint& guardedFootprint = guardedUnit->GetFootprint();
        guardedExtentThreshold =
          static_cast<float>(std::max(static_cast<int>(guardedFootprint.mSizeX), static_cast<int>(guardedFootprint.mSizeZ)));
      }
    }

    const Wm3::Vector3f guardReferencePosition = ResolveGuardReferencePosition();
    const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
    const float deltaX = ownerPosition.x - guardReferencePosition.x;
    const float deltaY = ownerPosition.y - guardReferencePosition.y;
    const float deltaZ = ownerPosition.z - guardReferencePosition.z;
    const float distance = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));
    return distance > guardedExtentThreshold + extraRange;
  }

  /**
   * Address: 0x00612560 (FUN_00612560)
   *
   * What it does:
   * Returns whether owner footprint-min cell lies inside one goal rectangle
   * bounds.
   */
  bool CUnitGuardTask::IsOwnerCellInsideGoalBounds(const SNavGoal& goal) const
  {
    if (mUnit == nullptr) {
      return false;
    }

    const SFootprint& footprint = mUnit->GetFootprint();
    const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
    const int ownerMinZ = static_cast<int>(ownerPosition.z - static_cast<float>(footprint.mSizeZ) * 0.5f);
    const int ownerMinX = static_cast<int>(ownerPosition.x - static_cast<float>(footprint.mSizeX) * 0.5f);

    const std::int16_t ownerCellMinX = static_cast<std::int16_t>(ownerMinX);
    const std::int16_t ownerCellMinZ = static_cast<std::int16_t>(ownerMinZ);
    return goal.minX <= ownerCellMinX && goal.maxX >= ownerCellMinX && goal.minZ <= ownerCellMinZ
      && goal.maxZ >= ownerCellMinZ;
  }

  /**
   * Address: 0x00610E00 (FUN_00610E00)
   *
   * What it does:
   * Compares the primary goal rectangle bounds lanes (`min/max X/Z`) for
   * exact equality.
   */
  bool CUnitGuardTask::IsSameGoalBounds(const SNavGoal& lhs, const SNavGoal& rhs)
  {
    return rhs.minX == lhs.minX && rhs.maxX == lhs.maxX && rhs.minZ == lhs.minZ && rhs.maxZ == lhs.maxZ;
  }

  /**
   * Address: 0x00613C40 (FUN_00613C40)
   *
   * What it does:
   * Updates guard-follow movement goal state, including move-target
   * preparation/clamping and navigator-goal submission gates.
   */
  void CUnitGuardTask::UpdateGuardFollowMoveGoal()
  {
    if (mUnit == nullptr || !mUnit->IsMobile()) {
      return;
    }

    Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
    const bool engineerWithGuardedUnit = mUnit->IsInCategory("ENGINEER") && guardedUnit != nullptr;
    if (engineerWithGuardedUnit) {
      const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
      const bool guardedUnitMoving = Wm3::Vector3f::Compare(&guardedUnit->Position, &guardedUnit->PrevPosition);
      const bool hasReservedAnchor = Wm3::Vector3f::Compare(&mGuardMoveAnchorPosition, &zero);
      const Wm3::Vector3f guardedPosition = guardedUnit->GetPosition();

      float deltaX = 0.0f;
      float deltaZ = 0.0f;
      if (guardedUnitMoving && hasReservedAnchor) {
        deltaX = mGuardMoveAnchorPosition.x - guardedPosition.x;
        deltaZ = mGuardMoveAnchorPosition.z - guardedPosition.z;
      } else {
        const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
        deltaX = ownerPosition.x - guardedPosition.x;
        deltaZ = ownerPosition.z - guardedPosition.z;
      }

      const float guardedDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
      if (ownerBlueprint != nullptr && ownerBlueprint->Economy.MaxBuildDistance * 2.0f > guardedDistance) {
        return;
      }

      if (hasReservedAnchor) {
        mGuardMoveAnchorPosition = zero;
        mUnit->FreeOgridRect();
      }
    }

    Wm3::Vector3f desiredPosition = ResolveGuardReferencePosition();

    gpg::Rect2f guardedSkirt{};
    if (guardedUnit != nullptr) {
      const Wm3::Vector3f guardedPosition = guardedUnit->GetPosition();
      const SCoordsVec2 guardedPos2d{guardedPosition.x, guardedPosition.z};
      guardedSkirt = guardedUnit->GetBlueprint()->GetSkirtRect(guardedPos2d);
    }

    bool clampedToPlayableRect = false;
    const bool skipPrepareMove = mUnit->mIsAir && mUnit->IsInCategory("EXPERIMENTAL");
    const bool useWholeMap = (mUnit->ArmyRef != nullptr) ? mUnit->ArmyRef->UseWholeMap() : false;
    if (!skipPrepareMove && !PrepareMove(0, mUnit, &desiredPosition, &guardedSkirt, useWholeMap)) {
      if (mUnit->SimulationRef != nullptr && mUnit->SimulationRef->mMapData != nullptr) {
        const gpg::Rect2i& playableRect = mUnit->SimulationRef->mMapData->mPlayableRect;
        desiredPosition.x = std::clamp(desiredPosition.x, static_cast<float>(playableRect.x0), static_cast<float>(playableRect.x1));
        desiredPosition.z = std::clamp(desiredPosition.z, static_cast<float>(playableRect.z0), static_cast<float>(playableRect.z1));
        clampedToPlayableRect = true;
      }
    }

    const SFootprint& footprint = mUnit->GetFootprint();
    SNavGoal proposedGoal{};
    proposedGoal.minX = static_cast<std::int16_t>(
      static_cast<int>(desiredPosition.x - static_cast<float>(footprint.mSizeX) * 0.5f)
    );
    proposedGoal.minZ = static_cast<std::int16_t>(
      static_cast<int>(desiredPosition.z - static_cast<float>(footprint.mSizeZ) * 0.5f)
    );
    proposedGoal.maxX = proposedGoal.minX + 1;
    proposedGoal.maxZ = proposedGoal.minZ + 1;

    if (IsOwnerCellInsideGoalBounds(proposedGoal)) {
      return;
    }

    IAiNavigator* const navigator = mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    const EAiNavigatorStatus navigatorStatus = navigator->GetStatus();
    if (navigatorStatus == AINAVSTATUS_Thinking) {
      return;
    }

    const Unit* const currentGuardedUnit = mSecondaryUnit.GetObjectPtr();
    const bool guardedUnitIdle = currentGuardedUnit != nullptr && currentGuardedUnit->IsIdleState();
    if (!guardedUnitIdle && navigatorStatus != AINAVSTATUS_Idle) {
      return;
    }

    if (!IsSameGoalBounds(mGuardGoal, proposedGoal) || clampedToPlayableRect || navigatorStatus != AINAVSTATUS_Steering) {
      navigator->SetGoal(proposedGoal);
      mGuardGoal = proposedGoal;
      mUnit->UpdateSpeedThroughStatus();
    }
  }

  /**
   * Address: 0x00612600 (FUN_00612600)
   *
   * What it does:
   * Evaluates engineer/pod guard-completion gates from queue-next-command and
   * guarded-unit idle state lanes.
   */
  bool CUnitGuardTask::ShouldAbortGuardForBuilderContext() const
  {
    if (mUnit == nullptr) {
      return false;
    }

    const bool isBuilderLike = mUnit->IsInCategory("ENGINEER") || mUnit->IsInCategory("POD");
    if (!isBuilderLike || mUnit->IsInCategory("REBUILDER")) {
      return false;
    }

    if (mUnit->CommandQueue != nullptr && mUnit->CommandQueue->GetCommandInQueue(1u) != nullptr) {
      return true;
    }

    if (mUnknown7A) {
      if (Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr(); guardedUnit != nullptr) {
        if (guardedUnit->IsIdleState()) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Address: 0x006127F0 (FUN_006127F0)
   *
   * What it does:
   * Tries to dispatch factory-build/upgrade follow-up tasks from owner or
   * guarded-unit build queues for builder-guard lanes.
   */
  void CUnitGuardTask::TryDispatchFactoryOrUpgradeFromGuardQueues()
  {
    if (mUnit == nullptr || mSecondaryUnit.GetObjectPtr() == nullptr) {
      return;
    }

    if (mUnit->IsUnitState(UNITSTATE_Building) || mUnit->IsUnitState(UNITSTATE_Repairing)) {
      return;
    }

    auto tryDispatchOwnerQueueCommand = [this](CUnitCommand* const command) -> bool {
      if (command == nullptr) {
        return false;
      }

      const EUnitCommandType commandType = command->mVarDat.mCmdType;
      if (commandType != EUnitCommandType::UNITCOMMAND_BuildFactory && commandType != EUnitCommandType::UNITCOMMAND_Upgrade) {
        return false;
      }

      const RUnitBlueprint* const blueprint = ResolveUnitBlueprintFromCommand(command);
      if (blueprint == nullptr) {
        return false;
      }

      mPrimaryCommandRef.Set(command);
      if (commandType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
        (void)CFactoryBuildTask::Create(this, blueprint, command, nullptr);
      } else {
        (void)CUnitUpgradeTask::Create(this, blueprint);
      }
      return true;
    };

    if (CUnitCommandQueue* const ownerQueue = mUnit->CommandQueue; ownerQueue != nullptr) {
      for (WeakPtr<CUnitCommand>& commandRef : ownerQueue->mCommandVec) {
        if (tryDispatchOwnerQueueCommand(commandRef.GetObjectPtr())) {
          return;
        }
      }
    }

    Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
    if (guardedUnit == nullptr || guardedUnit->CommandQueue == nullptr) {
      return;
    }

    CUnitCommandQueue* const guardedQueue = guardedUnit->CommandQueue;
    const std::size_t guardedCommandCount = guardedQueue->mCommandVec.size();
    for (std::size_t index = 0; index < guardedCommandCount; ++index) {
      CUnitCommand* const command = guardedQueue->mCommandVec[index].GetObjectPtr();
      if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
        continue;
      }

      const bool canDispatchSlot =
        index > 0u || command->mVarDat.mCount > 1
        || (guardedCommandCount <= 1u && mUnit->RepeatQueueEnabled);
      if (!canDispatchSlot) {
        continue;
      }

      const RUnitBlueprint* const blueprint = ResolveUnitBlueprintFromCommand(command);
      if (blueprint == nullptr || !mUnit->CanBuild(blueprint)) {
        continue;
      }

      if (command->mVarDat.mCount > 1) {
        command->DecreaseCount(1);
      } else if (mUnit->RepeatQueueEnabled) {
        command->mVarDat.mCount = command->mVarDat.mMaxCount;
        command->mNeedsUpdate = true;
        (void)guardedQueue->MoveCommandToBackOfQueue(command);
      } else {
        (void)guardedQueue->RemoveCommandFromQueue(command);
      }

      (void)CFactoryBuildTask::Create(this, blueprint, nullptr, guardedUnit);
      return;
    }
  }

  /**
   * Address: 0x00612BB0 (FUN_00612BB0)
   *
   * What it does:
   * Resolves one guard-context structure blueprint and build-cell target from
   * rebuilder queues or guarded-unit build-mobile command lanes.
   */
  const RUnitBlueprint* CUnitGuardTask::TryResolveGuardBuildBlueprint(SOCellPos& outBuildCellPos)
  {
    if (mUnit == nullptr || mUnit->AiBuilder == nullptr) {
      return nullptr;
    }

    if (mUnit->IsInCategory("REBUILDER")) {
      const RUnitBlueprint* const blueprint = mUnit->AiBuilder->BuilderGetNextRebuildStructure(outBuildCellPos);
      if (blueprint != nullptr) {
        mUnit->AiBuilder->BuilderRemoveRebuildStructure(outBuildCellPos);
      }
      return blueprint;
    }

    SEntitySetTemplateUnit visitedUnits{};
    Unit* guardedUnit = mSecondaryUnit.GetObjectPtr();
    while (guardedUnit != nullptr) {
      if (visitedUnits.ContainsUnit(guardedUnit)) {
        break;
      }

      Unit* const nextGuardedUnit = guardedUnit->GetGuardedUnit();
      if (nextGuardedUnit != nullptr) {
        (void)visitedUnits.AddUnit(guardedUnit);
        guardedUnit = nextGuardedUnit;
        continue;
      }

      CUnitCommandQueue* const commandQueue = guardedUnit->CommandQueue;
      CUnitCommand* const currentCommand = (commandQueue != nullptr) ? commandQueue->GetCurrentCommand() : nullptr;
      if (currentCommand == nullptr || currentCommand->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildMobile) {
        break;
      }

      const RUnitBlueprint* const blueprint = ResolveUnitBlueprintFromCommand(currentCommand);
      if (blueprint == nullptr || !mUnit->CanBuild(blueprint) || blueprint->IsMobile()) {
        break;
      }

      const Wm3::Vector3f buildTargetPosition = currentCommand->mTarget.GetTargetPosGun(false);
      outBuildCellPos = blueprint->mFootprint.ToCellPos(buildTargetPosition);
      return blueprint;
    }

    return nullptr;
  }

  /**
   * Address: 0x00613970 (FUN_00613970)
   *
   * What it does:
   * Converts one resolved build-cell target into world-space placement and
   * dispatches one mobile-build task for `buildBlueprint`.
   */
  void CUnitGuardTask::DispatchMobileBuildTask(
    const RUnitBlueprint* const buildBlueprint,
    const SOCellPos& buildCellPos
  )
  {
    if (buildBlueprint == nullptr || mUnit == nullptr || mUnit->SimulationRef == nullptr
        || mUnit->SimulationRef->mMapData == nullptr) {
      return;
    }

    const Wm3::Vector3f buildWorldPos = COORDS_ToWorldPos(
      mUnit->SimulationRef->mMapData,
      buildCellPos,
      static_cast<ELayer>(buildBlueprint->mFootprint.mOccupancyCaps),
      buildBlueprint->mFootprint.mSizeX,
      buildBlueprint->mFootprint.mSizeZ
    );

    const Wm3::Quatf buildOrientation{1.0f, 0.0f, 0.0f, 0.0f};
    const Wm3::Vector3f completionMoveOffset = Wm3::Vector3f::Zero();
    (void)CUnitMobileBuildTask::Create(this, buildBlueprint, buildWorldPos, buildOrientation, completionMoveOffset);
  }

  /**
   * Address: 0x00612FB0 (FUN_00612FB0)
   *
   * What it does:
   * Returns whether owner builder queue already contains a guard command that
   * targets the candidate unit's current world position.
   */
  bool CUnitGuardTask::HasGuardCommandAtUnitPosition(const Unit* const candidateUnit) const
  {
    if (candidateUnit == nullptr || mUnit == nullptr || mUnit->AiBuilder == nullptr) {
      return false;
    }

    const Wm3::Vector3f candidatePosition = candidateUnit->GetPosition();
    msvc8::vector<WeakPtr<CUnitCommand>>& builderQueue = mUnit->AiBuilder->BuilderGetFactoryCommandQueue();
    for (WeakPtr<CUnitCommand>& commandRef : builderQueue) {
      const CUnitCommand* const command = commandRef.GetObjectPtr();
      if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Guard) {
        continue;
      }

      const Wm3::Vector3f commandTargetPosition = const_cast<moho::CAiTarget&>(command->mTarget).GetTargetPosGun(false);
      const float deltaX = commandTargetPosition.x - candidatePosition.x;
      const float deltaZ = commandTargetPosition.z - candidatePosition.z;
      if ((deltaX * deltaX) + (deltaZ * deltaZ) < 0.000001f) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00613110 (FUN_00613110)
   *
   * What it does:
   * Selects one assist/capture candidate unit from guarded focus lanes or
   * nearby guard-area scan lanes for follow-up dispatch.
   */
  Unit* CUnitGuardTask::SelectAssistOrCaptureCandidateUnit()
  {
    if (mUnit == nullptr) {
      return nullptr;
    }

    const bool isRebuilder = mUnit->IsInCategory("REBUILDER");
    const bool isRepairUnit = mUnit->IsInCategory("REPAIR");
    if (!isRebuilder && !isRepairUnit) {
      return nullptr;
    }

    if (mTrackGuardedUnit) {
      Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
      if (guardedUnit == nullptr) {
        return nullptr;
      }

      if (!Wm3::Vector3f::Compare(&guardedUnit->Position, &guardedUnit->PrevPosition)) {
        if (guardedUnit->Health < guardedUnit->MaxHealth) {
          return guardedUnit;
        }

        const RUnitBlueprint* const guardedBlueprint = guardedUnit->GetBlueprint();
        if (guardedBlueprint != nullptr && guardedBlueprint->Physics.FuelUseTime > 1.0f && guardedUnit->FuelRatio < 1.0f) {
          return guardedUnit;
        }

        if (IsShieldFocusDamaged(guardedUnit)) {
          return guardedUnit;
        }

        if (!guardedUnit->IsPaused && guardedUnit->IsUnitState(UNITSTATE_Enhancing)) {
          return guardedUnit;
        }

        if (Unit* const focusAssistTarget = ResolveGuardFocusAssistTarget(guardedUnit, mUnit); focusAssistTarget != nullptr) {
          return focusAssistTarget;
        }

        if (!guardedUnit->IsPaused && guardedUnit->AiSiloBuild != nullptr
            && guardedUnit->IsUnitState(UNITSTATE_SiloBuildingAmmo)) {
          return guardedUnit;
        }
      }

      return nullptr;
    }

    if (mDisableBestEnemySearch || mDisableReactionState) {
      return nullptr;
    }

    if (mUnit->ArmyRef == nullptr || mUnit->SimulationRef == nullptr || mUnit->SimulationRef->mOGrid == nullptr) {
      return nullptr;
    }

    const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
    if (ownerBlueprint == nullptr) {
      return nullptr;
    }

    const float scanRadius = ownerBlueprint->AI.GuardScanRadius;
    const gpg::Rect2f scanRect{
      mGuardDirection.x - scanRadius,
      mGuardDirection.z - scanRadius,
      mGuardDirection.x + scanRadius,
      mGuardDirection.z + scanRadius
    };

    CollisionDBRect queryRect{};
    (void)func_Rect2fToInt16(&queryRect, scanRect);

    EntityGatherVector nearbyEntities{};
    (void)mUnit->SimulationRef->mOGrid->mEntityOccupationManager.GatherUnmarkedEntities(
      nearbyEntities,
      queryRect,
      ENTITYTYPE_Unit
    );

    Unit* bestCandidate = nullptr;
    float bestDistanceSquared = std::numeric_limits<float>::infinity();
    const Wm3::Vector3f ownerPosition = mUnit->GetPosition();
    for (Entity* const nearbyEntity : nearbyEntities) {
      Unit* const candidate = (nearbyEntity != nullptr) ? nearbyEntity->IsUnit() : nullptr;
      if (candidate == nullptr || candidate == mUnit || candidate->IsDead()) {
        continue;
      }

      if (candidate->SimulationRef == nullptr || candidate->SimulationRef->mMapData == nullptr) {
        continue;
      }

      if (!candidate->SimulationRef->mMapData->IsWithin(candidate->Position, 1.0f, mUnit->ArmyRef->UseWholeMap())) {
        continue;
      }

      if (Wm3::Vector3f::Compare(&candidate->Position, &candidate->PrevPosition)) {
        continue;
      }

      if (candidate->mCurrentLayer == LAYER_Air) {
        continue;
      }

      if (isRebuilder) {
        if (!HasGuardCommandAtUnitPosition(candidate)) {
          continue;
        }
      } else {
        if (candidate->ArmyRef == nullptr) {
          continue;
        }
        const bool isAllied =
          candidate->ArmyRef == mUnit->ArmyRef
          || mUnit->ArmyRef->GetAllianceWith(candidate->ArmyRef) == ALLIANCE_Ally;
        if (!isAllied) {
          continue;
        }
      }

      Unit* distanceTarget = nullptr;
      if (Entity* const focusEntity = candidate->GetFocusEntity(); focusEntity != nullptr) {
        distanceTarget = focusEntity->IsUnit();
      }

      if (distanceTarget == nullptr) {
        if (!NeedsAssistOrRepairDispatch(candidate)) {
          continue;
        }
        distanceTarget = candidate;
      }

      const float candidateDistanceSquared = DistanceSquared(ownerPosition, distanceTarget->GetPosition());
      if (candidateDistanceSquared < bestDistanceSquared) {
        bestDistanceSquared = candidateDistanceSquared;
        bestCandidate = distanceTarget;
      }
    }

    return bestCandidate;
  }

  /**
   * Address: 0x00613A80 (FUN_00613A80)
   *
   * What it does:
   * Dispatches allied repair/silo-assist or enemy capture follow-up work for
   * one guard candidate unit.
   */
  void CUnitGuardTask::DispatchAssistOrCaptureTask(Unit* const targetUnit)
  {
    if (targetUnit == nullptr || mUnit == nullptr || mCommandTask == nullptr) {
      return;
    }

    IAiCommandDispatchImpl* const dispatchTask = static_cast<IAiCommandDispatchImpl*>(mCommandTask);

    const bool isAlliedTarget =
      mUnit->ArmyRef != nullptr
      && targetUnit->ArmyRef != nullptr
      && mUnit->ArmyRef->GetAllianceWith(targetUnit->ArmyRef) == ALLIANCE_Ally;

    if (isAlliedTarget) {
      bool shouldIssueRepairTask = true;
      if (targetUnit->MaxHealth <= targetUnit->Health && !targetUnit->IsUnitState(UNITSTATE_Enhancing)) {
        bool focusNeedsRepair = false;
        if (targetUnit->RunScriptBool("ShieldIsOn") && targetUnit->IsInCategory("SHIELD")) {
          if (Entity* const focusEntity = targetUnit->GetFocusEntity(); focusEntity != nullptr) {
            focusNeedsRepair = focusEntity->MaxHealth > focusEntity->Health;
          }
        }
        if (!focusNeedsRepair) {
          shouldIssueRepairTask = false;
        }
      }

      if (shouldIssueRepairTask) {
        (void)moho::CUnitRepairTask::Allocate(dispatchTask, targetUnit, false);
      } else if (targetUnit->AiBuilder != nullptr && targetUnit->IsUnitState(UNITSTATE_SiloBuildingAmmo)) {
        (void)moho::CUnitRepairTask::Allocate(dispatchTask, targetUnit, true);
      }
      return;
    }

    CAiTarget targetPayload{};
    (void)targetPayload.UpdateTarget(static_cast<Entity*>(targetUnit));
    (void)CUnitCaptureTask::Create(mCommandTask, &targetPayload);
  }

  /**
   * Address: 0x006138F0 (FUN_006138F0, Moho::CUnitGuardTask::SetEnemy)
   *
   * What it does:
   * Builds one target payload for `enemy` and dispatches an attack-target task
   * bound to this guard task's command-dispatch lane.
   */
  void CUnitGuardTask::SetEnemy(Entity* const enemy)
  {
    if (enemy == nullptr || mCommandTask == nullptr) {
      return;
    }

    CAiTarget targetPayload{};
    (void)targetPayload.UpdateTarget(enemy);
    (void)CAttackTargetTask::CreateRespectFormation(mCommandTask, &targetPayload, nullptr, false);
  }

  /**
   * Address: 0x00613A10 (FUN_00613A10)
   *
   * What it does:
   * Builds one target payload for `targetEntity` and dispatches a reclaim task
   * through this guard task's command-dispatch lane.
   */
  void CUnitGuardTask::IssueReclaimTaskForEntity(Entity* const targetEntity)
  {
    if (targetEntity == nullptr || mCommandTask == nullptr) {
      return;
    }

    CAiTarget targetPayload{};
    (void)targetPayload.UpdateTarget(targetEntity);
    static_cast<IAiCommandDispatchImpl*>(mCommandTask)->IssueReclaimTask(targetPayload);
  }

  /**
   * Address: 0x00612E80 (FUN_00612E80)
   *
   * What it does:
   * Returns the guarded unit's reclaim focus entity when this guard owner is
   * reclaim-capable and the guarded unit is actively reclaiming.
   */
  Entity* CUnitGuardTask::ResolveGuardedReclaimFocusEntity() const
  {
    if (!mTrackGuardedUnit || mUnit == nullptr || mUnit->AiBuilder == nullptr || !mUnit->IsInCategory("RECLAIM")) {
      return nullptr;
    }

    Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
    if (guardedUnit == nullptr || !guardedUnit->IsUnitState(UNITSTATE_Reclaiming)) {
      return nullptr;
    }

    return guardedUnit->GetFocusEntity();
  }

  /**
   * Address: 0x00612AF0 (FUN_00612AF0, Moho::CUnitGuardTask::GetBestEnemy)
   *
   * What it does:
   * Uses the owner's attacker interface to pick the best enemy in guard-scan
   * range and clears any cached guard-move reservation direction when a new
   * enemy target is acquired.
   */
  Entity* CUnitGuardTask::GetBestEnemy()
  {
    Unit* const unit = mUnit;
    if (unit == nullptr || unit->AiAttacker == nullptr || mDisableBestEnemySearch || mDisableReactionState) {
      return nullptr;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    const float guardScanRadius = (blueprint != nullptr) ? blueprint->AI.GuardScanRadius : 0.0f;

    CAiAttackerImpl* const attacker = unit->AiAttacker;
    UnitWeapon* const primaryWeapon = attacker->GetPrimaryWeapon();
    Entity* const bestEnemy = attacker->FindBestEnemy(primaryWeapon, &unit->mBlipsInRange, guardScanRadius, false);
    if (bestEnemy == nullptr) {
      return nullptr;
    }

    const Wm3::Vector3f zero = Wm3::Vector3f::Zero();
    if (Wm3::Vector3f::Compare(&mGuardDirection, &zero)) {
      mGuardDirection = zero;
      unit->FreeOgridRect();
    }
    return bestEnemy;
  }

  /**
   * Address: 0x00614170 (FUN_00614170, Moho::CUnitGuardTask::AbortMove)
   *
   * What it does:
   * Marks owner unit move-abort state flag and forwards one navigator abort
   * call when a navigator lane is present.
   */
  void CUnitGuardTask::AbortMove()
  {
    if (mUnit == nullptr) {
      return;
    }

    mUnit->UnitStateMask |= kUnitStateMoveAbortMask;

    if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
      navigator->AbortMove();
    }
  }

  /**
   * Address: 0x006141A0 (FUN_006141A0, Moho::CUnitGuardTask::TaskTick)
   * Slot: 1
   *
   * What it does:
   * Advances one guard-task tick: reconciles linked command ownership lanes,
   * refreshes guarded-unit state, dispatches follow-up guard subtasks
   * (refuel/ferry/build/combat/reclaim/assist), and updates move-goal
   * steering state.
   */
  int CUnitGuardTask::Execute()
  {
    if (mUnit == nullptr) {
      return -1;
    }

    if (CUnitCommand* const primaryCommand = mPrimaryCommandRef.GetObjectPtr(); primaryCommand != nullptr) {
      if (mLinkResult == static_cast<EAiResult>(1)) {
        if (primaryCommand->mVarDat.mCount <= 1) {
          if (mUnit->RepeatQueueEnabled && primaryCommand->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
            primaryCommand->mVarDat.mCount = primaryCommand->mVarDat.mMaxCount;
            primaryCommand->mNeedsUpdate = true;
            if (mUnit->CommandQueue != nullptr) {
              (void)mUnit->CommandQueue->MoveCommandToBackOfQueue(primaryCommand);
            }
          } else if (mUnit->CommandQueue != nullptr) {
            (void)mUnit->CommandQueue->RemoveCommandFromQueue(primaryCommand);
          }
        } else {
          primaryCommand->DecreaseCount(1);
        }
      }

      mPrimaryCommandRef.UnlinkFromOwnerChain();
      mPrimaryCommandRef.ClearLinkState();
    }

    const Unit* const previousGuardedUnit = mSecondaryUnit.GetObjectPtr();
    const Unit* const currentGuardedUnit = mUnit->GetGuardedUnit();
    if (previousGuardedUnit != currentGuardedUnit) {
      mSecondaryUnit.Set(mUnit->GetGuardedUnit());

      CUnitCommand* const linkedCommand = mCommandRef.GetObjectPtr();
      Unit* const newGuardedUnit = mSecondaryUnit.GetObjectPtr();
      if (linkedCommand != nullptr && newGuardedUnit != nullptr && mUnit->CommandQueue != nullptr) {
        const int commandIndex = mUnit->CommandQueue->FindCommandIndex(linkedCommand->mConstDat.cmd);
        UpdateQueuedCommandTarget(mUnit->CommandQueue, commandIndex, newGuardedUnit);
      }
    }

    mUnit->UnitStateMask &= ~kUnitStateMoveAbortMask;

    Unit* const guardedUnit = mSecondaryUnit.GetObjectPtr();
    if (mTrackGuardedUnit) {
      if (guardedUnit == nullptr || guardedUnit->IsDead() || guardedUnit->DestroyQueued()) {
        return -1;
      }

      if (guardedUnit->IsUnitState(UNITSTATE_Attached) && !guardedUnit->IsBeingBuilt()) {
        return -1;
      }
    }

    if (mRefreshGuardedUnitFromNearby) {
      SEntitySetTemplateUnit visitedUnits{};
      mSecondaryUnit.Set(ResolveGuardCommandSourceUnit(mSecondaryUnit.GetObjectPtr(), visitedUnits));
    }

    if (mTrackGuardedUnit) {
      if (Unit* const refreshedGuardedUnit = mSecondaryUnit.GetObjectPtr(); refreshedGuardedUnit != nullptr) {
        mGuardDirection = refreshedGuardedUnit->GetPosition();
        mUnit->GuardedPos = mGuardDirection;
      }
    }

    const RUnitBlueprint* const ownerBlueprint = mUnit->GetBlueprint();
    const float guardScanRadius = (ownerBlueprint != nullptr) ? ownerBlueprint->AI.GuardScanRadius : 0.0f;

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        const SFootprint& footprint = mUnit->GetFootprint();
        const Wm3::Vector3f moveAnchorPosition = EnsureReservedGuardMoveAnchorPosition();
        const SOCellPos moveTargetCell = footprint.ToCellPos(moveAnchorPosition);
        NewMoveTask(SNavGoal(moveTargetCell), mCommandTask, 0, nullptr, 0);
        mTaskState = TASKSTATE_Waiting;
        break;
      }

      case TASKSTATE_Waiting:
        mUnit->FreeOgridRect();
        mTaskState = TASKSTATE_Processing;
        break;

      case TASKSTATE_Starting:
        if (IsOutsideGuardReferenceRange(guardScanRadius * 0.5f)) {
          UpdateGuardFollowMoveGoal();
        } else {
          mTaskState = TASKSTATE_Processing;
        }
        break;

      case TASKSTATE_Processing: {
        if (Unit* const platform = ResolveRefuelPlatform(mUnit); platform != nullptr) {
          if (IAiTransport* const transport = platform->AiTransport; transport != nullptr) {
            transport->TransportResetReservation();
          }
          AbortMove();
          if (mCommandTask != nullptr) {
            static_cast<IAiCommandDispatchImpl*>(mCommandTask)->IssueRefuelTask(platform);
          }
          break;
        }

        const Unit* const activeGuardedUnit = mSecondaryUnit.GetObjectPtr();
        bool shouldDispatchFerryTask = mPreferTransportRefuel;
        if (!shouldDispatchFerryTask && mAllowFerryBeaconRedirect && activeGuardedUnit != nullptr) {
          shouldDispatchFerryTask = activeGuardedUnit->IsInCategory("FERRYBEACON");
        }

        if (shouldDispatchFerryTask) {
          AbortMove();
          (void)CUnitFerryTask::Create(mCommandTask, mSecondaryUnit.GetObjectPtr());
          break;
        }

        if (mRefreshGuardedUnitFromNearby) {
          AbortMove();
          TryDispatchFactoryOrUpgradeFromGuardQueues();
          break;
        }

        if (Entity* const bestEnemy = GetBestEnemy(); bestEnemy != nullptr) {
          AbortMove();
          SetEnemy(bestEnemy);
          mTaskState = TASKSTATE_Starting;
          break;
        }

        SOCellPos buildCellPos{};
        if (const RUnitBlueprint* const buildBlueprint = TryResolveGuardBuildBlueprint(buildCellPos);
            buildBlueprint != nullptr) {
          mGuardMoveAnchorPosition = Wm3::Vector3f::Zero();
          AbortMove();
          DispatchMobileBuildTask(buildBlueprint, buildCellPos);
          break;
        }

        if (Entity* const reclaimEntity = ResolveGuardedReclaimFocusEntity(); reclaimEntity != nullptr) {
          AbortMove();
          IssueReclaimTaskForEntity(reclaimEntity);
          break;
        }

        if (Unit* const assistCandidate = SelectAssistOrCaptureCandidateUnit(); assistCandidate != nullptr) {
          AbortMove();
          DispatchAssistOrCaptureTask(assistCandidate);
          break;
        }

        if (ShouldAbortGuardForBuilderContext()) {
          return -1;
        }

        UpdateGuardFollowMoveGoal();
        break;
      }

      default:
        break;
    }

    if ((!mDisableReactionState && !mDisableBestEnemySearch) || mSecondaryUnit.GetObjectPtr() == nullptr) {
      return TASKSTATE_7;
    }

    return 1;
  }
} // namespace moho
