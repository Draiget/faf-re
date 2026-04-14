#include "moho/unit/tasks/CUnitReclaimTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr const char* kOnAssignedFocusEntityScript = "OnAssignedFocusEntity";
  constexpr std::uint64_t kUnitStateNoReclaimMask = 0x0000000000008000ull;
  constexpr std::uint64_t kUnitStateReclaimingMask = 0x0000000010000000ull;

  [[nodiscard]] gpg::RType* CachedCUnitReclaimTaskType()
  {
    gpg::RType* type = moho::CUnitReclaimTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitReclaimTask));
      moho::CUnitReclaimTask::sType = type;
    }
    return type;
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

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    gpg::RType* type = moho::SEconValue::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEconValue));
      moho::SEconValue::sType = type;
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  void WakeTaskThreadForImmediateTick(moho::CTaskThread* const ownerThread)
  {
    if (ownerThread == nullptr) {
      return;
    }

    ownerThread->mPendingFrames = 0;
    if (ownerThread->mStaged) {
      ownerThread->Unstage();
    }
  }

  void DestroyEconomyRequestPointer(moho::CEconRequest*& request)
  {
    if (request == nullptr) {
      return;
    }

    request->mNode.ListUnlink();
    delete request;
    request = nullptr;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitReclaimTask::sType = nullptr;

  /**
   * Address: 0x0061EB00 (FUN_0061EB00, sub_61EB00)
   *
   * What it does:
   * Initializes reclaim-task command/listener base slices and resets task
   * runtime lanes used by reflection allocation paths.
   */
  CUnitReclaimTask::CUnitReclaimTask()
    : CCommandTask()
    , CUnitReclaimTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mTargetHasNoMotor(false)
    , mPad4D{0, 0, 0}
    , mTargetPosition{}
    , mHasStarted(false)
    , mPad5D{0, 0, 0}
    , mConsumptionData(nullptr)
    , mReclaimRate(0.0f)
    , mReclaimPerSecond{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mTargetEntity.ClearLinkState();
    mTargetPosition.x = 0.0f;
    mTargetPosition.y = 0.0f;
    mTargetPosition.z = 0.0f;
    mReclaimPerSecond.energy = 0.0f;
    mReclaimPerSecond.mass = 0.0f;
  }

  /**
   * Address: 0x0061EB60 (FUN_0061EB60, Moho::CUnitReclaimTask::CUnitReclaimTask)
   *
   * What it does:
   * Initializes one reclaim task from dispatch context, target entity, and
   * target position snapshot, then seeds economy/request and command-listener
   * lanes.
   */
  CUnitReclaimTask::CUnitReclaimTask(
    CCommandTask* const parentTask,
    Entity* const targetEntity,
    const Wm3::Vector3f& targetPos
  )
    : CCommandTask(parentTask)
    , CUnitReclaimTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mCommand(nullptr)
    , mTargetEntity{}
    , mTargetHasNoMotor(false)
    , mPad4D{0, 0, 0}
    , mTargetPosition(targetPos)
    , mHasStarted(false)
    , mPad5D{0, 0, 0}
    , mConsumptionData(nullptr)
    , mReclaimRate(0.0f)
    , mReclaimPerSecond{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();

    mTargetEntity.ResetFromObject(targetEntity);

    mConsumptionData = new (std::nothrow) CEconRequest{};
    if (mConsumptionData != nullptr) {
      mConsumptionData->mRequested.energy = 0.0f;
      mConsumptionData->mRequested.mass = 0.0f;
      mConsumptionData->mGranted.energy = 0.0f;
      mConsumptionData->mGranted.mass = 0.0f;

      if (mUnit != nullptr && mUnit->ArmyRef != nullptr) {
        if (CSimArmyEconomyInfo* const economyInfo = mUnit->ArmyRef->GetEconomy(); economyInfo != nullptr) {
          mConsumptionData->mNode.ListLinkBefore(&economyInfo->registrationNode);
        }
      }
    }

    mReclaimRate = 0.0f;
    mReclaimPerSecond.energy = 0.0f;
    mReclaimPerSecond.mass = 0.0f;

    if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
      mCommand = mUnit->CommandQueue->GetCurrentCommand();
    }
    if (mCommand != nullptr) {
      mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mCommand));
    }

    if (mUnit != nullptr && mUnit->AiNavigator != nullptr) {
      mUnit->AiNavigator->AbortMove();
    }

    mTargetHasNoMotor = (mTargetEntity.GetObjectPtr() == nullptr);
  }

  /**
   * Address: 0x00620280 (FUN_00620280, Moho::CUnitReclaimTask::~CUnitReclaimTask)
   *
   * What it does:
   * Unlinks reclaim listeners/requests, clears reclaim/focus runtime state on
   * owner and target units, and tears down task/listener base slices.
   */
  CUnitReclaimTask::~CUnitReclaimTask()
  {
    mListenerLink.ListUnlink();

    if (Entity* const targetEntity = mTargetEntity.GetObjectPtr(); targetEntity != nullptr) {
      if (Unit* const targetUnit = targetEntity->IsUnit(); targetUnit != nullptr) {
        targetUnit->UnitStateMask &= ~kUnitStateNoReclaimMask;
      }
    }

    if (mUnit != nullptr && mUnit->AiBuilder != nullptr) {
      mUnit->AiBuilder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
    }

    SetReclaimScriptActive(false);

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        (void)mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;
      mUnit->UnitStateMask &= ~kUnitStateReclaimingMask;
      mUnit->WorkProgress = 0.0f;
    }

    DestroyEconomyRequestPointer(mConsumptionData);
    mTargetEntity.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x00620160 (FUN_00620160, listener callback lane)
   *
   * What it does:
   * Refreshes reclaim target from current command payload, rebinds unit focus
   * target, clears per-task progress state, and wakes owner task thread.
   */
  void CUnitReclaimTask::OnEvent(ECommandEvent)
  {
    SetReclaimScriptActive(false);

    Entity* commandTargetEntity = nullptr;
    if (mCommand != nullptr) {
      commandTargetEntity = mCommand->mTarget.targetEntity.GetObjectPtr();
      mTargetEntity.Set(commandTargetEntity);
      mTargetPosition = mCommand->mTarget.GetTargetPosGun(false);
    } else {
      mTargetEntity.Set(nullptr);
    }

    if (mUnit != nullptr) {
      mUnit->FocusEntityRef.ResetObjectPtr<Entity>(commandTargetEntity);
      if (mUnit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
        (void)mUnit->RunScript(kOnAssignedFocusEntityScript);
      }
      mUnit->NeedSyncGameData = true;
      mUnit->WorkProgress = 0.0f;
    }

    mTargetHasNoMotor = (commandTargetEntity == nullptr);
    mTaskState = TASKSTATE_Preparing;
    WakeTaskThreadForImmediateTick(mOwnerThread);
  }

  /**
   * Address: 0x00620C60 (FUN_00620C60, Moho::CUnitReclaimTask::MemberDeserialize)
   *
   * What it does:
   * Loads base command-task state and reclaim-task payload lanes, then
   * swaps owned economy request pointer ownership from archive state.
   */
  void CUnitReclaimTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), nullOwner);
    archive->ReadPointer_CUnitCommand(&mCommand, &nullOwner);
    archive->Read(CachedWeakPtrEntityType(), &mTargetEntity, nullOwner);
    archive->ReadBool(&mTargetHasNoMotor);
    archive->Read(CachedVector3fType(), &mTargetPosition, nullOwner);
    archive->ReadBool(&mHasStarted);

    CEconRequest* loadedRequest = nullptr;
    archive->ReadPointerOwned_CEconRequest(&loadedRequest, &nullOwner);

    CEconRequest* previousRequest = mConsumptionData;
    mConsumptionData = loadedRequest;
    DestroyEconomyRequestPointer(previousRequest);

    archive->ReadFloat(&mReclaimRate);
    archive->Read(CachedSEconValueType(), &mReclaimPerSecond, nullOwner);
  }

  /**
   * Address: 0x00620DD0 (FUN_00620DD0, Moho::CUnitReclaimTask::MemberSerialize)
   *
   * What it does:
   * Saves base command-task state and reclaim-task payload lanes including
   * tracked pointer ownership for command and economy request references.
   */
  void CUnitReclaimTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), nullOwner);

    gpg::RRef commandRef{};
    (void)gpg::RRef_CUnitCommand(&commandRef, mCommand);
    gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Unowned, nullOwner);

    archive->Write(CachedWeakPtrEntityType(), &mTargetEntity, nullOwner);
    archive->WriteBool(mTargetHasNoMotor);
    archive->Write(CachedVector3fType(), &mTargetPosition, nullOwner);
    archive->WriteBool(mHasStarted);

    gpg::RRef requestRef{};
    (void)gpg::RRef_CEconRequest(&requestRef, mConsumptionData);
    gpg::WriteRawPointer(archive, requestRef, gpg::TrackedPointerState::Owned, nullOwner);

    archive->WriteFloat(mReclaimRate);
    archive->Write(CachedSEconValueType(), &mReclaimPerSecond, nullOwner);
  }

  /**
   * Address: 0x00620110 (FUN_00620110, sub_620110)
   *
   * What it does:
   * Toggles reclaim-script active state and dispatches
   * `OnStartReclaim`/`OnStopReclaim` callbacks when state changes.
   */
  void CUnitReclaimTask::SetReclaimScriptActive(const bool active)
  {
    if (mHasStarted == active) {
      return;
    }

    mHasStarted = active;
    if (mUnit == nullptr) {
      return;
    }

    mUnit->RunScriptWeakEntity(active ? "OnStartReclaim" : "OnStopReclaim", mTargetEntity);
  }

} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00620AB0 (FUN_00620AB0, gpg::RRef_CUnitReclaimTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitReclaimTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitReclaimTask(gpg::RRef* const outRef, moho::CUnitReclaimTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitReclaimTaskType());
    return outRef;
  }
} // namespace gpg
