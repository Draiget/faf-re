#include "moho/unit/tasks/CUnitCallTransport.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/IAiTransport.h"
#include "gpg/core/utils/Logging.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCallTransportPending = 0x0000000000000100ull;
  constexpr std::uint64_t kUnitStateMaskWaitingForTransport = 0x0000000000000080ull;
  constexpr std::uint64_t kUnitStateMaskTeleporting = 0x0000000000080000ull;

  [[nodiscard]] const char* BlueprintIdOrUnknown(const moho::Unit* const unit) noexcept
  {
    if (!unit) {
      return "<unknown>";
    }

    const moho::RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return "<unknown>";
    }

    return blueprint->mBlueprintId.c_str();
  }

  [[nodiscard]] gpg::RType* CachedCUnitCallTransportType()
  {
    gpg::RType* type = moho::CUnitCallTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTransport));
      moho::CUnitCallTransport::sType = type;
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

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVTransformType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::VTransform));
    }
    return cached;
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
} // namespace

namespace moho
{
  gpg::RType* CUnitCallTransport::sType = nullptr;

  /**
   * Address: 0x005FF7F0 (FUN_005FF7F0, Moho::CUnitCallTransport::~CUnitCallTransport)
   *
   * What it does:
   * Tears down transport-call state, clears owner-unit transport flags,
   * finalizes dispatch result, and unlinks the target transport weak pointer.
   */
  CUnitCallTransport::~CUnitCallTransport()
  {
    mUnit->UnitStateMask &= ~kUnitStateMaskCallTransportPending;
    mUnit->UnitStateMask &= ~kUnitStateMaskWaitingForTransport;

    if (!mHasBeamupDestination) {
      if (mUnit->IsUnitState(UNITSTATE_Teleporting)) {
        (void)mUnit->RunScript("OnStopTransportBeamUp");
        mUnit->UnitStateMask &= ~kUnitStateMaskTeleporting;
      }

      if (CUnitMotion* const unitMotion = mUnit->UnitMotion; unitMotion != nullptr && mBeamupTime < 10.0f) {
        unitMotion->NotifyDetached(static_cast<Entity*>(mUnit), false);
      }

      Unit* const transportUnit = mTargetTransportUnit.GetObjectPtr();
      if (transportUnit != nullptr && transportUnit->AiTransport != nullptr && !transportUnit->IsDead()) {
        transportUnit->AiTransport->TransportRemovePickupUnit(mUnit, true);
      }
    }

    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mHasBeamupDestination));
    mTargetTransportUnit.UnlinkFromOwnerChain();
  }

  int CUnitCallTransport::Execute()
  {
    return -1;
  }

  /**
   * Address: 0x005FF650 (FUN_005FF650)
   *
   * What it does:
   * Initializes detached transport-call task state with identity transforms
   * and cleared weak-pointer/flag lanes.
   */
  CUnitCallTransport::CUnitCallTransport()
    : CCommandTask()
  {
    mTargetTransportUnit.ownerLinkSlot = nullptr;
    mTargetTransportUnit.nextInOwner = nullptr;
    mHasBeamupDestination = false;
    mBeamupTime = 0.0f;
    mSourceTransform.orient_ = Wm3::Quatf::Identity();
    mSourceTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mDestinationTransform.orient_ = Wm3::Quatf::Identity();
    mDestinationTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    mArrivalTickOrSequence = 0;
  }

  /**
   * Address: 0x005FF6D0 (FUN_005FF6D0, Moho::CUnitCallTransport::CUnitCallTransport)
   *
   * What it does:
   * Initializes one parent-linked call-transport task, binds the target
   * transport weak pointer, snapshots transport transform lanes, and sets
   * owner-unit transport-pending state.
   */
  CUnitCallTransport::CUnitCallTransport(CCommandTask* const parentTask, Unit* const transportUnit)
    : CCommandTask(parentTask)
  {
    mTargetTransportUnit.BindObjectUnlinked(transportUnit);
    (void)mTargetTransportUnit.LinkIntoOwnerChainHeadUnlinked();
    mHasBeamupDestination = false;
    mBeamupTime = 10.0f;

    if (transportUnit != nullptr) {
      const VTransform& transform = transportUnit->GetTransform();
      mSourceTransform = transform;
      mDestinationTransform = transform;
    } else {
      mSourceTransform.orient_ = Wm3::Quatf::Identity();
      mSourceTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
      mDestinationTransform.orient_ = Wm3::Quatf::Identity();
      mDestinationTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    }

    mArrivalTickOrSequence = 0;

    if (mUnit != nullptr) {
      mUnit->UnitStateMask |= kUnitStateMaskCallTransportPending;
      if (mUnit->IsUnitState(UNITSTATE_WaitForFerry)) {
        mTaskState = TASKSTATE_Waiting;
      }
    }
  }

  /**
   * Address: 0x00603890 (FUN_00603890)
   *
   * What it does:
   * Loads base command-task state, transport weak pointer, beamup flags, and
   * two transform lanes for one `CUnitCallTransport` object.
   */
  void CUnitCallTransport::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CUnitCallTransport* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(task), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->ReadBool(&task->mHasBeamupDestination);
    archive->ReadFloat(&task->mBeamupTime);
    archive->Read(CachedVTransformType(), &task->mSourceTransform, nullOwner);
    archive->Read(CachedVTransformType(), &task->mDestinationTransform, nullOwner);
    archive->ReadInt(&task->mArrivalTickOrSequence);
  }

  /**
   * Address: 0x006039A0 (FUN_006039A0)
   *
   * What it does:
   * Saves base command-task state, transport weak pointer, beamup flags, and
   * two transform lanes for one `CUnitCallTransport` object.
   */
  void CUnitCallTransport::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallTransport* const task,
    int,
    gpg::RRef*
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(task), nullOwner);
    archive->Write(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->WriteBool(task->mHasBeamupDestination);
    archive->WriteFloat(task->mBeamupTime);
    archive->Write(CachedVTransformType(), &task->mSourceTransform, nullOwner);
    archive->Write(CachedVTransformType(), &task->mDestinationTransform, nullOwner);
    archive->WriteInt(task->mArrivalTickOrSequence);
  }

  /**
   * Address: 0x005FFBB0 (FUN_005FFBB0, Moho::NewCallTransportCommand)
   *
   * What it does:
   * Validates one candidate transport and allocates a call-transport task when
   * legal, otherwise emits an illegal-transport warning.
   */
  void NewCallTransportCommand(CCommandTask* const parentTask, Unit* const transportUnit)
  {
    if (!transportUnit || transportUnit->IsDead()) {
      return;
    }

    if (transportUnit->AiTransport != nullptr) {
      (void)new (std::nothrow) CUnitCallTransport(parentTask, transportUnit);
      return;
    }

    gpg::Warnf("Attepted to call illegal transport %s", BlueprintIdOrUnknown(transportUnit));
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006031D0 (FUN_006031D0, gpg::RRef_CUnitCallTransport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTransport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTransport(gpg::RRef* const outRef, moho::CUnitCallTransport* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallTransportType());
    return outRef;
  }
} // namespace gpg
