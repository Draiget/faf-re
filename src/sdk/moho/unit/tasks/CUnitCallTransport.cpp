#include "moho/unit/tasks/CUnitCallTransport.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
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
} // namespace

namespace moho
{
  gpg::RType* CUnitCallTransport::sType = nullptr;

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
} // namespace moho
