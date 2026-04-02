#include "moho/unit/tasks/CUnitCallTeleport.h"

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
} // namespace

namespace moho
{
  gpg::RType* CUnitCallTeleport::sType = nullptr;

  int CUnitCallTeleport::Execute()
  {
    return -1;
  }

  /**
   * Address: 0x00603CD0 (FUN_00603CD0)
   *
   * What it does:
   * Loads base command-task state plus teleport-task weak-unit and status
   * flags from archive data.
   */
  void CUnitCallTeleport::MemberDeserialize(gpg::ReadArchive* const archive, CUnitCallTeleport* const task, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    gpg::RRef nullOwner{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(task), nullOwner);
    archive->Read(CachedWeakPtrUnitType(), &task->mTargetTransportUnit, nullOwner);
    archive->ReadBool(&task->mCompletedSuccessfully);
    archive->ReadBool(&task->mIsOccupying);
  }

  /**
   * Address: 0x00603D60 (FUN_00603D60)
   *
   * What it does:
   * Saves base command-task state plus teleport-task weak-unit and status
   * flags into archive data.
   */
  void CUnitCallTeleport::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallTeleport* const task,
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
    archive->WriteBool(task->mCompletedSuccessfully);
    archive->WriteBool(task->mIsOccupying);
  }
} // namespace moho
