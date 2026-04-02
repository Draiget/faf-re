#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

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
  gpg::RType* CUnitCallAirStagingPlatform::sType = nullptr;

  int CUnitCallAirStagingPlatform::Execute()
  {
    return -1;
  }

  /**
   * Address: 0x00603DF0 (FUN_00603DF0)
   *
   * What it does:
   * Loads base command-task state plus air-staging platform weak pointer and
   * completion flag from archive data.
   */
  void CUnitCallAirStagingPlatform::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CUnitCallAirStagingPlatform* const task,
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
    archive->Read(CachedWeakPtrUnitType(), &task->mPlatform, nullOwner);
    archive->ReadBool(&task->mDone);
  }

  /**
   * Address: 0x00603E80 (FUN_00603E80)
   *
   * What it does:
   * Saves base command-task state plus air-staging platform weak pointer and
   * completion flag into archive data.
   */
  void CUnitCallAirStagingPlatform::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CUnitCallAirStagingPlatform* const task,
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
    archive->Write(CachedWeakPtrUnitType(), &task->mPlatform, nullOwner);
    archive->WriteBool(task->mDone);
  }
} // namespace moho
