#include "moho/unit/tasks/CUnitCallTeleport.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskTeleportPending = 0x0000000000000100ull;

  [[nodiscard]] gpg::RType* CachedCUnitCallTeleportType()
  {
    gpg::RType* type = moho::CUnitCallTeleport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTeleport));
      moho::CUnitCallTeleport::sType = type;
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
  gpg::RType* CUnitCallTeleport::sType = nullptr;

  int CUnitCallTeleport::Execute()
  {
    return -1;
  }

  /**
   * Address: 0x00600E90 (FUN_00600E90, ??0CUnitCallTeleport@Moho@@QAE@@Z)
   */
  CUnitCallTeleport::CUnitCallTeleport(CCommandTask* const parentTask, Unit* const targetUnit)
    : CCommandTask(parentTask)
  {
    mTargetTransportUnit.BindObjectUnlinked(targetUnit);
    (void)mTargetTransportUnit.LinkIntoOwnerChainHeadUnlinked();
    mCompletedSuccessfully = false;
    mIsOccupying = false;

    if (mUnit) {
      mUnit->UnitStateMask |= kUnitStateMaskTeleportPending;
    }
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

namespace gpg
{
  /**
   * Address: 0x00603530 (FUN_00603530, gpg::RRef_CUnitCallTeleport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTeleport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTeleport(gpg::RRef* const outRef, moho::CUnitCallTeleport* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitCallTeleportType());
    return outRef;
  }
} // namespace gpg
