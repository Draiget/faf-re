#include "moho/serialization/CFireWeaponTaskSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/serialization/CFireWeaponTaskTypeInfo.h"
#include "moho/unit/tasks/CFireWeaponTask.h"

namespace
{
  /**
   * Address: 0x006DD3C0 (FUN_006DD3C0, j_Moho::CFireWeaponTask::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CFireWeaponTask::MemberSerialize`.
   */
  [[maybe_unused]] void CFireWeaponTaskMemberSerializeThunk(
    moho::CFireWeaponTask* const task,
    gpg::WriteArchive* const archive,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || task == nullptr) {
      return;
    }

    moho::CFireWeaponTask::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x006DE5F0 (FUN_006DE5F0, j_Moho::CFireWeaponTask::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CFireWeaponTask::MemberSerialize`.
   */
  [[maybe_unused]] void CFireWeaponTaskMemberSerializeThunkSecondary(
    moho::CFireWeaponTask* const task,
    gpg::WriteArchive* const archive,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || task == nullptr) {
      return;
    }

    moho::CFireWeaponTask::MemberSerialize(archive, task, version, ownerRef);
  }

  /**
   * Address: 0x006DD3B0 (FUN_006DD3B0)
   *
   * What it does:
   * Thin forwarding thunk to `CFireWeaponTask::MemberDeserialize`.
   */
  [[maybe_unused]] void CFireWeaponTaskMemberDeserializeThunk(
    moho::CFireWeaponTask* const task,
    gpg::ReadArchive* const archive,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || task == nullptr) {
      return;
    }

    moho::CFireWeaponTask::MemberDeserialize(archive, task, version, ownerRef);
  }

  [[nodiscard]] gpg::RType* ResolveCFireWeaponTaskType()
  {
    gpg::RType* type = gpg::LookupRType(typeid(moho::CFireWeaponTask));
    GPG_ASSERT(type != nullptr);
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD8890 (FUN_00BD8890, dynamic initializer for the global
   * `CFireWeaponTaskSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CFireWeaponTaskSerializer::CFireWeaponTaskSerializer()
    : mDeserialize(&CFireWeaponTaskSerializer::Deserialize)
    , mSerialize(&CFireWeaponTaskSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFE710 (FUN_00BFE710, Moho::CFireWeaponTaskSerializer::~CFireWeaponTaskSerializer)
   */
  CFireWeaponTaskSerializer::~CFireWeaponTaskSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006D3EF0 (FUN_006D3EF0, Moho::CFireWeaponTaskSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive loading into `CFireWeaponTask::MemberDeserialize`.
   */
  void CFireWeaponTaskSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int version, gpg::RRef* ownerRef)
  {
    CFireWeaponTask::MemberDeserialize(archive, reinterpret_cast<CFireWeaponTask*>(objectPtr), version, ownerRef);
  }

  /**
   * Address: 0x006D3F00 (FUN_006D3F00, Moho::CFireWeaponTaskSerializer::Serialize)
   *
   * What it does:
   * Forwards archive saving into `CFireWeaponTask::MemberSerialize`.
   */
  void CFireWeaponTaskSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int version, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CFireWeaponTask*>(objectPtr);
    if (ownerRef != nullptr) {
      CFireWeaponTask::MemberSerialize(archive, task, version, ownerRef);
      return;
    }

    CFireWeaponTaskMemberSerializeThunk(task, archive, version, ownerRef);
  }

  /**
   * Address: 0x006DB850 (FUN_006DB850, Moho::CFireWeaponTaskSerializer::RegisterSerializeFunctions)
   *
   * What it does:
   * Binds `CFireWeaponTask` load/save callbacks into reflected RTTI.
   */
  void CFireWeaponTaskSerializer::Init()
  {
    gpg::RType* const type = ResolveCFireWeaponTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  // Address: 0x010B7BC4 -- process-global `CFireWeaponTaskSerializer` singleton.
  moho::CFireWeaponTaskSerializer gCFireWeaponTaskSerializer;
} // namespace
