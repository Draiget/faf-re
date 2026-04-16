#include "moho/serialization/CFireWeaponTaskSerializer.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/serialization/CFireWeaponTaskTypeInfo.h"
#include "moho/unit/tasks/CFireWeaponTask.h"

namespace
{
  using Serializer = moho::CFireWeaponTaskSerializer;

  Serializer gCFireWeaponTaskSerializer{};

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

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::RType* ResolveCFireWeaponTaskType()
  {
    gpg::RType* type = gpg::LookupRType(typeid(moho::CFireWeaponTask));
    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::SerHelperBase* cleanup_CFireWeaponTaskSerializer_00BFE710_Impl()
  {
    if (gCFireWeaponTaskSerializer.mHelperNext != nullptr && gCFireWeaponTaskSerializer.mHelperPrev != nullptr) {
      gCFireWeaponTaskSerializer.mHelperNext->mPrev = gCFireWeaponTaskSerializer.mHelperPrev;
      gCFireWeaponTaskSerializer.mHelperPrev->mNext = gCFireWeaponTaskSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(gCFireWeaponTaskSerializer);
    gCFireWeaponTaskSerializer.mHelperNext = self;
    gCFireWeaponTaskSerializer.mHelperPrev = self;
    return self;
  }

} // namespace

namespace moho
{
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
  void CFireWeaponTaskSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveCFireWeaponTaskType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE710 (FUN_00BFE710, cleanup)
   */
  void cleanup_CFireWeaponTaskSerializer()
  {
    (void)cleanup_CFireWeaponTaskSerializer_00BFE710_Impl();
  }

  /**
   * Address: 0x006D3F50 (FUN_006D3F50)
   *
   * What it does:
   * Duplicated teardown lane that unlinks `CFireWeaponTaskSerializer` helper
   * links and rewires the node as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_CFireWeaponTaskSerializer_variant_primary()
  {
    return cleanup_CFireWeaponTaskSerializer_00BFE710_Impl();
  }

  /**
   * Address: 0x006D3F80 (FUN_006D3F80)
   *
   * What it does:
   * Secondary duplicated teardown lane for `CFireWeaponTaskSerializer` helper
   * link unlink + self-link reset.
   */
  gpg::SerHelperBase* cleanup_CFireWeaponTaskSerializer_variant_secondary()
  {
    return cleanup_CFireWeaponTaskSerializer_00BFE710_Impl();
  }

  /**
   * Address: 0x00BD8890 (FUN_00BD8890, register_CFireWeaponTaskSerializer)
   */
  void register_CFireWeaponTaskSerializer()
  {
    InitializeSerializerNode(gCFireWeaponTaskSerializer);
    gCFireWeaponTaskSerializer.mDeserialize = &CFireWeaponTaskSerializer::Deserialize;
    gCFireWeaponTaskSerializer.mSerialize = &CFireWeaponTaskSerializer::Serialize;
    (void)std::atexit(&cleanup_CFireWeaponTaskSerializer);
  }
} // namespace moho
