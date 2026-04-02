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

  void cleanup_CFireWeaponTaskSerializer_00BFE710_Impl()
  {
    gCFireWeaponTaskSerializer.mHelperNext = SerializerSelfNode(gCFireWeaponTaskSerializer);
    gCFireWeaponTaskSerializer.mHelperPrev = SerializerSelfNode(gCFireWeaponTaskSerializer);
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
    CFireWeaponTask::MemberSerialize(archive, reinterpret_cast<const CFireWeaponTask*>(objectPtr), version, ownerRef);
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
    cleanup_CFireWeaponTaskSerializer_00BFE710_Impl();
  }

  /**
   * Address: 0x00BD8890 (FUN_00BD8890, register_CFireWeaponTaskSerializer)
   */
  void register_CFireWeaponTaskSerializer()
  {
    InitializeSerializerNode(gCFireWeaponTaskSerializer);
    gCFireWeaponTaskSerializer.mDeserialize = &CFireWeaponTaskSerializer::Deserialize;
    gCFireWeaponTaskSerializer.mSerialize = &CFireWeaponTaskSerializer::Serialize;
    gCFireWeaponTaskSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_CFireWeaponTaskSerializer);
  }
} // namespace moho
