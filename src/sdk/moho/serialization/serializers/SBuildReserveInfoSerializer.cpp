#include "moho/serialization/serializers/SBuildReserveInfoSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/serialization/SBuildReserveInfo.h"

namespace
{
  moho::SBuildReserveInfoSerializer gSBuildReserveInfoSerializer;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext == nullptr || serializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mHelperPrev = self;
      serializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

  [[nodiscard]] gpg::RType* CachedSBuildReserveInfoType()
  {
    gpg::RType* type = moho::SBuildReserveInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SBuildReserveInfo));
      moho::SBuildReserveInfo::sType = type;
    }

    return type;
  }

  void CleanupSBuildReserveInfoSerializerAtExit()
  {
    (void)moho::cleanup_SBuildReserveInfoSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00579A70 (FUN_00579A70, Moho::SBuildReserveInfoSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `SBuildReserveInfo::MemberDeserialize`.
   */
  void SBuildReserveInfoSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const info = reinterpret_cast<SBuildReserveInfo*>(static_cast<std::uintptr_t>(objectPtr));
    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00579A80 (FUN_00579A80, Moho::SBuildReserveInfoSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `SBuildReserveInfo::MemberSerialize`.
   */
  void SBuildReserveInfoSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const info = reinterpret_cast<SBuildReserveInfo*>(static_cast<std::uintptr_t>(objectPtr));
    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x0057E1D0 (FUN_0057E1D0, gpg::SerSaveLoadHelper<Moho::SBuildReserveInfo>::Init lane)
   *
   * What it does:
   * Binds this serializer helper's load/save callbacks into
   * `SBuildReserveInfo` RTTI.
   */
  void SBuildReserveInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSBuildReserveInfoType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF6230 (FUN_00BF6230, Moho::SBuildReserveInfoSerializer::~SBuildReserveInfoSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_SBuildReserveInfoSerializer()
  {
    return UnlinkSerializerNode(gSBuildReserveInfoSerializer);
  }

  /**
   * Address: 0x00BCB390 (FUN_00BCB390, register_SBuildReserveInfoSerializer)
   *
   * What it does:
   * Initializes `SBuildReserveInfo` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_SBuildReserveInfoSerializer()
  {
    ResetSerializerNode(gSBuildReserveInfoSerializer);
    gSBuildReserveInfoSerializer.mDeserialize = &SBuildReserveInfoSerializer::Deserialize;
    gSBuildReserveInfoSerializer.mSerialize = &SBuildReserveInfoSerializer::Serialize;
    (void)std::atexit(&CleanupSBuildReserveInfoSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct SBuildReserveInfoSerializerBootstrap
  {
    SBuildReserveInfoSerializerBootstrap()
    {
      moho::register_SBuildReserveInfoSerializer();
    }
  };

  SBuildReserveInfoSerializerBootstrap gSBuildReserveInfoSerializerBootstrap;
} // namespace
