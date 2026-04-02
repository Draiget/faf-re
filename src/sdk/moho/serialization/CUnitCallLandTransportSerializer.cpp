#include "moho/serialization/CUnitCallLandTransportSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"

namespace
{
  moho::CUnitCallLandTransportSerializer gCUnitCallLandTransportSerializer;

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

  [[nodiscard]] gpg::RType* CachedCUnitCallLandTransportType()
  {
    gpg::RType* type = moho::CUnitCallLandTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallLandTransport));
      moho::CUnitCallLandTransport::sType = type;
    }
    return type;
  }

  void CleanupCUnitCallLandTransportSerializerAtExit()
  {
    (void)moho::cleanup_CUnitCallLandTransportSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00600700 (FUN_00600700, Moho::CUnitCallLandTransportSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `CUnitCallLandTransport::MemberDeserialize`.
   */
  void CUnitCallLandTransportSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallLandTransport::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitCallLandTransport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x00600710 (FUN_00600710, Moho::CUnitCallLandTransportSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `CUnitCallLandTransport::MemberSerialize`.
   */
  void CUnitCallLandTransportSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallLandTransport::MemberSerialize(
      archive,
      reinterpret_cast<const CUnitCallLandTransport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x00602470 (FUN_00602470)
   *
   * What it does:
   * Binds this serializer helper's load/save callbacks into
   * `CUnitCallLandTransport` RTTI.
   */
  void CUnitCallLandTransportSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitCallLandTransportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF96B0 (FUN_00BF96B0, cleanup_CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallLandTransportSerializer()
  {
    return UnlinkSerializerNode(gCUnitCallLandTransportSerializer);
  }

  /**
   * Address: 0x00BCFCC0 (FUN_00BCFCC0, register_CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallLandTransport` serializer callback pointers and
   * schedules process-exit helper unlink cleanup.
   */
  void register_CUnitCallLandTransportSerializer()
  {
    ResetSerializerNode(gCUnitCallLandTransportSerializer);
    gCUnitCallLandTransportSerializer.mDeserialize = &CUnitCallLandTransportSerializer::Deserialize;
    gCUnitCallLandTransportSerializer.mSerialize = &CUnitCallLandTransportSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitCallLandTransportSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitCallLandTransportSerializerBootstrap
  {
    CUnitCallLandTransportSerializerBootstrap()
    {
      moho::register_CUnitCallLandTransportSerializer();
    }
  };

  CUnitCallLandTransportSerializerBootstrap gCUnitCallLandTransportSerializerBootstrap;
} // namespace

