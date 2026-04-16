#include "moho/serialization/CUnitCallTransportSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallTransport.h"

namespace
{
  moho::CUnitCallTransportSerializer gCUnitCallTransportSerializer;

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

  [[nodiscard]] gpg::RType* CachedCUnitCallTransportType()
  {
    gpg::RType* type = moho::CUnitCallTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTransport));
      moho::CUnitCallTransport::sType = type;
    }
    return type;
  }

  void CleanupCUnitCallTransportSerializerAtExit()
  {
    (void)moho::cleanup_CUnitCallTransportSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FFAF0 (FUN_005FFAF0, Moho::CUnitCallTransportSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `CUnitCallTransport::MemberDeserialize`.
   */
  void CUnitCallTransportSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitCallTransport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x005FFB00 (FUN_005FFB00, Moho::CUnitCallTransportSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `CUnitCallTransport::MemberSerialize`.
   */
  void CUnitCallTransportSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTransport::MemberSerialize(
      archive,
      reinterpret_cast<const CUnitCallTransport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x006023B0 (FUN_006023B0)
   *
   * What it does:
   * Binds this serializer helper's load/save callbacks into
   * `CUnitCallTransport` RTTI.
   */
  void CUnitCallTransportSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitCallTransportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF9620 (FUN_00BF9620, cleanup_CUnitCallTransportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallTransportSerializer()
  {
    return UnlinkSerializerNode(gCUnitCallTransportSerializer);
  }

  /**
   * Address: 0x00BCFC60 (FUN_00BCFC60, register_CUnitCallTransportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallTransport` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_CUnitCallTransportSerializer()
  {
    ResetSerializerNode(gCUnitCallTransportSerializer);
    gCUnitCallTransportSerializer.mDeserialize = &CUnitCallTransportSerializer::Deserialize;
    gCUnitCallTransportSerializer.mSerialize = &CUnitCallTransportSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitCallTransportSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitCallTransportSerializerBootstrap
  {
    CUnitCallTransportSerializerBootstrap()
    {
      moho::register_CUnitCallTransportSerializer();
    }
  };

  CUnitCallTransportSerializerBootstrap gCUnitCallTransportSerializerBootstrap;
} // namespace

namespace
{
  /**
   * Address: 0x005FFB50 (FUN_005FFB50)
   *
   * What it does:
   * Unlinks `CUnitCallTransportSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallTransportSerializerNodePrimary()
  {
    return UnlinkSerializerNode(gCUnitCallTransportSerializer);
  }

  /**
   * Address: 0x005FFB80 (FUN_005FFB80)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCallTransportSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallTransportSerializerNodeSecondary()
  {
    return UnlinkSerializerNode(gCUnitCallTransportSerializer);
  }
} // namespace
