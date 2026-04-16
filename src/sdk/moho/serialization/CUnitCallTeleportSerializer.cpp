#include "moho/serialization/CUnitCallTeleportSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"

namespace
{
  moho::CUnitCallTeleportSerializer gCUnitCallTeleportSerializer;

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

  [[nodiscard]] gpg::RType* CachedCUnitCallTeleportType()
  {
    gpg::RType* type = moho::CUnitCallTeleport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTeleport));
      moho::CUnitCallTeleport::sType = type;
    }
    return type;
  }

  void CleanupCUnitCallTeleportSerializerAtExit()
  {
    (void)moho::cleanup_CUnitCallTeleportSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006011F0 (FUN_006011F0, Moho::CUnitCallTeleportSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `CUnitCallTeleport::MemberDeserialize`.
   */
  void CUnitCallTeleportSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitCallTeleport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x00601200 (FUN_00601200, Moho::CUnitCallTeleportSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `CUnitCallTeleport::MemberSerialize`.
   */
  void CUnitCallTeleportSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallTeleport::MemberSerialize(
      archive,
      reinterpret_cast<const CUnitCallTeleport*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x00602530 (FUN_00602530)
   *
   * What it does:
   * Binds this serializer helper's load/save callbacks into
   * `CUnitCallTeleport` RTTI.
   */
  void CUnitCallTeleportSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitCallTeleportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF9740 (FUN_00BF9740, cleanup_CUnitCallTeleportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallTeleportSerializer()
  {
    return UnlinkSerializerNode(gCUnitCallTeleportSerializer);
  }

  /**
   * Address: 0x00BCFD20 (FUN_00BCFD20, register_CUnitCallTeleportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallTeleport` serializer callback pointers and schedules
   * process-exit helper unlink cleanup.
   */
  void register_CUnitCallTeleportSerializer()
  {
    ResetSerializerNode(gCUnitCallTeleportSerializer);
    gCUnitCallTeleportSerializer.mDeserialize = &CUnitCallTeleportSerializer::Deserialize;
    gCUnitCallTeleportSerializer.mSerialize = &CUnitCallTeleportSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitCallTeleportSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitCallTeleportSerializerBootstrap
  {
    CUnitCallTeleportSerializerBootstrap()
    {
      moho::register_CUnitCallTeleportSerializer();
    }
  };

  CUnitCallTeleportSerializerBootstrap gCUnitCallTeleportSerializerBootstrap;
} // namespace

namespace
{
  /**
   * Address: 0x00601250 (FUN_00601250)
   *
   * What it does:
   * Unlinks `CUnitCallTeleportSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallTeleportSerializerNodePrimary()
  {
    return UnlinkSerializerNode(gCUnitCallTeleportSerializer);
  }

  /**
   * Address: 0x00601280 (FUN_00601280)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCallTeleportSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallTeleportSerializerNodeSecondary()
  {
    return UnlinkSerializerNode(gCUnitCallTeleportSerializer);
  }
} // namespace
