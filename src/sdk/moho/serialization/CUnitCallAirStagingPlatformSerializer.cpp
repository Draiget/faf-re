#include "moho/serialization/CUnitCallAirStagingPlatformSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

namespace
{
  moho::CUnitCallAirStagingPlatformSerializer gCUnitCallAirStagingPlatformSerializer;

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

  [[nodiscard]] gpg::RType* CachedCUnitCallAirStagingPlatformType()
  {
    gpg::RType* type = moho::CUnitCallAirStagingPlatform::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallAirStagingPlatform));
      moho::CUnitCallAirStagingPlatform::sType = type;
    }
    return type;
  }

  void CleanupCUnitCallAirStagingPlatformSerializerAtExit()
  {
    (void)moho::cleanup_CUnitCallAirStagingPlatformSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00601C20 (FUN_00601C20, Moho::CUnitCallAirStagingPlatformSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into
   * `CUnitCallAirStagingPlatform::MemberDeserialize`.
   */
  void CUnitCallAirStagingPlatformSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberDeserialize(
      archive,
      reinterpret_cast<CUnitCallAirStagingPlatform*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x00601C30 (FUN_00601C30, Moho::CUnitCallAirStagingPlatformSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into
   * `CUnitCallAirStagingPlatform::MemberSerialize`.
   */
  void CUnitCallAirStagingPlatformSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef
  )
  {
    CUnitCallAirStagingPlatform::MemberSerialize(
      archive,
      reinterpret_cast<const CUnitCallAirStagingPlatform*>(static_cast<std::uintptr_t>(objectPtr)),
      version,
      ownerRef
    );
  }

  /**
   * Address: 0x006025F0 (FUN_006025F0)
   *
   * What it does:
   * Binds this serializer helper's load/save callbacks into
   * `CUnitCallAirStagingPlatform` RTTI.
   */
  void CUnitCallAirStagingPlatformSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedCUnitCallAirStagingPlatformType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF97D0 (FUN_00BF97D0, cleanup_CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallAirStagingPlatformSerializer()
  {
    return UnlinkSerializerNode(gCUnitCallAirStagingPlatformSerializer);
  }

  /**
   * Address: 0x00BCFD80 (FUN_00BCFD80, register_CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Initializes `CUnitCallAirStagingPlatform` serializer callback pointers and
   * schedules process-exit helper unlink cleanup.
   */
  void register_CUnitCallAirStagingPlatformSerializer()
  {
    ResetSerializerNode(gCUnitCallAirStagingPlatformSerializer);
    gCUnitCallAirStagingPlatformSerializer.mDeserialize = &CUnitCallAirStagingPlatformSerializer::Deserialize;
    gCUnitCallAirStagingPlatformSerializer.mSerialize = &CUnitCallAirStagingPlatformSerializer::Serialize;
    (void)std::atexit(&CleanupCUnitCallAirStagingPlatformSerializerAtExit);
  }
} // namespace moho

namespace
{
  struct CUnitCallAirStagingPlatformSerializerBootstrap
  {
    CUnitCallAirStagingPlatformSerializerBootstrap()
    {
      moho::register_CUnitCallAirStagingPlatformSerializer();
    }
  };

  CUnitCallAirStagingPlatformSerializerBootstrap gCUnitCallAirStagingPlatformSerializerBootstrap;
} // namespace

namespace
{
  /**
   * Address: 0x00601C80 (FUN_00601C80)
   *
   * What it does:
   * Unlinks `CUnitCallAirStagingPlatformSerializer` helper node from the
   * intrusive serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallAirStagingPlatformSerializerNodePrimary()
  {
    return UnlinkSerializerNode(gCUnitCallAirStagingPlatformSerializer);
  }

  /**
   * Address: 0x00601CB0 (FUN_00601CB0)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCallAirStagingPlatformSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCallAirStagingPlatformSerializerNodeSecondary()
  {
    return UnlinkSerializerNode(gCUnitCallAirStagingPlatformSerializer);
  }
} // namespace
