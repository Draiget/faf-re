#include "moho/unit/core/UnitAttributesSerializer.h"

#include <cstdint>
#include <cstdlib>

#include "gpg/core/utils/Global.h"
#include "moho/unit/core/UnitAttributes.h"

namespace
{
  moho::UnitAttributesSerializer gUnitAttributesSerializer;

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gUnitAttributesSerializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkUnitAttributesSerializerNodeCore() noexcept
  {
    if (gUnitAttributesSerializer.mHelperNext != nullptr && gUnitAttributesSerializer.mHelperPrev != nullptr) {
      gUnitAttributesSerializer.mHelperNext->mPrev = gUnitAttributesSerializer.mHelperPrev;
      gUnitAttributesSerializer.mHelperPrev->mNext = gUnitAttributesSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode();
    gUnitAttributesSerializer.mHelperPrev = self;
    gUnitAttributesSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x0055C3B0 (FUN_0055C3B0, SerSaveLoadHelper<UnitAttributes>::unlink lane A)
   *
   * What it does:
   * Unlinks the UnitAttributes serializer helper node and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkUnitAttributesSerializerNodeLaneA() noexcept
  {
    return UnlinkUnitAttributesSerializerNodeCore();
  }

  /**
   * Address: 0x0055C3E0 (FUN_0055C3E0, SerSaveLoadHelper<UnitAttributes>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the UnitAttributes serializer
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkUnitAttributesSerializerNodeLaneB() noexcept
  {
    return UnlinkUnitAttributesSerializerNodeCore();
  }

  void ResetSerializerNode() noexcept
  {
    if (gUnitAttributesSerializer.mHelperNext == nullptr || gUnitAttributesSerializer.mHelperPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode();
      gUnitAttributesSerializer.mHelperPrev = self;
      gUnitAttributesSerializer.mHelperNext = self;
      return;
    }

    (void)UnlinkUnitAttributesSerializerNodeLaneA();
  }

  void cleanup_UnitAttributesSerializer_atexit()
  {
    moho::cleanup_UnitAttributesSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0055C350 (FUN_0055C350, Moho::UnitAttributesSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `UnitAttributes::MemberDeserialize`.
   */
  void UnitAttributesSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const attributes = reinterpret_cast<UnitAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    UnitAttributes::MemberDeserialize(archive, attributes);
  }

  /**
   * Address: 0x0055C360 (FUN_0055C360, Moho::UnitAttributesSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `UnitAttributes::MemberSerialize`.
   */
  void UnitAttributesSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const attributes = reinterpret_cast<const UnitAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    UnitAttributes::MemberSerialize(attributes, archive);
  }

  /**
   * Address: 0x0055CAE0 (FUN_0055CAE0, gpg::SerSaveLoadHelper<Moho::UnitAttributes>::Init lane)
   *
   * What it does:
   * Binds serializer load/save callbacks into `UnitAttributes` RTTI.
   */
  void UnitAttributesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = UnitAttributes::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF5390 (FUN_00BF5390, Moho::UnitAttributesSerializer::~UnitAttributesSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node and restores self-links.
   */
  void cleanup_UnitAttributesSerializer()
  {
    (void)UnlinkUnitAttributesSerializerNodeLaneA();
  }

  /**
   * Address: 0x00BCA5E0 (FUN_00BCA5E0, register_UnitAttributesSerializer)
   *
   * What it does:
   * Initializes serializer callback pointers and schedules exit cleanup.
   */
  void register_UnitAttributesSerializer()
  {
    ResetSerializerNode();
    gUnitAttributesSerializer.mDeserialize = &UnitAttributesSerializer::Deserialize;
    gUnitAttributesSerializer.mSerialize = &UnitAttributesSerializer::Serialize;
    (void)std::atexit(&cleanup_UnitAttributesSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct UnitAttributesSerializerBootstrap
  {
    UnitAttributesSerializerBootstrap()
    {
      moho::register_UnitAttributesSerializer();
    }
  };

  [[maybe_unused]] UnitAttributesSerializerBootstrap gUnitAttributesSerializerBootstrap;
} // namespace
