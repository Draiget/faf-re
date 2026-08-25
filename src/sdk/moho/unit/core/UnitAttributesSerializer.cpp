#include "moho/unit/core/UnitAttributesSerializer.h"

#include <cstdint>
#include <cstdlib>

#include "gpg/core/utils/Global.h"
#include "moho/unit/core/UnitAttributes.h"

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
  void UnitAttributesSerializer::Init()
  {
    gpg::RType* const type = UnitAttributes::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BCA5E0 (FUN_00BCA5E0, register_UnitAttributesSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  UnitAttributesSerializer::UnitAttributesSerializer()
    : mDeserialize(&UnitAttributesSerializer::Deserialize)
    , mSerialize(&UnitAttributesSerializer::Serialize)
  {}

  UnitAttributesSerializer::~UnitAttributesSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  // Address: 0x010ACCF8 -- process-global `UnitAttributesSerializer` singleton.
  moho::UnitAttributesSerializer gUnitAttributesSerializer;
} // namespace
