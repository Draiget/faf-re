#include "moho/serialization/CUnitCallLandTransportSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallLandTransport.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCallLandTransportType()
  {
    gpg::RType* type = moho::CUnitCallLandTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallLandTransport));
      moho::CUnitCallLandTransport::sType = type;
    }
    return type;
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
  void CUnitCallLandTransportSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitCallLandTransportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BCFCC0 (FUN_00BCFCC0, register_CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCallLandTransportSerializer::CUnitCallLandTransportSerializer()
    : mDeserialize(&CUnitCallLandTransportSerializer::Deserialize)
    , mSerialize(&CUnitCallLandTransportSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF96B0 (FUN_00BF96B0, Moho::CUnitCallLandTransportSerializer::~CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently
   * sits in and restores a self-linked sentinel state.
   */
  CUnitCallLandTransportSerializer::~CUnitCallLandTransportSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  moho::CUnitCallLandTransportSerializer gCUnitCallLandTransportSerializer;
} // namespace
