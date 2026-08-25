#include "moho/serialization/CUnitCallAirStagingPlatformSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCallAirStagingPlatformType()
  {
    gpg::RType* type = moho::CUnitCallAirStagingPlatform::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallAirStagingPlatform));
      moho::CUnitCallAirStagingPlatform::sType = type;
    }
    return type;
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
  void CUnitCallAirStagingPlatformSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitCallAirStagingPlatformType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BCFD80 (FUN_00BCFD80, register_CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCallAirStagingPlatformSerializer::CUnitCallAirStagingPlatformSerializer()
    : mDeserialize(&CUnitCallAirStagingPlatformSerializer::Deserialize)
    , mSerialize(&CUnitCallAirStagingPlatformSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF97D0 (FUN_00BF97D0, Moho::CUnitCallAirStagingPlatformSerializer::~CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently
   * sits in and restores a self-linked sentinel state.
   */
  CUnitCallAirStagingPlatformSerializer::~CUnitCallAirStagingPlatformSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  moho::CUnitCallAirStagingPlatformSerializer gCUnitCallAirStagingPlatformSerializer;
} // namespace
