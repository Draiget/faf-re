#include "moho/serialization/CUnitCallTeleportSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCallTeleportType()
  {
    gpg::RType* type = moho::CUnitCallTeleport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTeleport));
      moho::CUnitCallTeleport::sType = type;
    }
    return type;
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
  void CUnitCallTeleportSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitCallTeleportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BCFD20 (FUN_00BCFD20, register_CUnitCallTeleportSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitCallTeleportSerializer::CUnitCallTeleportSerializer()
    : mDeserialize(&CUnitCallTeleportSerializer::Deserialize)
    , mSerialize(&CUnitCallTeleportSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF9740 (FUN_00BF9740, Moho::CUnitCallTeleportSerializer::~CUnitCallTeleportSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently
   * sits in and restores a self-linked sentinel state.
   */
  CUnitCallTeleportSerializer::~CUnitCallTeleportSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  moho::CUnitCallTeleportSerializer gCUnitCallTeleportSerializer;
} // namespace
