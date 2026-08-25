#include "moho/serialization/CUnitCallTransportSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitCallTransport.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCallTransportType()
  {
    gpg::RType* type = moho::CUnitCallTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitCallTransport));
      moho::CUnitCallTransport::sType = type;
    }
    return type;
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
  void CUnitCallTransportSerializer::Init()
  {
    gpg::RType* const type = CachedCUnitCallTransportType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BCFC60 (FUN_00BCFC60, register_CUnitCallTransportSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields. The ctor's atexit target (0x00BF9620) is a
   * plain unlink thunk with no mangled destructor name in IDA, but its body
   * is byte-identical to the confirmed real destructors of this class's
   * three sibling serializers, so it is modeled the same way: the
   * compiler's implicit static-destructor registration rather than an
   * explicit call.
   */
  CUnitCallTransportSerializer::CUnitCallTransportSerializer()
    : mDeserialize(&CUnitCallTransportSerializer::Deserialize)
    , mSerialize(&CUnitCallTransportSerializer::Serialize)
  {}

  /**
   * Address: 0x00BF9620 (FUN_00BF9620)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently
   * sits in and restores a self-linked sentinel state.
   */
  CUnitCallTransportSerializer::~CUnitCallTransportSerializer()
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  moho::CUnitCallTransportSerializer gCUnitCallTransportSerializer;
} // namespace
