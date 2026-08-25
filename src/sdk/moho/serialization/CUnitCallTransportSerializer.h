#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTransport;

  class CUnitCallTransportSerializer : public gpg::SerHelperBase
  {
  public:
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
    CUnitCallTransportSerializer();

    /**
     * Address: 0x00BF9620 (FUN_00BF9620)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CUnitCallTransportSerializer();

    /**
     * Address: 0x005FFAF0 (FUN_005FFAF0, Moho::CUnitCallTransportSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitCallTransport::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005FFB00 (FUN_005FFB00, Moho::CUnitCallTransportSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitCallTransport::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006023B0 (FUN_006023B0)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallTransport` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCallTransportSerializer, mDeserialize) == 0x0C,
    "CUnitCallTransportSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallTransportSerializer, mSerialize) == 0x10,
    "CUnitCallTransportSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCallTransportSerializer) == 0x14, "CUnitCallTransportSerializer size must be 0x14");
} // namespace moho
