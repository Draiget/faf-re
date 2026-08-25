#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallLandTransport;

  class CUnitCallLandTransportSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCFCC0 (FUN_00BCFCC0, register_CUnitCallLandTransportSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCallLandTransportSerializer();

    /**
     * Address: 0x00BF96B0 (FUN_00BF96B0, Moho::CUnitCallLandTransportSerializer::~CUnitCallLandTransportSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CUnitCallLandTransportSerializer();

    /**
     * Address: 0x00600700 (FUN_00600700, Moho::CUnitCallLandTransportSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitCallLandTransport::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00600710 (FUN_00600710, Moho::CUnitCallLandTransportSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitCallLandTransport::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00602470 (FUN_00602470)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallLandTransport` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCallLandTransportSerializer, mDeserialize) == 0x0C,
    "CUnitCallLandTransportSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallLandTransportSerializer, mSerialize) == 0x10,
    "CUnitCallLandTransportSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitCallLandTransportSerializer) == 0x14,
    "CUnitCallLandTransportSerializer size must be 0x14"
  );
} // namespace moho
