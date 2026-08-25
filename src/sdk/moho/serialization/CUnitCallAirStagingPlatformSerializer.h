#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallAirStagingPlatform;

  class CUnitCallAirStagingPlatformSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCFD80 (FUN_00BCFD80, register_CUnitCallAirStagingPlatformSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCallAirStagingPlatformSerializer();

    /**
     * Address: 0x00BF97D0 (FUN_00BF97D0, Moho::CUnitCallAirStagingPlatformSerializer::~CUnitCallAirStagingPlatformSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CUnitCallAirStagingPlatformSerializer();

    /**
     * Address: 0x00601C20 (FUN_00601C20, Moho::CUnitCallAirStagingPlatformSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into
     * `CUnitCallAirStagingPlatform::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00601C30 (FUN_00601C30, Moho::CUnitCallAirStagingPlatformSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into
     * `CUnitCallAirStagingPlatform::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006025F0 (FUN_006025F0)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `CUnitCallAirStagingPlatform` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCallAirStagingPlatformSerializer, mDeserialize) == 0x0C,
    "CUnitCallAirStagingPlatformSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCallAirStagingPlatformSerializer, mSerialize) == 0x10,
    "CUnitCallAirStagingPlatformSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(CUnitCallAirStagingPlatformSerializer) == 0x14,
    "CUnitCallAirStagingPlatformSerializer size must be 0x14"
  );
} // namespace moho
