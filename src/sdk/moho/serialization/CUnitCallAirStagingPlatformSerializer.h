#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallAirStagingPlatform;

  class CUnitCallAirStagingPlatformSerializer
  {
  public:
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
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext; // +0x04
    gpg::SerHelperBase* mHelperPrev; // +0x08
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CUnitCallAirStagingPlatformSerializer, mHelperNext) == 0x04,
    "CUnitCallAirStagingPlatformSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCallAirStagingPlatformSerializer, mHelperPrev) == 0x08,
    "CUnitCallAirStagingPlatformSerializer::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BF97D0 (FUN_00BF97D0, cleanup_CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallAirStagingPlatformSerializer();

  /**
   * Address: 0x00BCFD80 (FUN_00BCFD80, register_CUnitCallAirStagingPlatformSerializer)
   *
   * What it does:
   * Initializes `CUnitCallAirStagingPlatform` serializer callback pointers and
   * schedules process-exit helper unlink cleanup.
   */
  void register_CUnitCallAirStagingPlatformSerializer();
} // namespace moho

