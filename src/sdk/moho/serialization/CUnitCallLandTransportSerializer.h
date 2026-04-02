#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallLandTransport;

  class CUnitCallLandTransportSerializer
  {
  public:
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
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext; // +0x04
    gpg::SerHelperBase* mHelperPrev; // +0x08
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CUnitCallLandTransportSerializer, mHelperNext) == 0x04,
    "CUnitCallLandTransportSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCallLandTransportSerializer, mHelperPrev) == 0x08,
    "CUnitCallLandTransportSerializer::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BF96B0 (FUN_00BF96B0, cleanup_CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitCallLandTransportSerializer();

  /**
   * Address: 0x00BCFCC0 (FUN_00BCFCC0, register_CUnitCallLandTransportSerializer)
   *
   * What it does:
   * Initializes `CUnitCallLandTransport` serializer callback pointers and
   * schedules process-exit helper unlink cleanup.
   */
  void register_CUnitCallLandTransportSerializer();
} // namespace moho

