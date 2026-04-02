#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F378
   */
  class STransportPickUpInfoSerializer
  {
  public:
    /**
     * Address: 0x005E4660 (FUN_005E4660, STransportPickUpInfoSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `STransportPickUpInfo` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E4670 (FUN_005E4670, STransportPickUpInfoSerializer::Serialize)
     *
     * What it does:
     * Serializes one `STransportPickUpInfo` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E4650 (FUN_005E4650, nullsub_1637 placeholder lane)
     *
     * What it does:
     * Binds load/save serializer callbacks into `STransportPickUpInfo` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(STransportPickUpInfoSerializer, mHelperNext) == 0x04,
    "STransportPickUpInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(STransportPickUpInfoSerializer, mHelperPrev) == 0x08,
    "STransportPickUpInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(STransportPickUpInfoSerializer, mLoadCallback) == 0x0C,
    "STransportPickUpInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(STransportPickUpInfoSerializer, mSaveCallback) == 0x10,
    "STransportPickUpInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(STransportPickUpInfoSerializer) == 0x14, "STransportPickUpInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BCEE50 (FUN_00BCEE50, register_STransportPickUpInfoSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `STransportPickUpInfo` and installs
   * process-exit cleanup.
   */
  int register_STransportPickUpInfoSerializer();
} // namespace moho

