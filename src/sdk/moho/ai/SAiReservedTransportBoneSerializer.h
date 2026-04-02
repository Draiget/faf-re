#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E1F270
   * COL:  0x00E76A74
   */
  class SAiReservedTransportBoneSerializer
  {
  public:
    /**
     * Address: 0x005E40A0 (FUN_005E40A0, SAiReservedTransportBoneSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `SAiReservedTransportBone` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E40B0 (FUN_005E40B0, SAiReservedTransportBoneSerializer::Serialize)
     *
     * What it does:
     * Serializes one `SAiReservedTransportBone` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E8F70 (FUN_005E8F70)
     *
     * What it does:
     * Binds load/save serializer callbacks into SAiReservedTransportBone RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mHelperNext) == 0x04,
    "SAiReservedTransportBoneSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mHelperPrev) == 0x08,
    "SAiReservedTransportBoneSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mLoadCallback) == 0x0C,
    "SAiReservedTransportBoneSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SAiReservedTransportBoneSerializer, mSaveCallback) == 0x10,
    "SAiReservedTransportBoneSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(SAiReservedTransportBoneSerializer) == 0x14,
    "SAiReservedTransportBoneSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCED90 (FUN_00BCED90, register_SAiReservedTransportBoneSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `SAiReservedTransportBone` and installs
   * process-exit cleanup.
   */
  int register_SAiReservedTransportBoneSerializer();
} // namespace moho
