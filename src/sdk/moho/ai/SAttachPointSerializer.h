#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F2F4
   */
  class SAttachPointSerializer
  {
  public:
    /**
     * Address: 0x005E42E0 (FUN_005E42E0, SAttachPointSerializer::Deserialize)
     *
     * What it does:
     * Deserializes one `SAttachPoint` payload from archive lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E42F0 (FUN_005E42F0, SAttachPointSerializer::Serialize)
     *
     * What it does:
     * Serializes one `SAttachPoint` payload into archive lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005E42D0 (FUN_005E42D0, nullsub_1636 placeholder lane)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SAttachPoint` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SAttachPointSerializer, mHelperNext) == 0x04,
    "SAttachPointSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SAttachPointSerializer, mHelperPrev) == 0x08,
    "SAttachPointSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SAttachPointSerializer, mLoadCallback) == 0x0C,
    "SAttachPointSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SAttachPointSerializer, mSaveCallback) == 0x10,
    "SAttachPointSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SAttachPointSerializer) == 0x14, "SAttachPointSerializer size must be 0x14");

  /**
   * Address: 0x00BCEDF0 (FUN_00BCEDF0, register_SAttachPointSerializer)
   *
   * What it does:
   * Registers serializer callbacks for `SAttachPoint` and installs process-exit
   * cleanup.
   */
  int register_SAttachPointSerializer();
} // namespace moho

