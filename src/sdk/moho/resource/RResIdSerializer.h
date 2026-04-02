#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class RResId;

  /**
   * VFTABLE: 0x00E073BC
   * COL: 0x00E61E9C
   */
  class RResIdSerializer
  {
  public:
    /**
     * Address: 0x004A9690 (FUN_004A9690, Moho::RResIdSerializer::Deserialize)
     *
     * What it does:
     * Loads one reflected `RResId` filename string from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A96B0 (FUN_004A96B0, Moho::RResIdSerializer::Serialize)
     *
     * What it does:
     * Saves one reflected `RResId` filename string to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004A9790 (FUN_004A9790, gpg::SerSaveLoadHelper<Moho::RResId>::Init)
     *
     * What it does:
     * Binds `RResId` serializer load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(RResIdSerializer, mHelperNext) == 0x04, "RResIdSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(RResIdSerializer, mHelperPrev) == 0x08, "RResIdSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(RResIdSerializer, mDeserialize) == 0x0C, "RResIdSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(RResIdSerializer, mSerialize) == 0x10, "RResIdSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(RResIdSerializer) == 0x14, "RResIdSerializer size must be 0x14");

  /**
   * Address: 0x004A9680 (FUN_004A9680, nullsub_693)
   *
   * What it does:
   * No-op startup table lane preserved for serializer bootstrap parity.
   */
  void nullsub_693();

  /**
   * Address: 0x004A9700 (FUN_004A9700)
   */
  gpg::SerHelperBase* ResetRResIdSerializerLinksVariant1();

  /**
   * Address: 0x004A9730 (FUN_004A9730)
   */
  gpg::SerHelperBase* ResetRResIdSerializerLinksVariant2();

  /**
   * Address: 0x00BC5A80 (register_RResIdSerializer)
   */
  int register_RResIdSerializer();
} // namespace moho

