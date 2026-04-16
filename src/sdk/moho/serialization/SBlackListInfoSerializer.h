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
   * VFTABLE: 0x00E2E268
   * COL: 0x00E87DE0
   */
  class SBlackListInfoSerializer
  {
  public:
    /**
     * Address: 0x006D3980 (FUN_006D3980, Moho::SBlackListInfoSerializer::Deserialize)
     *
     * What it does:
     * Loads the reflected `WeakPtr<Entity>` and integer lanes for `SBlackListInfo`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D3990 (FUN_006D3990, Moho::SBlackListInfoSerializer::Serialize)
     *
     * What it does:
     * Saves the reflected `WeakPtr<Entity>` and integer lanes for `SBlackListInfo`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB560 (FUN_006DB560, gpg::SerSaveLoadHelper<Moho::SBlackListInfo>::Init)
     *
     * What it does:
     * Binds `SBlackListInfo` RTTI load/save callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SBlackListInfoSerializer, mHelperNext) == 0x04,
    "SBlackListInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SBlackListInfoSerializer, mHelperPrev) == 0x08,
    "SBlackListInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SBlackListInfoSerializer, mDeserialize) == 0x0C,
    "SBlackListInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SBlackListInfoSerializer, mSerialize) == 0x10,
    "SBlackListInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SBlackListInfoSerializer) == 0x14, "SBlackListInfoSerializer size must be 0x14");

  /**
   * Address: 0x00BFE680 (FUN_00BFE680, serializer helper unlink cleanup)
   *
   * What it does:
   * Unlinks `SBlackListInfoSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_SBlackListInfoSerializer();

  /**
   * Address: 0x00BD8830 (FUN_00BD8830, register serializer + atexit cleanup)
   *
   * What it does:
   * Initializes and registers `SBlackListInfo` serializer callbacks.
   */
  int register_SBlackListInfoSerializer();

  /**
   * Address: 0x006D39E0 (FUN_006D39E0, sub_6D39E0)
   *
   * What it does:
   * Duplicate cleanup lane for `SBlackListInfoSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SBlackListInfoSerializer_00();

  /**
   * Address: 0x006D3970 (FUN_006D3970, nullsub_1857)
   *
   * What it does:
   * No-op thunk lane preserved for startup table parity.
   */
  void nullsub_1857_00();
} // namespace moho
