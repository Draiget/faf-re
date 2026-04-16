#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E35A40
   * COL: 0x00E8F218
   */
  class ISoundManagerSerializer
  {
  public:
    /**
     * Address: 0x00760BD0 (FUN_00760BD0, Moho::ISoundManagerSerializer::Deserialize)
     *
     * What it does:
     * Placeholder deserialize lane for `ISoundManager` (no payload fields).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00760BE0 (FUN_00760BE0, Moho::ISoundManagerSerializer::Serialize)
     *
     * What it does:
     * Placeholder serialize lane for `ISoundManager` (no payload fields).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00761BE0 (FUN_00761BE0, gpg::SerSaveLoadHelper_ISoundManager::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `ISoundManager` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(ISoundManagerSerializer, mHelperNext) == 0x04, "ISoundManagerSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ISoundManagerSerializer, mHelperPrev) == 0x08, "ISoundManagerSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ISoundManagerSerializer, mLoadCallback) == 0x0C,
    "ISoundManagerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ISoundManagerSerializer, mSaveCallback) == 0x10,
    "ISoundManagerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ISoundManagerSerializer) == 0x14, "ISoundManagerSerializer size must be 0x14");
} // namespace moho
