#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  struct SerHelperBase;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E35ABC
   * COL: 0x00E8EF78
   */
  class CSimSoundManagerSerializer
  {
  public:
    /**
     * Address: 0x00762440 (FUN_00762440)
     *
     * What it does:
     * Reflection load callback wrapper for `CSimSoundManager`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00762450 (FUN_00762450)
     *
     * What it does:
     * Reflection save callback wrapper for `CSimSoundManager`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00761E90 (FUN_00761E90, gpg::SerSaveLoadHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CSimSoundManager` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CSimSoundManagerSerializer, mHelperNext) == 0x04,
    "CSimSoundManagerSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimSoundManagerSerializer, mHelperPrev) == 0x08,
    "CSimSoundManagerSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimSoundManagerSerializer, mLoadCallback) == 0x0C,
    "CSimSoundManagerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimSoundManagerSerializer, mSaveCallback) == 0x10,
    "CSimSoundManagerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CSimSoundManagerSerializer) == 0x14, "CSimSoundManagerSerializer size must be 0x14");
} // namespace moho
