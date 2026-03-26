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
   * VFTABLE: 0x00E35AAC
   * COL: 0x00E8F024
   */
  class CSimSoundManagerConstruct
  {
  public:
    /**
     * Address: 0x00761E10 (FUN_00761E10, gpg::SerConstructHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CSimSoundManager` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CSimSoundManagerConstruct, mHelperNext) == 0x04,
    "CSimSoundManagerConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimSoundManagerConstruct, mHelperPrev) == 0x08,
    "CSimSoundManagerConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimSoundManagerConstruct, mConstructCallback) == 0x0C,
    "CSimSoundManagerConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimSoundManagerConstruct, mDeleteCallback) == 0x10,
    "CSimSoundManagerConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CSimSoundManagerConstruct) == 0x14, "CSimSoundManagerConstruct size must be 0x14");
} // namespace moho

