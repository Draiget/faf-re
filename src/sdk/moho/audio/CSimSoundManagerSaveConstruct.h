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
   * VFTABLE: 0x00E35A9C
   * COL: 0x00E8F0D0
   */
  class CSimSoundManagerSaveConstruct
  {
  public:
    /**
     * Address: 0x00761D90 (FUN_00761D90, gpg::SerSaveConstructHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CSimSoundManager` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mHelperNext) == 0x04,
    "CSimSoundManagerSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mHelperPrev) == 0x08,
    "CSimSoundManagerSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CSimSoundManagerSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CSimSoundManagerSaveConstruct) == 0x10, "CSimSoundManagerSaveConstruct size must be 0x10");
} // namespace moho

