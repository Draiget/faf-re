#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class WriteArchive;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E35A9C
   * COL: 0x00E8F0D0
   */
  class CSimSoundManagerSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC520 (FUN_00BDC520, dynamic initializer for the global
     * `CSimSoundManagerSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the save-construct-args callback field to `SaveConstructArgs`.
     */
    CSimSoundManagerSaveConstruct();

    /**
     * Address: 0x007610B0 (FUN_007610B0)
     *
     * What it does:
     * Writes the owning `Sim*` (read from the `CSimSoundManager` object's
     * `mOwnerSim` field at +0x04) as an unowned tracked pointer.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00761D90 (FUN_00761D90, gpg::SerSaveConstructHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Resolves `CSimSoundManager` RTTI and installs the save-construct-args
     * callback. Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this
     * helper is drained from the pending list (vtable slot 0).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mNext) == 0x04, "CSimSoundManagerSaveConstruct::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mPrev) == 0x08, "CSimSoundManagerSaveConstruct::mPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimSoundManagerSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CSimSoundManagerSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CSimSoundManagerSaveConstruct) == 0x10, "CSimSoundManagerSaveConstruct size must be 0x10");
} // namespace moho
