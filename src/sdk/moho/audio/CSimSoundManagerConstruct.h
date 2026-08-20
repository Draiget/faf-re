#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E35AAC
   * COL: 0x00E8F024
   */
  class CSimSoundManagerConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC550 (FUN_00BDC550, dynamic initializer for the global
     * `CSimSoundManagerConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list, see
     * `gpg::SerHelperBase::SerHelperBase`), then binds the construct/delete
     * callback fields to `Construct`/`Deconstruct`.
     */
    CSimSoundManagerConstruct();

    /**
     * Address: 0x00761240 (FUN_00761240, Moho::CSimSoundManagerConstruct::Construct)
     *
     * What it does:
     * Reads the owning `Sim*`, allocates one `CSimSoundManager`, and returns it
     * through `SerConstructResult` as unowned payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x007623F0 (FUN_007623F0)
     *
     * What it does:
     * Deleting-teardown callback: dispatches through `ISoundManager::Destroy`
     * (vtable slot 5) with the deleting flag set, when the object pointer is
     * non-null.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00761E10 (FUN_00761E10, gpg::SerConstructHelper_CSimSoundManager::Init)
     *
     * What it does:
     * Resolves `CSimSoundManager` RTTI and installs construct/delete callbacks.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CSimSoundManagerConstruct, mNext) == 0x04, "CSimSoundManagerConstruct::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimSoundManagerConstruct, mPrev) == 0x08, "CSimSoundManagerConstruct::mPrev offset must be 0x08"
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
