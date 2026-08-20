#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC98D0 (FUN_00BC98D0, dynamic initializer for the global
     * `CAniDefaultSkelSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the save-construct-args callback field.
     */
    CAniDefaultSkelSaveConstruct();

    /**
     * Address: 0x0054C4D0 (FUN_0054C4D0)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into `CAniDefaultSkel` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(CAniDefaultSkelSaveConstruct, mNext) == 0x04, "CAniDefaultSkelSaveConstruct::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAniDefaultSkelSaveConstruct, mPrev) == 0x08, "CAniDefaultSkelSaveConstruct::mPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAniDefaultSkelSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CAniDefaultSkelSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CAniDefaultSkelSaveConstruct) == 0x10, "CAniDefaultSkelSaveConstruct size must be 0x10");
} // namespace moho
