#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9900 (FUN_00BC9900, dynamic initializer for the global
     * `CAniDefaultSkelConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the construct/delete callback fields.
     */
    CAniDefaultSkelConstruct();

    /**
     * Address: 0x0054C550 (FUN_0054C550)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into `CAniDefaultSkel` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  static_assert(offsetof(CAniDefaultSkelConstruct, mNext) == 0x04, "CAniDefaultSkelConstruct::mNext offset must be 0x04");
  static_assert(offsetof(CAniDefaultSkelConstruct, mPrev) == 0x08, "CAniDefaultSkelConstruct::mPrev offset must be 0x08");
  static_assert(
    offsetof(CAniDefaultSkelConstruct, mSerConstructFunc) == 0x0C,
    "CAniDefaultSkelConstruct::mSerConstructFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CAniDefaultSkelConstruct, mDeleteFunc) == 0x10, "CAniDefaultSkelConstruct::mDeleteFunc offset must be 0x10"
  );
  static_assert(sizeof(CAniDefaultSkelConstruct) == 0x14, "CAniDefaultSkelConstruct size must be 0x14");
} // namespace moho
