#include "moho/unit/CUnitMotionSerHelpers.h"

#include "moho/unit/CUnitMotionConstruct.h"
#include "moho/unit/CUnitMotionSerializer.h"

namespace
{
  /**
   * Address: 0x00BD7240 (FUN_00BD7240, dynamic initializer for the global
   * `CUnitMotionConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields (vtable slot 0 `Init()` dispatched
   * later by `gpg::SerHelperBase::InitNewHelpers`). Confirmed via raw asm:
   * base-ctor call -> field-set -> vtable-install -> atexit, with no eager
   * `RegisterConstructFunction()` dispatch (the prior recovery fabricated
   * that eager call from `register_CUnitMotionConstruct`).
   */
  moho::CUnitMotionConstruct gCUnitMotionConstruct;

  /**
   * Address: 0x00BD7280 (FUN_00BD7280, dynamic initializer for the global
   * `CUnitMotionSerializer` singleton)
   *
   * What it does:
   * Same shape as `CUnitMotionConstruct` above, independent `__xc_a` static
   * initializer.
   */
  moho::CUnitMotionSerializer gCUnitMotionSerializer;
} // namespace
