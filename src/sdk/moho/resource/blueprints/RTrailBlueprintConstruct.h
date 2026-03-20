#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EC4C
   * COL: 0x00E680E4
   */
  class RTrailBlueprintConstruct
  {
  public:
    /**
     * Address: 0x00510700 (FUN_00510700, sub_510700)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into RTrailBlueprint RTTI
     * (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  static_assert(sizeof(RTrailBlueprintConstruct) == 0x14, "RTrailBlueprintConstruct size must be 0x14");
} // namespace moho
