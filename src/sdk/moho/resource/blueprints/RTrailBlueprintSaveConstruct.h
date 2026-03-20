#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0EC3C
   * COL: 0x00E68190
   */
  class RTrailBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x00510680 (FUN_00510680, sub_510680)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into RTrailBlueprint RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(sizeof(RTrailBlueprintSaveConstruct) == 0x10, "RTrailBlueprintSaveConstruct size must be 0x10");
} // namespace moho
