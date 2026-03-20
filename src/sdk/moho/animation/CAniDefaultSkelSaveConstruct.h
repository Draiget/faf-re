#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelSaveConstruct
  {
  public:
    /**
     * Address: 0x0054C4D0 (FUN_0054C4D0)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into `CAniDefaultSkel` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(sizeof(CAniDefaultSkelSaveConstruct) == 0x10, "CAniDefaultSkelSaveConstruct size must be 0x10");
} // namespace moho
