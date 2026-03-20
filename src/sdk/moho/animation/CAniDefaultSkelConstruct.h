#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAniDefaultSkelConstruct
  {
  public:
    /**
     * Address: 0x0054C550 (FUN_0054C550)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into `CAniDefaultSkel` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  static_assert(sizeof(CAniDefaultSkelConstruct) == 0x14, "CAniDefaultSkelConstruct size must be 0x14");
} // namespace moho
