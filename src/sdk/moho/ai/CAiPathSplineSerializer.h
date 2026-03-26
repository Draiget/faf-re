#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C8DC
   * COL:  0x00E726A8
   */
  class CAiPathSplineSerializer
  {
  public:
    /**
     * Address: 0x005B48E0 (FUN_005B48E0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathSpline RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(sizeof(CAiPathSplineSerializer) == 0x14, "CAiPathSplineSerializer size must be 0x14");
} // namespace moho
