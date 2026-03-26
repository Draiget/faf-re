#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E148
   * COL:  0x00E74D1C
   */
  class CAiSteeringImplSerializer
  {
  public:
    /**
     * Address: 0x005D3EB0 (FUN_005D3EB0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiSteeringImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(sizeof(CAiSteeringImplSerializer) == 0x14, "CAiSteeringImplSerializer size must be 0x14");
} // namespace moho
