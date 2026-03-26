#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DB44
   * COL:  0x00E73C00
   */
  class CAiReconDBImplSerializer
  {
  public:
    /**
     * Address: 0x005C4EE0 (FUN_005C4EE0)
     *
     * What it does:
     * Binds load/save callbacks into CAiReconDBImpl RTTI
     * (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(sizeof(CAiReconDBImplSerializer) == 0x14, "CAiReconDBImplSerializer size must be 0x14");
} // namespace moho
