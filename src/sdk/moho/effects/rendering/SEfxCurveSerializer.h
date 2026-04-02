#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class SEfxCurveSerializer
  {
  public:
    /**
     * Address: 0x00515B30 (FUN_00515B30, gpg::SerSaveLoadHelper_SEfxCurve::Init)
     *
     * What it does:
     * Binds `SEfxCurve` load/save archive callbacks into its RTTI descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  /**
   * Address: 0x00BC8440 (FUN_00BC8440, register_SEfxCurveSerializer)
   *
   * What it does:
   * Initializes `SEfxCurveSerializer` callback lanes and installs process-exit
   * helper cleanup.
   */
  void register_SEfxCurveSerializer();

  static_assert(sizeof(SEfxCurveSerializer) == 0x14, "SEfxCurveSerializer size must be 0x14");
} // namespace moho
