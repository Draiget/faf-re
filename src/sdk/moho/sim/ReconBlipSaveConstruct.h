#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA44
   * COL:  0x00E73FF0
   */
  class ReconBlipSaveConstruct
  {
  public:
    /**
     * Address: 0x005C42B0 (FUN_005C42B0, gpg::SerSaveConstructHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds save-construct-args callback into ReconBlip RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(ReconBlipSaveConstruct, mHelperNext) == 0x04,
    "ReconBlipSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ReconBlipSaveConstruct, mHelperPrev) == 0x08,
    "ReconBlipSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ReconBlipSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "ReconBlipSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(ReconBlipSaveConstruct) == 0x10, "ReconBlipSaveConstruct size must be 0x10");
} // namespace moho
