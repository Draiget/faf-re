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
   * VFTABLE: 0x00E1DA54
   * COL:  0x00E73F44
   */
  class ReconBlipConstruct
  {
  public:
    /**
     * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into ReconBlip RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(ReconBlipConstruct, mHelperNext) == 0x04, "ReconBlipConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mHelperPrev) == 0x08, "ReconBlipConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mConstructCallback) == 0x0C,
    "ReconBlipConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipConstruct, mDeleteCallback) == 0x10, "ReconBlipConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipConstruct) == 0x14, "ReconBlipConstruct size must be 0x14");
} // namespace moho
