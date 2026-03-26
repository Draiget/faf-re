#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E16340
   * COL: 0x00E6A95C
   */
  class CAniResourceSkelSaveConstruct
  {
  public:
    /**
     * Address: 0x00539500 (FUN_00539500, gpg::SerSaveConstructHelper_CAniResourceSkel::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CAniResourceSkel` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mHelperNext) == 0x04,
    "CAniResourceSkelSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mHelperPrev) == 0x08,
    "CAniResourceSkelSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAniResourceSkelSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CAniResourceSkelSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CAniResourceSkelSaveConstruct) == 0x10, "CAniResourceSkelSaveConstruct size must be 0x10");
} // namespace moho
