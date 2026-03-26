#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CUnitMotionConstruct
  {
  public:
    /**
     * Address: 0x006BA7F0 (FUN_006BA7F0, gpg::SerConstructHelper_CUnitMotion::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into CUnitMotion RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CUnitMotionConstruct, mHelperNext) == 0x04, "CUnitMotionConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitMotionConstruct, mHelperPrev) == 0x08, "CUnitMotionConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitMotionConstruct, mConstructCallback) == 0x0C,
    "CUnitMotionConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitMotionConstruct, mDeleteCallback) == 0x10,
    "CUnitMotionConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitMotionConstruct) == 0x14, "CUnitMotionConstruct size must be 0x14");
} // namespace moho
