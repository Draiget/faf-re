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
   * VFTABLE: 0x00E1C0F0
   * COL:  0x00E7162C
   */
  class CAiNavigatorLandConstruct
  {
  public:
    /**
     * Address: 0x005A73B0 (FUN_005A73B0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiNavigatorLand RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiNavigatorLandConstruct, mHelperNext) == 0x04,
    "CAiNavigatorLandConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mHelperPrev) == 0x08,
    "CAiNavigatorLandConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mConstructCallback) == 0x0C,
    "CAiNavigatorLandConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorLandConstruct, mDeleteCallback) == 0x10,
    "CAiNavigatorLandConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorLandConstruct) == 0x14, "CAiNavigatorLandConstruct size must be 0x14");
} // namespace moho

