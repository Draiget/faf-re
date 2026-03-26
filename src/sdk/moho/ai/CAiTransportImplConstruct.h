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
   * VFTABLE: 0x00E1F4AC
   * COL:  0x00E76564
   */
  class CAiTransportImplConstruct
  {
  public:
    /**
     * Address: 0x005E9BB0 (FUN_005E9BB0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiTransportImpl RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;             // +0x04
    gpg::SerHelperBase* mHelperPrev;             // +0x08
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;   // +0x10
  };

  static_assert(
    offsetof(CAiTransportImplConstruct, mHelperNext) == 0x04,
    "CAiTransportImplConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiTransportImplConstruct, mHelperPrev) == 0x08,
    "CAiTransportImplConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiTransportImplConstruct, mConstructCallback) == 0x0C,
    "CAiTransportImplConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTransportImplConstruct, mDeleteCallback) == 0x10,
    "CAiTransportImplConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTransportImplConstruct) == 0x14, "CAiTransportImplConstruct size must be 0x14");
} // namespace moho
