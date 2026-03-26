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
   * VFTABLE: 0x00E1C0A8
   * COL:  0x00E71774
   */
  class CAiNavigatorImplSerializer
  {
  public:
    /**
     * Address: 0x005A72A0 (FUN_005A72A0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorImplSerializer, mHelperNext) == 0x04,
    "CAiNavigatorImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiNavigatorImplSerializer, mHelperPrev) == 0x08,
    "CAiNavigatorImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiNavigatorImplSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorImplSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorImplSerializer) == 0x14, "CAiNavigatorImplSerializer size must be 0x14");
} // namespace moho

