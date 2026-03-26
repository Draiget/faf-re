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
   * VFTABLE: 0x00E1C6E4
   * COL:  0x00E723F0
   */
  class CAiPathNavigatorSerializer
  {
  public:
    /**
     * Address: 0x005B0130 (FUN_005B0130)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathNavigator RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiPathNavigatorSerializer, mHelperNext) == 0x04,
    "CAiPathNavigatorSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mHelperPrev) == 0x08,
    "CAiPathNavigatorSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mLoadCallback) == 0x0C,
    "CAiPathNavigatorSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mSaveCallback) == 0x10,
    "CAiPathNavigatorSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPathNavigatorSerializer) == 0x14, "CAiPathNavigatorSerializer size must be 0x14");
} // namespace moho
