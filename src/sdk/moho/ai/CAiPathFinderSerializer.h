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
   * VFTABLE: 0x00E1C40C
   * COL:  0x00E72058
   */
  class CAiPathFinderSerializer
  {
  public:
    /**
     * Address: 0x005AB210 (FUN_005AB210)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathFinder RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;      // +0x04
    gpg::SerHelperBase* mHelperPrev;      // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiPathFinderSerializer, mHelperNext) == 0x04,
    "CAiPathFinderSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPathFinderSerializer, mHelperPrev) == 0x08,
    "CAiPathFinderSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPathFinderSerializer, mLoadCallback) == 0x0C,
    "CAiPathFinderSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPathFinderSerializer, mSaveCallback) == 0x10,
    "CAiPathFinderSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPathFinderSerializer) == 0x14, "CAiPathFinderSerializer size must be 0x14");
} // namespace moho
