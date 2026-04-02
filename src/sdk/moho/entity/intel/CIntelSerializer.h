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
   * VFTABLE: 0x00E36214
   * COL:  0x00E8FC14
   */
  class CIntelSerializer
  {
  public:
    /**
     * Address: 0x0076E810 (FUN_0076E810, gpg::SerSaveLoadHelper_CIntel::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CIntel RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CIntelSerializer, mHelperLinks) == 0x04, "CIntelSerializer::mHelperLinks offset must be 0x04");
  static_assert(
    offsetof(CIntelSerializer, mLoadCallback) == 0x0C, "CIntelSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelSerializer, mSaveCallback) == 0x10, "CIntelSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelSerializer) == 0x14, "CIntelSerializer size must be 0x14");
} // namespace moho

