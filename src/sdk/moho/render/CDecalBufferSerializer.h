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
   * VFTABLE: 0x00E373D8
   * COL: 0x00E91490
   */
  class CDecalBufferSerializer
  {
  public:
    /**
     * Address: 0x0077AB00 (FUN_0077AB00, gpg::SerSaveLoadHelper_CDecalBuffer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CDecalBuffer` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CDecalBufferSerializer, mHelperNext) == 0x04, "CDecalBufferSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CDecalBufferSerializer, mHelperPrev) == 0x08, "CDecalBufferSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CDecalBufferSerializer, mLoadCallback) == 0x0C, "CDecalBufferSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CDecalBufferSerializer, mSaveCallback) == 0x10, "CDecalBufferSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CDecalBufferSerializer) == 0x14, "CDecalBufferSerializer size must be 0x14");
} // namespace moho
