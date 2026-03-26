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
   * VFTABLE: 0x00E373E8
   * COL: 0x00E913E4
   */
  class CDecalHandleSerializer
  {
  public:
    /**
     * Address: 0x0077ABC0 (FUN_0077ABC0, gpg::SerSaveLoadHelper_CDecalHandle::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CDecalHandle RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CDecalHandleSerializer, mHelperNext) == 0x04, "CDecalHandleSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CDecalHandleSerializer, mHelperPrev) == 0x08, "CDecalHandleSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CDecalHandleSerializer, mLoadCallback) == 0x0C, "CDecalHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CDecalHandleSerializer, mSaveCallback) == 0x10, "CDecalHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CDecalHandleSerializer) == 0x14, "CDecalHandleSerializer size must be 0x14");
} // namespace moho
