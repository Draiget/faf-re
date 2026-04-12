#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "Wm3Box3.h"

namespace gpg
{
  /**
   * VFTABLE: 0x00E0394C
   * COL: 0x00E601FC
   */
  class SerSaveLoadHelper_Box3f
  {
  public:
    /**
     * Address: 0x004756D0 (FUN_004756D0, gpg::SerSaveLoadHelper_Box3f::Init)
     *
     * What it does:
     * Binds Box3<float> load/save callbacks into reflected type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(SerSaveLoadHelper_Box3f, mHelperNext) == 0x04,
    "SerSaveLoadHelper_Box3f::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelper_Box3f, mHelperPrev) == 0x08,
    "SerSaveLoadHelper_Box3f::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SerSaveLoadHelper_Box3f, mLoadCallback) == 0x0C,
    "SerSaveLoadHelper_Box3f::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SerSaveLoadHelper_Box3f, mSaveCallback) == 0x10,
    "SerSaveLoadHelper_Box3f::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SerSaveLoadHelper_Box3f) == 0x14, "SerSaveLoadHelper_Box3f size must be 0x14");
} // namespace gpg
