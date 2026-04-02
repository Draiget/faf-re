#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  class CMersenneTwisterSerializer
  {
  public:
    /**
     * Address: 0x0040F2C0 (FUN_0040F2C0, gpg::SerSaveLoadHelper<class Moho::CMersenneTwister>::Init)
     *
     * What it does:
     * Binds CMersenneTwister load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CMersenneTwisterSerializer, mHelperNext) == 0x04,
    "CMersenneTwisterSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CMersenneTwisterSerializer, mHelperPrev) == 0x08,
    "CMersenneTwisterSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CMersenneTwisterSerializer, mLoadCallback) == 0x0C,
    "CMersenneTwisterSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CMersenneTwisterSerializer, mSaveCallback) == 0x10,
    "CMersenneTwisterSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CMersenneTwisterSerializer) == 0x14, "CMersenneTwisterSerializer size must be 0x14");
} // namespace moho
