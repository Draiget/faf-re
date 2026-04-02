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
   * VFTABLE: 0x00DFFF54
   * COL: 0x00E5C3D0
   */
  class BVIntSetSerializer
  {
  public:
    /**
     * Address: 0x004015C0 (FUN_004015C0)
     *
     * What it does:
     * Initializes serializer callback slots for BVIntSet save/load member paths.
     */
    BVIntSetSerializer();

    /**
     * Address: 0x00402620 (FUN_00402620, gpg::SerSaveLoadHelper<class Moho::BVIntSet>::Init)
     *
     * What it does:
     * Binds BVIntSet load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(BVIntSetSerializer, mHelperNext) == 0x04, "BVIntSetSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(BVIntSetSerializer, mHelperPrev) == 0x08, "BVIntSetSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(BVIntSetSerializer, mLoadCallback) == 0x0C, "BVIntSetSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(BVIntSetSerializer, mSaveCallback) == 0x10, "BVIntSetSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(BVIntSetSerializer) == 0x14, "BVIntSetSerializer size must be 0x14");
} // namespace moho
