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
   * VFTABLE: 0x00E1DA64
   * COL:  0x00E73E98
   */
  class ReconBlipSerializer
  {
  public:
    /**
     * Address: 0x005C43B0 (FUN_005C43B0, gpg::SerSaveLoadHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into ReconBlip RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(ReconBlipSerializer, mHelperNext) == 0x04, "ReconBlipSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ReconBlipSerializer, mHelperPrev) == 0x08, "ReconBlipSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ReconBlipSerializer, mLoadCallback) == 0x0C, "ReconBlipSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipSerializer, mSaveCallback) == 0x10, "ReconBlipSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipSerializer) == 0x14, "ReconBlipSerializer size must be 0x14");
} // namespace moho
