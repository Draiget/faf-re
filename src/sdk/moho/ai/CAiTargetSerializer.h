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
   * VFTABLE: 0x00E1ED54
   * COL:  0x00E76220
   */
  class CAiTargetSerializer
  {
  public:
    /**
     * Address: 0x005E3540 (FUN_005E3540)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiTarget RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  /**
   * Address: 0x00BCEC50 (FUN_00BCEC50, register_CAiTargetSerializer)
   *
   * What it does:
   * Registers `CAiTarget` serializer callbacks and installs process-exit
   * cleanup.
   */
  int register_CAiTargetSerializer();

  static_assert(
    offsetof(CAiTargetSerializer, mHelperNext) == 0x04, "CAiTargetSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiTargetSerializer, mHelperPrev) == 0x08, "CAiTargetSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiTargetSerializer, mLoadCallback) == 0x0C, "CAiTargetSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTargetSerializer, mSaveCallback) == 0x10, "CAiTargetSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTargetSerializer) == 0x14, "CAiTargetSerializer size must be 0x14");
} // namespace moho
