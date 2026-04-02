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
   * VFTABLE: 0x00E1EB24
   * COL: 0x00E756B0
   */
  class CAcquireTargetTaskSerializer
  {
  public:
    /**
     * Address: 0x005DC190 (FUN_005DC190)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CAcquireTargetTask` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;     // +0x10
  };

  /**
   * Address: 0x00BCE930 (FUN_00BCE930, register_CAcquireTargetTaskSerializer)
   *
   * What it does:
   * Constructs the global serializer owner and registers process-exit cleanup.
   */
  int register_CAcquireTargetTaskSerializer();

  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mHelperNext) == 0x04,
    "CAcquireTargetTaskSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mHelperPrev) == 0x08,
    "CAcquireTargetTaskSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mDeserialize) == 0x0C,
    "CAcquireTargetTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CAcquireTargetTaskSerializer, mSerialize) == 0x10,
    "CAcquireTargetTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CAcquireTargetTaskSerializer) == 0x14, "CAcquireTargetTaskSerializer size must be 0x14");
} // namespace moho
