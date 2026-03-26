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
   * VFTABLE: 0x00E1F3B8
   * COL:  0x00E766B0
   */
  class IAiTransportSerializer
  {
  public:
    /**
     * Address: 0x005E9530 (FUN_005E9530)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiTransport RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiTransportSerializer, mHelperNext) == 0x04, "IAiTransportSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiTransportSerializer, mHelperPrev) == 0x08, "IAiTransportSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiTransportSerializer, mLoadCallback) == 0x0C,
    "IAiTransportSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiTransportSerializer, mSaveCallback) == 0x10,
    "IAiTransportSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiTransportSerializer) == 0x14, "IAiTransportSerializer size must be 0x14");
} // namespace moho
