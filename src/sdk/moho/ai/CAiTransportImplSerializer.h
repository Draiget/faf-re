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
   * VFTABLE: 0x00E1F4BC
   * COL:  0x00E764B8
   */
  class CAiTransportImplSerializer
  {
  public:
    /**
     * Address: 0x005E9C30 (FUN_005E9C30)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiTransportImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiTransportImplSerializer, mHelperNext) == 0x04,
    "CAiTransportImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiTransportImplSerializer, mHelperPrev) == 0x08,
    "CAiTransportImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiTransportImplSerializer, mLoadCallback) == 0x0C,
    "CAiTransportImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTransportImplSerializer, mSaveCallback) == 0x10,
    "CAiTransportImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTransportImplSerializer) == 0x14, "CAiTransportImplSerializer size must be 0x14");
} // namespace moho
