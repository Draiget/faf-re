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
   * VFTABLE: 0x00E3636C
   * COL:  0x00E8FDA4
   */
  class CIntelCounterHandleSerializer
  {
  public:
    /**
     * Address: 0x0076FC20 (FUN_0076FC20, gpg::SerSaveLoadHelper_CIntelCounterHandle::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CIntelCounterHandle RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CIntelCounterHandleSerializer, mHelperNext) == 0x04,
    "CIntelCounterHandleSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mHelperPrev) == 0x08,
    "CIntelCounterHandleSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelCounterHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelCounterHandleSerializer, mSaveCallback) == 0x10,
    "CIntelCounterHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelCounterHandleSerializer) == 0x14, "CIntelCounterHandleSerializer size must be 0x14");
} // namespace moho
