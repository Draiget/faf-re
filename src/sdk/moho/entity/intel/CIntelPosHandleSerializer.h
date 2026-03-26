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
   * VFTABLE: 0x00E3631C
   * COL:  0x00E8FF4C
   */
  class CIntelPosHandleSerializer
  {
  public:
    /**
     * Address: 0x0076FB00 (FUN_0076FB00, gpg::SerSaveLoadHelper_CIntelPosHandle::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CIntelPosHandle RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CIntelPosHandleSerializer, mHelperNext) == 0x04, "CIntelPosHandleSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mHelperPrev) == 0x08, "CIntelPosHandleSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mLoadCallback) == 0x0C,
    "CIntelPosHandleSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelPosHandleSerializer, mSaveCallback) == 0x10,
    "CIntelPosHandleSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelPosHandleSerializer) == 0x14, "CIntelPosHandleSerializer size must be 0x14");
} // namespace moho
