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
   * VFTABLE: 0x00E1DE48
   * COL:  0x00E747F8
   */
  class CAiSiloBuildImplSerializer
  {
  public:
    /**
     * Address: 0x005CFF30 (FUN_005CFF30)
     *
     * void ()
     *
     * IDA signature:
     * void (__cdecl *__thiscall sub_5CFF30(_DWORD *this))(gpg::ReadArchive *, int, int, gpg::RRef *);
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiSiloBuildImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mHelperNext) == 0x04,
    "CAiSiloBuildImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mHelperPrev) == 0x08,
    "CAiSiloBuildImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mLoadCallback) == 0x0C,
    "CAiSiloBuildImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mSaveCallback) == 0x10,
    "CAiSiloBuildImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiSiloBuildImplSerializer) == 0x14, "CAiSiloBuildImplSerializer size must be 0x14");
} // namespace moho
