#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class IAiAttackerSerializer
  {
  public:
    /**
     * Address: 0x005DBC90 (FUN_005DBC90)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiAttacker RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiAttackerSerializer, mHelperNext) == 0x04, "IAiAttackerSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mHelperPrev) == 0x08, "IAiAttackerSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mLoadCallback) == 0x0C, "IAiAttackerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mSaveCallback) == 0x10, "IAiAttackerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiAttackerSerializer) == 0x14, "IAiAttackerSerializer size must be 0x14");
} // namespace moho
