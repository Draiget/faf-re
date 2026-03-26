#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CAiFormationDBImplSerializer
  {
  public:
    /**
     * Address: 0x0059CBA0 (FUN_0059CBA0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiFormationDBImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiFormationDBImplSerializer, mHelperNext) == 0x04,
    "CAiFormationDBImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiFormationDBImplSerializer, mHelperPrev) == 0x08,
    "CAiFormationDBImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiFormationDBImplSerializer, mLoadCallback) == 0x0C,
    "CAiFormationDBImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiFormationDBImplSerializer, mSaveCallback) == 0x10,
    "CAiFormationDBImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiFormationDBImplSerializer) == 0x14, "CAiFormationDBImplSerializer size must be 0x14");
} // namespace moho
