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
   * VFTABLE: 0x00E1CAA8
   * COL:  0x00E729EC
   */
  class CAiPersonalitySerializer
  {
  public:
    /**
     * Address: 0x005B9350 (FUN_005B9350)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPersonality RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiPersonalitySerializer, mHelperNext) == 0x04,
    "CAiPersonalitySerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mHelperPrev) == 0x08,
    "CAiPersonalitySerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mLoadCallback) == 0x0C,
    "CAiPersonalitySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPersonalitySerializer, mSaveCallback) == 0x10,
    "CAiPersonalitySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPersonalitySerializer) == 0x14, "CAiPersonalitySerializer size must be 0x14");
} // namespace moho
