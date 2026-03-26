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
   * VFTABLE: 0x00E19A58
   * COL:  0x00E6E5D4
   */
  class CAiBrainSerializer
  {
  public:
    /**
     * Address: 0x0057E460 (FUN_0057E460)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiBrain RTTI.
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

  static_assert(offsetof(CAiBrainSerializer, mHelperNext) == 0x04, "CAiBrainSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CAiBrainSerializer, mHelperPrev) == 0x08, "CAiBrainSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CAiBrainSerializer, mLoadCallback) == 0x0C, "CAiBrainSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiBrainSerializer, mSaveCallback) == 0x10, "CAiBrainSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiBrainSerializer) == 0x14, "CAiBrainSerializer size must be 0x14");
} // namespace moho
