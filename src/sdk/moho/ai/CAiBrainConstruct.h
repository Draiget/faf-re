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
   * VFTABLE: 0x00E19A48
   * COL:  0x00E6E680
   */
  class CAiBrainConstruct
  {
  public:
    /**
     * Address: 0x0057E3E0 (FUN_0057E3E0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiBrain RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(CAiBrainConstruct, mHelperNext) == 0x04, "CAiBrainConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(CAiBrainConstruct, mHelperPrev) == 0x08, "CAiBrainConstruct::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CAiBrainConstruct, mConstructCallback) == 0x0C,
      "CAiBrainConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CAiBrainConstruct, mDeleteCallback) == 0x10, "CAiBrainConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(CAiBrainConstruct) == 0x14, "CAiBrainConstruct size must be 0x14");
} // namespace moho
