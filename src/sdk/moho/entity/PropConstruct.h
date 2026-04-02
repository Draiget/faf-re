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
   * VFTABLE: 0x00E2F4E4
   * COL: 0x00E8D85C
   */
  class PropConstruct
  {
  public:
    /**
     * Address: 0x006FA9E0 (FUN_006FA9E0, sub_6FA9E0)
     *
     * What it does:
     * Binds Prop construct/delete callbacks into reflected RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(PropConstruct, mHelperLinks) == 0x04, "PropConstruct::mHelperLinks offset must be 0x04");
  static_assert(
    offsetof(PropConstruct, mConstructCallback) == 0x0C, "PropConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(offsetof(PropConstruct, mDeleteCallback) == 0x10, "PropConstruct::mDeleteCallback offset must be 0x10");
  static_assert(sizeof(PropConstruct) == 0x14, "PropConstruct size must be 0x14");

  /**
   * Address: 0x00BFF200 (FUN_00BFF200, sub_BFF200)
   *
   * What it does:
   * Unlinks `PropConstruct` helper node from global serializer intrusive list.
   */
  gpg::SerHelperBase* cleanup_PropConstruct();

  /**
   * Address: 0x00BD98D0 (FUN_00BD98D0, sub_BD98D0)
   *
   * What it does:
   * Initializes `PropConstruct` helper callback slots and registers them.
   */
  void register_PropConstruct();
} // namespace moho


