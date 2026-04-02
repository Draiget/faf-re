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
   * VFTABLE: 0x00E2F4D4
   * COL: 0x00E8D908
   */
  class PropSaveConstruct
  {
  public:
    /**
     * Address: 0x006FA960 (FUN_006FA960, sub_6FA960)
     *
     * What it does:
     * Binds Prop save-construct-args callback into reflected RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04 (intrusive helper node)
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(offsetof(PropSaveConstruct, mHelperLinks) == 0x04, "PropSaveConstruct::mHelperLinks offset must be 0x04");
  static_assert(
    offsetof(PropSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "PropSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(PropSaveConstruct) == 0x10, "PropSaveConstruct size must be 0x10");

  /**
   * Address: 0x00BFF1D0 (FUN_00BFF1D0, sub_BFF1D0)
   *
   * What it does:
   * Unlinks `PropSaveConstruct` helper node from global serializer intrusive list.
   */
  gpg::SerHelperBase* cleanup_PropSaveConstruct();

  /**
   * Address: 0x00BD98A0 (FUN_00BD98A0, sub_BD98A0)
   *
   * What it does:
   * Initializes `PropSaveConstruct` helper callback slots and registers them.
   */
  void register_PropSaveConstruct();
} // namespace moho


