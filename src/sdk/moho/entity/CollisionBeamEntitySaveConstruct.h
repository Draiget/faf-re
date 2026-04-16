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
   * VFTABLE: 0x00E26F74
   * COL: 0x00E994E0
   */
  class CollisionBeamEntitySaveConstruct
  {
  public:
    /**
      * Alias of FUN_00674EE0 (non-canonical helper lane).
     *
     * What it does:
     * Resolves `CollisionBeamEntity` RTTI and binds one save-construct-args
     * callback lane (`serSaveConstructArgsFunc_`).
     */
    virtual gpg::RType* Init();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(CollisionBeamEntitySaveConstruct, mHelperLinks) == 0x04,
    "CollisionBeamEntitySaveConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CollisionBeamEntitySaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CollisionBeamEntitySaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CollisionBeamEntitySaveConstruct) == 0x10, "CollisionBeamEntitySaveConstruct size must be 0x10");

  /**
   * Address: 0x00BD4C60 (FUN_00BD4C60, register_CollisionBeamEntitySaveConstruct)
   *
   * What it does:
   * Initializes startup helper links/callback lanes for
   * `CollisionBeamEntity` save-construct registration.
   */
  int register_CollisionBeamEntitySaveConstruct();

  /**
   * Address: 0x00BFC340 (FUN_00BFC340, cleanup_CollisionBeamEntitySaveConstruct)
   *
   * What it does:
   * Unlinks save-construct helper node and rewires it to self-linked state.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySaveConstruct();
} // namespace moho
