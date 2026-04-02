#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RRef;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E10DCC
   * COL: 0x00E68E70
   */
  class RProjectileBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x0051CC90 (FUN_0051CC90, sub_51CC90)
     * Slot: 0
     *
     * What it does:
     * Binds `RProjectileBlueprint` save-construct-args callback into reflected
     * RTTI (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(RProjectileBlueprintSaveConstruct, mHelperNext) == 0x04,
    "RProjectileBlueprintSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RProjectileBlueprintSaveConstruct, mHelperPrev) == 0x08,
    "RProjectileBlueprintSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(RProjectileBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RProjectileBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RProjectileBlueprintSaveConstruct) == 0x10, "RProjectileBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x0051C9C0 (FUN_0051C9C0, sub_51C9C0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x0051CA40 (FUN_0051CA40, sub_51CA40)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00BF2F50 (FUN_00BF2F50, sub_BF2F50)
   *
   * What it does:
   * Unlinks `RProjectileBlueprintSaveConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RProjectileBlueprintSaveConstruct();

  /**
   * Address: 0x00BC86D0 (FUN_00BC86D0, sub_BC86D0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RProjectileBlueprint`.
   */
  int register_RProjectileBlueprintSaveConstruct();
} // namespace moho
