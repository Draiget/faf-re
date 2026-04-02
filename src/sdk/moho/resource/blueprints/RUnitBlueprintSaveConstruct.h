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
   * VFTABLE: 0x00E15A9C
   * COL: 0x00E695A8
   */
  class RUnitBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x005236C0 (FUN_005236C0, sub_5236C0)
     * Slot: 0
     *
     * What it does:
     * Binds `RUnitBlueprint` save-construct-args callback into reflected RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(offsetof(RUnitBlueprintSaveConstruct, mHelperNext) == 0x04, "RUnitBlueprintSaveConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(RUnitBlueprintSaveConstruct, mHelperPrev) == 0x08, "RUnitBlueprintSaveConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(RUnitBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RUnitBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RUnitBlueprintSaveConstruct) == 0x10, "RUnitBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x00522B60 (FUN_00522B60, sub_522B60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00522BE0 (FUN_00522BE0, sub_522BE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00BF3750 (FUN_00BF3750, sub_BF3750)
   *
   * What it does:
   * Unlinks `RUnitBlueprintSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintSaveConstruct();

  /**
   * Address: 0x00BC8C30 (FUN_00BC8C30, sub_BC8C30)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RUnitBlueprint`.
   */
  int register_RUnitBlueprintSaveConstruct();
} // namespace moho
