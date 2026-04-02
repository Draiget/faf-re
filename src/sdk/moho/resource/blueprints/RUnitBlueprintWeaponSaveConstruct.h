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
   * VFTABLE: 0x00E15ABC
   * COL: 0x00E69450
   */
  class RUnitBlueprintWeaponSaveConstruct
  {
  public:
    /**
     * Address: 0x005237C0 (FUN_005237C0, sub_5237C0)
     * Slot: 0
     *
     * What it does:
     * Binds `RUnitBlueprintWeapon` save-construct-args callback into reflected
     * RTTI (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(RUnitBlueprintWeaponSaveConstruct, mHelperNext) == 0x04,
    "RUnitBlueprintWeaponSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintWeaponSaveConstruct, mHelperPrev) == 0x08,
    "RUnitBlueprintWeaponSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintWeaponSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RUnitBlueprintWeaponSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(
    sizeof(RUnitBlueprintWeaponSaveConstruct) == 0x10,
    "RUnitBlueprintWeaponSaveConstruct size must be 0x10"
  );

  /**
   * Address: 0x00522DE0 (FUN_00522DE0, sub_522DE0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprintWeapon`.
   */
  void SaveConstructArgs_RUnitBlueprintWeaponThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00522E60 (FUN_00522E60, sub_522E60)
   *
   * What it does:
   * Writes owner unit-blueprint pointer plus stable weapon index save-construct
   * args for one `RUnitBlueprintWeapon`.
   */
  void SaveConstructArgs_RUnitBlueprintWeapon(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00BF37B0 (FUN_00BF37B0, sub_BF37B0)
   *
   * What it does:
   * Unlinks `RUnitBlueprintWeaponSaveConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintWeaponSaveConstruct();

  /**
   * Address: 0x00BC8CA0 (FUN_00BC8CA0, sub_BC8CA0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RUnitBlueprintWeapon`.
   */
  int register_RUnitBlueprintWeaponSaveConstruct();
} // namespace moho
