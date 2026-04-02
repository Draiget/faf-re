#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E15ACC
   * COL: 0x00E693A4
   */
  class RUnitBlueprintWeaponConstruct
  {
  public:
    /**
     * Address: 0x00523840 (FUN_00523840, sub_523840)
     * Slot: 0
     *
     * What it does:
     * Binds `RUnitBlueprintWeapon` construct/delete callbacks into reflected
     * RTTI (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(RUnitBlueprintWeaponConstruct, mHelperNext) == 0x04,
    "RUnitBlueprintWeaponConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RUnitBlueprintWeaponConstruct, mHelperPrev) == 0x08,
    "RUnitBlueprintWeaponConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(RUnitBlueprintWeaponConstruct, mConstructCallback) == 0x0C,
    "RUnitBlueprintWeaponConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintWeaponConstruct, mDeleteCallback) == 0x10,
    "RUnitBlueprintWeaponConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RUnitBlueprintWeaponConstruct) == 0x14, "RUnitBlueprintWeaponConstruct size must be 0x14");

  /**
   * Address: 0x00522F40 (FUN_00522F40, sub_522F40)
   *
   * What it does:
   * Reads owner `RUnitBlueprint*` plus weapon index and resolves one
   * `RUnitBlueprintWeapon*` from the owner blueprint weapon array.
   */
  void Construct_RUnitBlueprintWeapon(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x00525E00 (FUN_00525E00, sub_525E00)
   *
   * What it does:
   * Deletes one constructed `RUnitBlueprintWeapon`.
   */
  void Delete_RUnitBlueprintWeapon(void* objectPtr);

  /**
   * Address: 0x00BF37E0 (FUN_00BF37E0, sub_BF37E0)
   *
   * What it does:
   * Unlinks `RUnitBlueprintWeaponConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintWeaponConstruct();

  /**
   * Address: 0x00BC8CD0 (FUN_00BC8CD0, sub_BC8CD0)
   *
   * What it does:
   * Initializes and registers global construct helper for
   * `RUnitBlueprintWeapon`.
   */
  int register_RUnitBlueprintWeaponConstruct();
} // namespace moho
