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
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RUnitBlueprintWeapon>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RUnitBlueprintWeapon` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RUnitBlueprintWeaponConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8CD0 (FUN_00BC8CD0, dynamic initializer for the global
     * `RUnitBlueprintWeaponConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RUnitBlueprintWeaponConstruct();

    /**
     * Address: 0x00523840 (FUN_00523840, gpg::SerConstructHelper<Moho::RUnitBlueprintWeapon>::Init)
     *
     * What it does:
     * Lazily resolves the `RUnitBlueprintWeapon` reflection descriptor,
     * asserts the construct callback slot is empty, and publishes this
     * helper's construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
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
} // namespace moho
