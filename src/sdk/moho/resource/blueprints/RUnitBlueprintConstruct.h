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
   * VFTABLE: 0x00E15AAC
   * COL: 0x00E694FC
   */
  class RUnitBlueprintConstruct
  {
  public:
    /**
     * Address: 0x00523740 (FUN_00523740, sub_523740)
     * Slot: 0
     *
     * What it does:
     * Binds `RUnitBlueprint` construct/delete callbacks into reflected RTTI
     * (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(RUnitBlueprintConstruct, mHelperNext) == 0x04, "RUnitBlueprintConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(RUnitBlueprintConstruct, mHelperPrev) == 0x08, "RUnitBlueprintConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(RUnitBlueprintConstruct, mConstructCallback) == 0x0C,
    "RUnitBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RUnitBlueprintConstruct, mDeleteCallback) == 0x10,
    "RUnitBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RUnitBlueprintConstruct) == 0x14, "RUnitBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x00522CC0 (FUN_00522CC0, sub_522CC0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves unit
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RUnitBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x00525D80 (FUN_00525D80, sub_525D80)
   *
   * What it does:
   * Deletes one constructed `RUnitBlueprint`.
   */
  void Delete_RUnitBlueprint(void* objectPtr);

  /**
   * Address: 0x00BF3780 (FUN_00BF3780, sub_BF3780)
   *
   * What it does:
   * Unlinks `RUnitBlueprintConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintConstruct();

  /**
   * Address: 0x00BC8C60 (FUN_00BC8C60, sub_BC8C60)
   *
   * What it does:
   * Initializes and registers global construct helper for `RUnitBlueprint`.
   */
  int register_RUnitBlueprintConstruct();
} // namespace moho
