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
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RUnitBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RUnitBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RUnitBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8C60 (FUN_00BC8C60, dynamic initializer for the global
     * `RUnitBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RUnitBlueprintConstruct();

    /**
     * Address: 0x00523740 (FUN_00523740, gpg::SerConstructHelper<Moho::RUnitBlueprint>::Init)
     *
     * What it does:
     * Lazily resolves the `RUnitBlueprint` reflection descriptor, asserts
     * the construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(offsetof(RUnitBlueprintConstruct, mConstructCallback) == 0x0C, "RUnitBlueprintConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(RUnitBlueprintConstruct, mDeleteCallback) == 0x10, "RUnitBlueprintConstruct::mDeleteCallback offset must be 0x10");
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
} // namespace moho
