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
   * VFTABLE: 0x00E0EC4C
   * COL: 0x00E680E4
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RTrailBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RTrailBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RTrailBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8170 (FUN_00BC8170, dynamic initializer for the global
     * `RTrailBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RTrailBlueprintConstruct();

    /**
     * Address: 0x00510700 (FUN_00510700, gpg::SerConstructHelper<Moho::RTrailBlueprint>::Init)
     *
     * What it does:
     * Lazily resolves the `RTrailBlueprint` reflection descriptor, asserts
     * the construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RTrailBlueprintConstruct, mConstructCallback) == 0x0C,
    "RTrailBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RTrailBlueprintConstruct, mDeleteCallback) == 0x10,
    "RTrailBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RTrailBlueprintConstruct) == 0x14, "RTrailBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x005100C0 (FUN_005100C0, sub_5100C0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves trail
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RTrailBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x00511100 (FUN_00511100)
   *
   * What it does:
   * Deletes one constructed `RTrailBlueprint`.
   */
  void Delete_RTrailBlueprint(void* objectPtr);
} // namespace moho
