#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RRef;
  class ReadArchive;
  class SerConstructResult;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E10DDC
   * COL: 0x00E68DC4
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RProjectileBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RProjectileBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RProjectileBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8700 (FUN_00BC8700, dynamic initializer for the global
     * `RProjectileBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RProjectileBlueprintConstruct();

    /**
     * Address: 0x0051CD10 (FUN_0051CD10, gpg::SerConstructHelper<Moho::RProjectileBlueprint>::Init)
     *
     * What it does:
     * Lazily resolves the `RProjectileBlueprint` reflection descriptor,
     * asserts the construct callback slot is empty, and publishes this
     * helper's construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RProjectileBlueprintConstruct, mConstructCallback) == 0x0C,
    "RProjectileBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RProjectileBlueprintConstruct, mDeleteCallback) == 0x10,
    "RProjectileBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RProjectileBlueprintConstruct) == 0x14, "RProjectileBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x0051CB20 (FUN_0051CB20, sub_51CB20)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves
   * projectile blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RProjectileBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x0051CF40 (FUN_0051CF40, sub_51CF40)
   *
   * What it does:
   * Deletes one constructed `RProjectileBlueprint`.
   */
  void Delete_RProjectileBlueprint(void* objectPtr);
} // namespace moho
