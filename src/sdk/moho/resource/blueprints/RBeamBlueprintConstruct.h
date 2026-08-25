#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class RRef;
} // namespace gpg

namespace moho
{
  /**
   * Demangled: gpg::SerConstructHelper<class Moho::RBeamBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize `RBeamBlueprint`
   * references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RBeamBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC81E0 (FUN_00BC81E0, dynamic initializer for the global
     * `RBeamBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RBeamBlueprintConstruct();

    /**
     * Address: 0x00510800 (FUN_00510800, gpg::SerConstructHelper<Moho::RBeamBlueprint>::Init)
     *
     * IDA signature:
     * void __thiscall sub_510800(RBeamBlueprintConstruct *this);
     *
     * What it does:
     * Lazily resolves the `RBeamBlueprint` reflection descriptor, asserts the
     * construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RBeamBlueprintConstruct, mConstructCallback) == 0x0C,
    "RBeamBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RBeamBlueprintConstruct, mDeleteCallback) == 0x10,
    "RBeamBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RBeamBlueprintConstruct) == 0x14, "RBeamBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x00510340 (FUN_00510340, sub_510340)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves beam
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RBeamBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x00511150 (FUN_00511150)
   *
   * What it does:
   * Deletes one constructed `RBeamBlueprint`.
   */
  void Delete_RBeamBlueprint(void* objectPtr);
} // namespace moho
