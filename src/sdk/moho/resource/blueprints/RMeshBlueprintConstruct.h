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
   * VFTABLE: 0x00E0FEA0
   * COL: 0x00E68B64
   *
   * Demangled: gpg::SerConstructHelper<class Moho::RMeshBlueprint>
   *
   * What it does:
   * Binds the construct/delete callbacks used to materialize
   * `RMeshBlueprint` references during load. Base-class construction
   * (`gpg::SerHelperBase::SerHelperBase`) self-links this node and splices it
   * into the pending `sNewHelpers` list; `InitNewHelpers` later dispatches
   * `Init()` on it.
   */
  class RMeshBlueprintConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8580 (FUN_00BC8580, dynamic initializer for the global
     * `RMeshBlueprintConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the construct/delete callback fields, and registers process-exit
     * cleanup.
     */
    RMeshBlueprintConstruct();

    /**
     * Address: 0x005194F0 (FUN_005194F0, gpg::SerConstructHelper<Moho::RMeshBlueprint>::Init)
     *
     * What it does:
     * Lazily resolves the `RMeshBlueprint` reflection descriptor, asserts the
     * construct callback slot is empty, and publishes this helper's
     * construct/delete callbacks to the descriptor.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };
  static_assert(
    offsetof(RMeshBlueprintConstruct, mConstructCallback) == 0x0C,
    "RMeshBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(RMeshBlueprintConstruct, mDeleteCallback) == 0x10,
    "RMeshBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(RMeshBlueprintConstruct) == 0x14, "RMeshBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x005190A0 (FUN_005190A0, sub_5190A0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves mesh
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RMeshBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x0051A3B0 (FUN_0051A3B0, sub_51A3B0)
   *
   * What it does:
   * Deletes one constructed `RMeshBlueprint`.
   */
  void Delete_RMeshBlueprint(void* objectPtr);
} // namespace moho
