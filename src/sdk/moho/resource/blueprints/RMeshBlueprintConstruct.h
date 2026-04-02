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
   */
  class RMeshBlueprintConstruct
  {
  public:
    /**
     * Address: 0x005194F0 (FUN_005194F0, sub_5194F0)
     * Slot: 0
     *
     * What it does:
     * Binds `RMeshBlueprint` construct/delete callbacks into reflected RTTI
     * (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(RMeshBlueprintConstruct, mHelperNext) == 0x04, "RMeshBlueprintConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RMeshBlueprintConstruct, mHelperPrev) == 0x08, "RMeshBlueprintConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00519040 (FUN_00519040, sub_519040)
   *
   * What it does:
   * Unlinks `RMeshBlueprintConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintConstructPrimary();

  /**
   * Address: 0x00519070 (FUN_00519070, sub_519070)
   *
   * What it does:
   * Secondary unlink thunk for `RMeshBlueprintConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintConstructSecondary();

  /**
   * Address: 0x00BC8580 (FUN_00BC8580, sub_BC8580)
   *
   * What it does:
   * Initializes and registers global construct helper for `RMeshBlueprint`.
   */
  int register_RMeshBlueprintConstruct();
} // namespace moho

