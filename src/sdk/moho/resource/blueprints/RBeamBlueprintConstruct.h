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
  class RBeamBlueprintConstruct
  {
  public:
    /**
     * Address: 0x00510800 (FUN_00510800, sub_510800)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into RBeamBlueprint RTTI
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
    offsetof(RBeamBlueprintConstruct, mHelperNext) == 0x04, "RBeamBlueprintConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RBeamBlueprintConstruct, mHelperPrev) == 0x08, "RBeamBlueprintConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BC81E0 (FUN_00BC81E0, sub_BC81E0)
   *
   * What it does:
   * Initializes and registers global construct helper for `RBeamBlueprint`.
   */
  int register_RBeamBlueprintConstruct();
} // namespace moho
