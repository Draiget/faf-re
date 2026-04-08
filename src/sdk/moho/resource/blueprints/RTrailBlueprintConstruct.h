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
   */
  class RTrailBlueprintConstruct
  {
  public:
    /**
     * Address: 0x00510700 (FUN_00510700, sub_510700)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into RTrailBlueprint RTTI
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
    offsetof(RTrailBlueprintConstruct, mHelperNext) == 0x04, "RTrailBlueprintConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RTrailBlueprintConstruct, mHelperPrev) == 0x08, "RTrailBlueprintConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BC8170 (FUN_00BC8170, sub_BC8170)
   *
   * What it does:
   * Initializes and registers global construct helper for `RTrailBlueprint`.
   */
  int register_RTrailBlueprintConstruct();
} // namespace moho
