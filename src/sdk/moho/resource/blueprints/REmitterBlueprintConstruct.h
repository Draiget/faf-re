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
  class REmitterBlueprintConstruct
  {
  public:
    /**
     * Address: 0x00510600 (FUN_00510600, sub_510600)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into REmitterBlueprint RTTI
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
    offsetof(REmitterBlueprintConstruct, mHelperNext) == 0x04,
    "REmitterBlueprintConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(REmitterBlueprintConstruct, mHelperPrev) == 0x08,
    "REmitterBlueprintConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(REmitterBlueprintConstruct, mConstructCallback) == 0x0C,
    "REmitterBlueprintConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(REmitterBlueprintConstruct, mDeleteCallback) == 0x10,
    "REmitterBlueprintConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(REmitterBlueprintConstruct) == 0x14, "REmitterBlueprintConstruct size must be 0x14");

  /**
   * Address: 0x0050FE40 (FUN_0050FE40)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves emitter
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_REmitterBlueprint(
    gpg::ReadArchive* archive,
    int objectPtr,
    int version,
    gpg::SerConstructResult* result
  );

  /**
   * Address: 0x005110A0 (FUN_005110A0)
   *
   * What it does:
   * Deletes one constructed `REmitterBlueprint`.
   */
  void Delete_REmitterBlueprint(void* objectPtr);

  /**
   * Address: 0x00BC8100 (FUN_00BC8100, register_REmitterBlueprintConstruct)
   *
   * What it does:
   * Initializes and registers global construct helper for `REmitterBlueprint`.
   */
  int register_REmitterBlueprintConstruct();
} // namespace moho
