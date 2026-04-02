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
   */
  class RProjectileBlueprintConstruct
  {
  public:
    /**
     * Address: 0x0051CD10 (FUN_0051CD10, sub_51CD10)
     * Slot: 0
     *
     * What it does:
     * Binds `RProjectileBlueprint` construct/delete callbacks into reflected
     * RTTI (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(RProjectileBlueprintConstruct, mHelperNext) == 0x04,
    "RProjectileBlueprintConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RProjectileBlueprintConstruct, mHelperPrev) == 0x08,
    "RProjectileBlueprintConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BF2F80 (FUN_00BF2F80, sub_BF2F80)
   *
   * What it does:
   * Unlinks `RProjectileBlueprintConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RProjectileBlueprintConstruct();

  /**
   * Address: 0x00BC8700 (FUN_00BC8700, sub_BC8700)
   *
   * What it does:
   * Initializes and registers global construct helper for
   * `RProjectileBlueprint`.
   */
  int register_RProjectileBlueprintConstruct();
} // namespace moho
