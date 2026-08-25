#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RRef;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E10DCC
   * COL: 0x00E68E70
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RProjectileBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `RProjectileBlueprint` reference on load. This
   * is the save-side counterpart of `RProjectileBlueprintConstruct` (that
   * class's `Init()` writes `serConstructFunc_`/`deleteFunc_`; this one
   * writes `serSaveConstructArgsFunc_`).
   */
  class RProjectileBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC86D0 (FUN_00BC86D0, dynamic initializer for the global
     * `RProjectileBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    RProjectileBlueprintSaveConstruct();

    /**
     * Address: 0x0051CC90 (FUN_0051CC90, gpg::SerSaveConstructHelper<Moho::RProjectileBlueprint>::Init)
     *
     * What it does:
     * Resolves `RProjectileBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RProjectileBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RProjectileBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RProjectileBlueprintSaveConstruct) == 0x10, "RProjectileBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x0051C9C0 (FUN_0051C9C0, sub_51C9C0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x0051CA40 (FUN_0051CA40, sub_51CA40)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
