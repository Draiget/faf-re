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
   * VFTABLE: 0x00E15A9C
   * COL: 0x00E695A8
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RUnitBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `RUnitBlueprint` reference on load. This is the
   * save-side counterpart of `RUnitBlueprintConstruct` (that class's
   * `Init()` writes `serConstructFunc_`/`deleteFunc_`; this one writes
   * `serSaveConstructArgsFunc_`).
   */
  class RUnitBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8C30 (FUN_00BC8C30, dynamic initializer for the global
     * `RUnitBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    RUnitBlueprintSaveConstruct();

    /**
     * Address: 0x005236C0 (FUN_005236C0, gpg::SerSaveConstructHelper<Moho::RUnitBlueprint>::Init)
     *
     * What it does:
     * Resolves `RUnitBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(offsetof(RUnitBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C, "RUnitBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C");
  static_assert(sizeof(RUnitBlueprintSaveConstruct) == 0x10, "RUnitBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x00522B60 (FUN_00522B60, sub_522B60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00522BE0 (FUN_00522BE0, sub_522BE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
