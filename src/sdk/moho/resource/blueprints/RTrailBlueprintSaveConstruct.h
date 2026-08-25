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
   * VFTABLE: 0x00E0EC3C
   * COL: 0x00E68190
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RTrailBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `RTrailBlueprint` reference on load. This is
   * the save-side counterpart of `RTrailBlueprintConstruct` (that class's
   * `Init()` writes `serConstructFunc_`/`deleteFunc_`; this one writes
   * `serSaveConstructArgsFunc_`).
   */
  class RTrailBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8140 (FUN_00BC8140, dynamic initializer for the global
     * `RTrailBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    RTrailBlueprintSaveConstruct();

    /**
     * Address: 0x00510680 (FUN_00510680, gpg::SerSaveConstructHelper<Moho::RTrailBlueprint>::Init)
     *
     * What it does:
     * Resolves `RTrailBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RTrailBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RTrailBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RTrailBlueprintSaveConstruct) == 0x10, "RTrailBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x0050FF60 (FUN_0050FF60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x0050FFE0 (FUN_0050FFE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
