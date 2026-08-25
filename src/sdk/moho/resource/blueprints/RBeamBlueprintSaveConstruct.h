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
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RBeamBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `RBeamBlueprint` reference on load. Base-class
   * construction (`gpg::SerHelperBase::SerHelperBase`) self-links this node
   * and splices it into the pending `sNewHelpers` list; `InitNewHelpers`
   * later dispatches `Init()` on it. This is the save-side counterpart of
   * `RBeamBlueprintConstruct` (that class's `Init()` writes
   * `serConstructFunc_`/`deleteFunc_`; this one writes
   * `serSaveConstructArgsFunc_`).
   */
  class RBeamBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC81B0 (FUN_00BC81B0, dynamic initializer for the global
     * `RBeamBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    RBeamBlueprintSaveConstruct();

    /**
     * Address: 0x00510780 (FUN_00510780, gpg::SerSaveConstructHelper<Moho::RBeamBlueprint>::Init)
     *
     * What it does:
     * Resolves `RBeamBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RBeamBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RBeamBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RBeamBlueprintSaveConstruct) == 0x10, "RBeamBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x005101E0 (FUN_005101E0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00510260 (FUN_00510260)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
