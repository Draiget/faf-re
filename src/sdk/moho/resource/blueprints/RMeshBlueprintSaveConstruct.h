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
   * VFTABLE: 0x00E0FE90
   * COL: 0x00E68C10
   *
   * Demangled: gpg::SerSaveConstructHelper<class Moho::RMeshBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `RMeshBlueprint` reference on load. This is the
   * save-side counterpart of `RMeshBlueprintConstruct` (that class's
   * `Init()` writes `serConstructFunc_`/`deleteFunc_`; this one writes
   * `serSaveConstructArgsFunc_`).
   */
  class RMeshBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8550 (FUN_00BC8550, dynamic initializer for the global
     * `RMeshBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    RMeshBlueprintSaveConstruct();

    /**
     * Address: 0x00519470 (FUN_00519470, gpg::SerSaveConstructHelper<Moho::RMeshBlueprint>::Init)
     *
     * What it does:
     * Resolves `RMeshBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(RMeshBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "RMeshBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(RMeshBlueprintSaveConstruct) == 0x10, "RMeshBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x00518F40 (FUN_00518F40, sub_518F40)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x00518FC0 (FUN_00518FC0, sub_518FC0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
