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
   * Demangled: gpg::SerSaveConstructHelper<class Moho::REmitterBlueprint>
   *
   * What it does:
   * Binds the save-construct-args callback used to serialize the arguments
   * needed to reconstruct an `REmitterBlueprint` reference on load. This is
   * the save-side counterpart of `REmitterBlueprintConstruct` (that class's
   * `Init()` writes `serConstructFunc_`/`deleteFunc_`; this one writes
   * `serSaveConstructArgsFunc_`).
   */
  class REmitterBlueprintSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC80D0 (FUN_00BC80D0, dynamic initializer for the global
     * `REmitterBlueprintSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * binds the save-construct-args callback field, and registers
     * process-exit cleanup.
     */
    REmitterBlueprintSaveConstruct();

    /**
     * Address: 0x00510580 (FUN_00510580, gpg::SerSaveConstructHelper<Moho::REmitterBlueprint>::Init)
     *
     * What it does:
     * Resolves `REmitterBlueprint` RTTI and installs this helper's
     * save-construct-args callback into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };
  static_assert(
    offsetof(REmitterBlueprintSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "REmitterBlueprintSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(REmitterBlueprintSaveConstruct) == 0x10, "REmitterBlueprintSaveConstruct size must be 0x10");

  /**
   * Address: 0x0050FCE0 (FUN_0050FCE0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprintThunk(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );

  /**
   * Address: 0x0050FD60 (FUN_0050FD60)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprint(
    gpg::WriteArchive* archive,
    int objectPtr,
    int version,
    gpg::RRef* ownerRef,
    gpg::SerSaveConstructArgsResult* result
  );
} // namespace moho
