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
  class REmitterBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x00510580 (FUN_00510580, sub_510580)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into REmitterBlueprint RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(REmitterBlueprintSaveConstruct, mHelperNext) == 0x04,
    "REmitterBlueprintSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(REmitterBlueprintSaveConstruct, mHelperPrev) == 0x08,
    "REmitterBlueprintSaveConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BC80D0 (FUN_00BC80D0, sub_BC80D0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `REmitterBlueprint`.
   */
  int register_REmitterBlueprintSaveConstruct();
} // namespace moho
