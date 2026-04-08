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
   */
  class RTrailBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x00510680 (FUN_00510680, sub_510680)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into RTrailBlueprint RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(RTrailBlueprintSaveConstruct, mHelperNext) == 0x04,
    "RTrailBlueprintSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RTrailBlueprintSaveConstruct, mHelperPrev) == 0x08,
    "RTrailBlueprintSaveConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BC8140 (FUN_00BC8140, sub_BC8140)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RTrailBlueprint`.
   */
  int register_RTrailBlueprintSaveConstruct();
} // namespace moho
