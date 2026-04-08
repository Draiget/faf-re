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
  class RBeamBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x00510780 (FUN_00510780, sub_510780)
     * Slot: 0
     *
     * What it does:
     * Binds save-construct-args callback into RBeamBlueprint RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(RBeamBlueprintSaveConstruct, mHelperNext) == 0x04,
    "RBeamBlueprintSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RBeamBlueprintSaveConstruct, mHelperPrev) == 0x08,
    "RBeamBlueprintSaveConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BC81B0 (FUN_00BC81B0, sub_BC81B0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RBeamBlueprint`.
   */
  int register_RBeamBlueprintSaveConstruct();
} // namespace moho
