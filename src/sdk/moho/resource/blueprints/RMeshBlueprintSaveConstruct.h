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
   */
  class RMeshBlueprintSaveConstruct
  {
  public:
    /**
     * Address: 0x00519470 (FUN_00519470, sub_519470)
     * Slot: 0
     *
     * What it does:
     * Binds `RMeshBlueprint` save-construct-args callback into reflected RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(RMeshBlueprintSaveConstruct, mHelperNext) == 0x04,
    "RMeshBlueprintSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(RMeshBlueprintSaveConstruct, mHelperPrev) == 0x08,
    "RMeshBlueprintSaveConstruct::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00518F60 (FUN_00518F60, sub_518F60)
   *
   * What it does:
   * Unlinks `RMeshBlueprintSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintSaveConstructPrimary();

  /**
   * Address: 0x00518F90 (FUN_00518F90, sub_518F90)
   *
   * What it does:
   * Secondary unlink thunk for `RMeshBlueprintSaveConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintSaveConstructSecondary();

  /**
   * Address: 0x00BC8550 (FUN_00BC8550, sub_BC8550)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RMeshBlueprint`.
   */
  int register_RMeshBlueprintSaveConstruct();
} // namespace moho

