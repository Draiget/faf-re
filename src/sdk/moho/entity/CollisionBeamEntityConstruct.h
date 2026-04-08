#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E26F74
   * COL: 0x00E994DC
   */
  class CollisionBeamEntitySaveConstruct
  {
  public:
    /**
     * Address: 0x006738A0 (FUN_006738A0, CollisionBeamEntity save-construct args callback)
     *
     * What it does:
     * Serializes owning `Sim` pointer as unowned save-construct argument.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00674EE0 (FUN_00674EE0, gpg::SerSaveConstructHelper_CollisionBeamEntity::Init)
     *
     * What it does:
     * Binds save-construct-args callback lane into `CollisionBeamEntity` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(CollisionBeamEntitySaveConstruct, mHelperLinks) == 0x04,
    "CollisionBeamEntitySaveConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CollisionBeamEntitySaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CollisionBeamEntitySaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(
    sizeof(CollisionBeamEntitySaveConstruct) == 0x10,
    "CollisionBeamEntitySaveConstruct size must be 0x10"
  );

  /**
   * Address: 0x00BFC340 (FUN_00BFC340, cleanup_CollisionBeamEntitySaveConstruct)
   *
   * What it does:
   * Unlinks `CollisionBeamEntitySaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntitySaveConstruct();

  /**
   * Address: 0x00BD4C60 (FUN_00BD4C60, register_CollisionBeamEntitySaveConstruct)
   *
   * What it does:
   * Initializes startup save-construct helper and schedules exit cleanup.
   */
  int register_CollisionBeamEntitySaveConstruct();

  /**
   * VFTABLE: 0x00E26F84
   * COL: 0x00E994B8
   */
  class CollisionBeamEntityConstruct
  {
  public:
    /**
     * Address: 0x00673A30 (FUN_00673A30, Moho::CollisionBeamEntityConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `CollisionBeamEntity::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x00675570 (FUN_00675570, Moho::CollisionBeamEntityConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `CollisionBeamEntity`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00674F60 (FUN_00674F60, gpg::SerConstructHelper_CollisionBeamEntity::Init)
     *
     * What it does:
     * Binds construct/delete callback lanes into `CollisionBeamEntity` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase mHelperLinks; // +0x04
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CollisionBeamEntityConstruct, mHelperLinks) == 0x04,
    "CollisionBeamEntityConstruct::mHelperLinks offset must be 0x04"
  );
  static_assert(
    offsetof(CollisionBeamEntityConstruct, mConstructCallback) == 0x0C,
    "CollisionBeamEntityConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CollisionBeamEntityConstruct, mDeleteCallback) == 0x10,
    "CollisionBeamEntityConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CollisionBeamEntityConstruct) == 0x14, "CollisionBeamEntityConstruct size must be 0x14");

  /**
   * Address: 0x00673A00 (FUN_00673A00, cleanup_CollisionBeamEntityConstruct)
   *
   * What it does:
   * Unlinks `CollisionBeamEntityConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_CollisionBeamEntityConstruct();

  /**
   * Address: 0x00BD4C90 (FUN_00BD4C90, register_CollisionBeamEntityConstruct)
   *
   * What it does:
   * Initializes startup construct helper and callback lanes for
   * `CollisionBeamEntity`.
   */
  void register_CollisionBeamEntityConstruct();
} // namespace moho
