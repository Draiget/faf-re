#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/projectile/Projectile.h"

namespace gpg
{
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  class ProjectileSaveConstruct
  {
  public:
    /**
     * Address: 0x0069E370 (FUN_0069E370, Moho::ProjectileSaveConstruct::SaveConstructArgs)
     *
     * What it does:
     * Serializes the owning `Sim` pointer for one `Projectile` as an unowned
     * save-construct argument.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0069EB80 (FUN_0069EB80, Moho::ProjectileSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds save-construct callback into reflected RTTI for `Projectile`.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(offsetof(ProjectileSaveConstruct, mHelperNext) == 0x04, "ProjectileSaveConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(ProjectileSaveConstruct, mHelperPrev) == 0x08, "ProjectileSaveConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(ProjectileSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "ProjectileSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(ProjectileSaveConstruct) == 0x10, "ProjectileSaveConstruct size must be 0x10");

  class ProjectileConstruct
  {
  public:
    /**
     * Address: 0x0069E500 (FUN_0069E500, Moho::ProjectileConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `Projectile::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0069F880 (FUN_0069F880, Moho::ProjectileConstruct::Deconstruct)
     *
     * What it does:
     * Runs deleting-dtor teardown for one constructed `Projectile`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0069EC00 (FUN_0069EC00, Moho::ProjectileConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Projectile`.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(offsetof(ProjectileConstruct, mHelperNext) == 0x04, "ProjectileConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(ProjectileConstruct, mHelperPrev) == 0x08, "ProjectileConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(ProjectileConstruct, mConstructCallback) == 0x0C,
    "ProjectileConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ProjectileConstruct, mDeconstructCallback) == 0x10,
    "ProjectileConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(ProjectileConstruct) == 0x14, "ProjectileConstruct size must be 0x14");

  class ProjectileSerializer
  {
  public:
    /**
     * Address: 0x0069E5D0 (FUN_0069E5D0, Moho::ProjectileSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load callback into `Projectile::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0069E5E0 (FUN_0069E5E0, Moho::ProjectileSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save callback into `Projectile::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0069EC80 (FUN_0069EC80, gpg::SerSaveLoadHelper_Projectile::Init)
     *
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `Projectile`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(ProjectileSerializer, mHelperNext) == 0x04, "ProjectileSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(ProjectileSerializer, mHelperPrev) == 0x08, "ProjectileSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(ProjectileSerializer, mDeserialize) == 0x0C,
    "ProjectileSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ProjectileSerializer, mSerialize) == 0x10, "ProjectileSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(ProjectileSerializer) == 0x14, "ProjectileSerializer size must be 0x14");

  /**
   * Address: 0x00BFD670 (FUN_00BFD670, cleanup_ProjectileSaveConstruct)
   *
   * What it does:
   * Unlinks `ProjectileSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileSaveConstruct();

  /**
   * Address: 0x00BFD6A0 (FUN_00BFD6A0, cleanup_ProjectileConstruct)
   *
   * What it does:
   * Unlinks `ProjectileConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileConstruct();

  /**
   * Address: 0x00BFD6D0 (FUN_00BFD6D0, cleanup_ProjectileSerializer)
   *
   * What it does:
   * Unlinks `ProjectileSerializer` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileSerializer();

  /**
   * Address: 0x00BD6410 (FUN_00BD6410, register_ProjectileSaveConstruct)
   *
   * What it does:
   * Initializes and registers `ProjectileSaveConstruct` startup helper.
   */
  int register_ProjectileSaveConstruct();

  /**
   * Address: 0x00BD6440 (FUN_00BD6440, register_ProjectileConstruct)
   *
   * What it does:
   * Initializes and registers `ProjectileConstruct` startup helper.
   */
  int register_ProjectileConstruct();

  /**
   * Address: 0x00BD6480 (FUN_00BD6480, register_ProjectileSerializer)
   *
   * What it does:
   * Initializes and registers `ProjectileSerializer` startup helper.
   */
  void register_ProjectileSerializer();
} // namespace moho
