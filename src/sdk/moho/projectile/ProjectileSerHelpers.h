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
  /**
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='ProjectileSaveConstruct@Moho'`): `FUN_00BD6410` (real,
   * `__xc_a`-reachable) vs. a dead zero-xref duplicate at `FUN_0069E340`
   * (same field writes, no `atexit` call, confirmed via raw asm never
   * live). Confirmed via raw asm: the real ctor default-constructs
   * `gpg::SerHelperBase`, binds `mSaveConstructArgsCallback` to
   * `FUN_0069E370`, installs the `ProjectileSaveConstruct` vtable, and
   * pushes plain unmangled `FUN_00BFD670` (bare unlink-then-self-link
   * shape, matching `SerHelperBase::ResetLinks()`) as its `atexit` target
   * -- no eager `RegisterSaveConstructArgsFunction`/`Init()` call exists
   * in the real ctor.
   */
  class ProjectileSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6410 (FUN_00BD6410, dynamic initializer for the global
     * `ProjectileSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    ProjectileSaveConstruct();

    /**
     * Address: 0x00BFD670 (FUN_00BFD670, Moho::ProjectileSaveConstruct::~ProjectileSaveConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_0069E3C0`/
     * `FUN_0069E3F0` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneAJ` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~ProjectileSaveConstruct();

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
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(ProjectileSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "ProjectileSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(ProjectileSaveConstruct) == 0x10, "ProjectileSaveConstruct size must be 0x10");

  /**
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='ProjectileConstruct@Moho'`): `FUN_00BD6440` (real, sole
   * writer, `__xc_a`-reachable). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mConstructCallback`/`mDeconstructCallback`
   * to `FUN_0069E500`/`FUN_0069F880`, installs the `ProjectileConstruct`
   * vtable, and pushes plain unmangled `FUN_00BFD6A0` (bare
   * unlink-then-self-link shape, matching `SerHelperBase::ResetLinks()`) as
   * its `atexit` target -- no eager `RegisterConstructFunction`/`Init()`
   * call exists in the real ctor.
   */
  class ProjectileConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6440 (FUN_00BD6440, dynamic initializer for the global
     * `ProjectileConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    ProjectileConstruct();

    /**
     * Address: 0x00BFD6A0 (FUN_00BFD6A0, Moho::ProjectileConstruct::~ProjectileConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. `FUN_0069E4A0`/
     * `FUN_0069E4D0` are dead, zero-xref duplicate-emission twins of this
     * exact body (function_sha256-confirmed), formerly modeled in
     * `moho/containers/LegacyContainerFillLanes.cpp` as
     * `gGlobalIntrusiveSentinelLaneAK` and its two reset thunks; removed in
     * favor of this citation.
     */
    ~ProjectileConstruct();

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
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback;   // +0x0C
    gpg::RType::delete_func_t mDeconstructCallback;    // +0x10
  };

  static_assert(
    offsetof(ProjectileConstruct, mConstructCallback) == 0x0C,
    "ProjectileConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ProjectileConstruct, mDeconstructCallback) == 0x10,
    "ProjectileConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(ProjectileConstruct) == 0x14, "ProjectileConstruct size must be 0x14");

  /**
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='ProjectileSerializer@Moho'`): `FUN_00BD6480` (real, sole
   * writer, `__xc_a`-reachable). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_0069E5D0`/`FUN_0069E5E0`, installs the `ProjectileSerializer`
   * vtable, and pushes the real mangled destructor
   * `??1ProjectileSerializer@Moho@@QAE@@Z` (`FUN_00BFD6D0`, confirmed
   * unlink-then-self-link shape matching `SerHelperBase::ResetLinks()`) as
   * its `atexit` target -- no eager `RegisterSerializeFunctions`/`Init()`
   * call exists in the real ctor.
   */
  class ProjectileSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD6480 (FUN_00BD6480, dynamic initializer for the global
     * `ProjectileSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    ProjectileSerializer();

    /**
     * Address: 0x00BFD6D0 (FUN_00BFD6D0, Moho::ProjectileSerializer::~ProjectileSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~ProjectileSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(ProjectileSerializer, mDeserialize) == 0x0C,
    "ProjectileSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ProjectileSerializer, mSerialize) == 0x10, "ProjectileSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(ProjectileSerializer) == 0x14, "ProjectileSerializer size must be 0x14");
} // namespace moho
