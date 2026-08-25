#include "moho/projectile/ProjectileSerHelpers.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;
  gpg::RType* gProjectileType = nullptr;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  // Address: 0x010B55D0 -- process-global `ProjectileSaveConstruct` singleton
  // (constructed by FUN_00BD6410, self-registering via `__xc_a`; see
  // ProjectileSerHelpers.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  moho::ProjectileSaveConstruct gProjectileSaveConstruct;

  // Address: 0x010B548C -- process-global `ProjectileConstruct` singleton
  // (constructed by FUN_00BD6440, self-registering via `__xc_a`).
  moho::ProjectileConstruct gProjectileConstruct;

  // Address: 0x010B5524 -- process-global `ProjectileSerializer` singleton
  // (constructed by FUN_00BD6480, self-registering via `__xc_a`).
  moho::ProjectileSerializer gProjectileSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0069E370 (FUN_0069E370, Moho::ProjectileSaveConstruct::SaveConstructArgs)
   *
   * What it does:
   * Serializes the owning `Sim` pointer for one `Projectile` as an unowned
   * save-construct argument.
   */
  void ProjectileSaveConstruct::SaveConstructArgs(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const projectile = reinterpret_cast<Projectile*>(objectPtr);
    if (!archive || !projectile) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = projectile->SimulationRef;
    ownerRef.mType = projectile->SimulationRef ? ResolveCachedType<Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x0069E500 (FUN_0069E500, Moho::ProjectileConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow into `Projectile::MemberConstruct`.
   */
  void ProjectileConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    if (!archive || !result) {
      return;
    }

    Projectile::MemberConstruct(archive, result);
  }

  /**
   * Address: 0x0069F880 (FUN_0069F880, Moho::ProjectileConstruct::Deconstruct)
   *
   * What it does:
   * Runs deleting-dtor teardown for one constructed `Projectile`.
   */
  void ProjectileConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const projectile = static_cast<Projectile*>(objectPtr);
    if (!projectile) {
      return;
    }

    delete projectile;
  }

  /**
   * Address: 0x0069E5D0 (FUN_0069E5D0, Moho::ProjectileSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive-load callback into `Projectile::MemberDeserialize`.
   */
  void ProjectileSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const projectile = reinterpret_cast<Projectile*>(objectPtr);
    if (!archive || !projectile) {
      return;
    }

    projectile->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0069E5E0 (FUN_0069E5E0, Moho::ProjectileSerializer::Serialize)
   *
   * What it does:
   * Forwards archive-save callback into `Projectile::MemberSerialize`.
   */
  void ProjectileSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const projectile = reinterpret_cast<Projectile*>(objectPtr);
    if (!archive || !projectile) {
      return;
    }

    projectile->MemberSerialize(archive);
  }

  /**
   * Address: 0x0069EB80 (FUN_0069EB80, Moho::ProjectileSaveConstruct::RegisterSaveConstructArgsFunction)
   *
   * What it does:
   * Binds save-construct callback into reflected RTTI for `Projectile`.
   */
  void ProjectileSaveConstruct::Init()
  {
    gpg::RType* type = Projectile::sType;
    if (!type) {
      type = ResolveCachedType<Projectile>(gProjectileType);
      Projectile::sType = type;
    }

    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x0069EC00 (FUN_0069EC00, Moho::ProjectileConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Projectile`.
   */
  void ProjectileConstruct::Init()
  {
    gpg::RType* type = Projectile::sType;
    if (!type) {
      type = ResolveCachedType<Projectile>(gProjectileType);
      Projectile::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x0069EC80 (FUN_0069EC80, gpg::SerSaveLoadHelper_Projectile::Init)
   *
   * What it does:
   * Binds load/save callbacks into reflected RTTI for `Projectile`.
   */
  void ProjectileSerializer::Init()
  {
    gpg::RType* type = Projectile::sType;
    if (!type) {
      type = ResolveCachedType<Projectile>(gProjectileType);
      Projectile::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD6410 (FUN_00BD6410, dynamic initializer for the global
   * `ProjectileSaveConstruct` singleton)
   */
  ProjectileSaveConstruct::ProjectileSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&ProjectileSaveConstruct::SaveConstructArgs)
      )
  {}

  ProjectileSaveConstruct::~ProjectileSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00BD6440 (FUN_00BD6440, dynamic initializer for the global
   * `ProjectileConstruct` singleton)
   */
  ProjectileConstruct::ProjectileConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ProjectileConstruct::Construct))
    , mDeconstructCallback(&ProjectileConstruct::Deconstruct)
  {}

  ProjectileConstruct::~ProjectileConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00BD6480 (FUN_00BD6480, dynamic initializer for the global
   * `ProjectileSerializer` singleton)
   */
  ProjectileSerializer::ProjectileSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&ProjectileSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&ProjectileSerializer::Serialize))
  {}

  ProjectileSerializer::~ProjectileSerializer()
  {
    ResetLinks();
  }
} // namespace moho
