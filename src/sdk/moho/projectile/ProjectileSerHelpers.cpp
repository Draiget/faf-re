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

#pragma init_seg(lib)

namespace
{
  gpg::RType* gSimType = nullptr;
  gpg::RType* gProjectileType = nullptr;
  moho::ProjectileSaveConstruct gProjectileSaveConstruct{};
  moho::ProjectileConstruct gProjectileConstruct{};
  moho::ProjectileSerializer gProjectileSerializer{};

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void CleanupProjectileSaveConstructAtexit()
  {
    (void)moho::cleanup_ProjectileSaveConstruct();
  }

  void CleanupProjectileConstructAtexit()
  {
    (void)moho::cleanup_ProjectileConstruct();
  }

  void CleanupProjectileSerializerAtexit()
  {
    (void)moho::cleanup_ProjectileSerializer();
  }
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
   * What it does:
   * Binds save-construct callback into reflected RTTI for `Projectile`.
   */
  void ProjectileSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* type = Projectile::sType;
    if (!type) {
      type = ResolveCachedType<Projectile>(gProjectileType);
      Projectile::sType = type;
    }

    GPG_ASSERT(
      type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback
    );
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Projectile`.
   */
  void ProjectileConstruct::RegisterConstructFunction()
  {
    gpg::RType* type = Projectile::sType;
    if (!type) {
      type = ResolveCachedType<Projectile>(gProjectileType);
      Projectile::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x0069EC80 (FUN_0069EC80, gpg::SerSaveLoadHelper_Projectile::Init)
   *
   * What it does:
   * Binds load/save callbacks into reflected RTTI for `Projectile`.
   */
  void ProjectileSerializer::RegisterSerializeFunctions()
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
   * Address: 0x00BFD670 (FUN_00BFD670, cleanup_ProjectileSaveConstruct)
   *
   * What it does:
   * Unlinks `ProjectileSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileSaveConstruct()
  {
    return UnlinkHelperNode(gProjectileSaveConstruct);
  }

  /**
   * Address: 0x00BFD6A0 (FUN_00BFD6A0, cleanup_ProjectileConstruct)
   *
   * What it does:
   * Unlinks `ProjectileConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileConstruct()
  {
    return UnlinkHelperNode(gProjectileConstruct);
  }

  /**
   * Address: 0x00BFD6D0 (FUN_00BFD6D0, cleanup_ProjectileSerializer)
   *
   * What it does:
   * Unlinks `ProjectileSerializer` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_ProjectileSerializer()
  {
    return UnlinkHelperNode(gProjectileSerializer);
  }

  /**
   * Address: 0x00BD6410 (FUN_00BD6410, register_ProjectileSaveConstruct)
   *
   * What it does:
   * Initializes and registers `ProjectileSaveConstruct` startup helper.
   */
  int register_ProjectileSaveConstruct()
  {
    InitializeHelperNode(gProjectileSaveConstruct);
    gProjectileSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&ProjectileSaveConstruct::SaveConstructArgs);
    gProjectileSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupProjectileSaveConstructAtexit);
  }

  /**
   * Address: 0x00BD6440 (FUN_00BD6440, register_ProjectileConstruct)
   *
   * What it does:
   * Initializes and registers `ProjectileConstruct` startup helper.
   */
  int register_ProjectileConstruct()
  {
    InitializeHelperNode(gProjectileConstruct);
    gProjectileConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&ProjectileConstruct::Construct);
    gProjectileConstruct.mDeconstructCallback = &ProjectileConstruct::Deconstruct;
    gProjectileConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupProjectileConstructAtexit);
  }

  /**
   * Address: 0x00BD6480 (FUN_00BD6480, register_ProjectileSerializer)
   *
   * What it does:
   * Initializes and registers `ProjectileSerializer` startup helper.
   */
  void register_ProjectileSerializer()
  {
    InitializeHelperNode(gProjectileSerializer);
    gProjectileSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&ProjectileSerializer::Deserialize);
    gProjectileSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&ProjectileSerializer::Serialize);
    gProjectileSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupProjectileSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct ProjectileSerHelpersBootstrap
  {
    ProjectileSerHelpersBootstrap()
    {
      (void)moho::register_ProjectileSaveConstruct();
      (void)moho::register_ProjectileConstruct();
      moho::register_ProjectileSerializer();
    }
  };

  ProjectileSerHelpersBootstrap gProjectileSerHelpersBootstrap;
} // namespace
