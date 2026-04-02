#include "moho/resource/blueprints/RUnitBlueprintWeaponSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gUnitBlueprintType = nullptr;
  gpg::RType* gUnitBlueprintWeaponType = nullptr;
  moho::RUnitBlueprintWeaponSaveConstruct gUnitBlueprintWeaponSaveConstruct;

  void CleanupUnitBlueprintWeaponSaveConstructAtexit()
  {
    (void)moho::cleanup_RUnitBlueprintWeaponSaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00522DE0 (FUN_00522DE0, sub_522DE0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprintWeapon`.
   */
  void SaveConstructArgs_RUnitBlueprintWeaponThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RUnitBlueprintWeapon(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00522E60 (FUN_00522E60, sub_522E60)
   *
   * What it does:
   * Writes owner unit-blueprint pointer plus stable weapon index save-construct
   * args for one `RUnitBlueprintWeapon`.
   */
  void SaveConstructArgs_RUnitBlueprintWeapon(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const weapon = reinterpret_cast<RUnitBlueprintWeapon*>(objectPtr);

    gpg::RRef ownerBlueprintRef{};
    ownerBlueprintRef.mObj = weapon->OwnerBlueprint;
    ownerBlueprintRef.mType = weapon->OwnerBlueprint
      ? blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType)
      : nullptr;

    gpg::WriteRawPointer(archive, ownerBlueprintRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive->WriteUInt(weapon->WeaponIndex);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x005237C0 (FUN_005237C0, sub_5237C0)
   *
   * What it does:
   * Binds `RUnitBlueprintWeapon` save-construct-args callback into reflected
   * RTTI (`serSaveConstructArgsFunc_`).
   */
  void RUnitBlueprintWeaponSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RUnitBlueprintWeapon>(gUnitBlueprintWeaponType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BF37B0 (FUN_00BF37B0, sub_BF37B0)
   *
   * What it does:
   * Unlinks `RUnitBlueprintWeaponSaveConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintWeaponSaveConstruct()
  {
    return blueprint_ser::UnlinkHelperNode(gUnitBlueprintWeaponSaveConstruct);
  }

  /**
   * Address: 0x00BC8CA0 (FUN_00BC8CA0, sub_BC8CA0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RUnitBlueprintWeapon`.
   */
  int register_RUnitBlueprintWeaponSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gUnitBlueprintWeaponSaveConstruct);
    gUnitBlueprintWeaponSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RUnitBlueprintWeaponThunk);
    gUnitBlueprintWeaponSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupUnitBlueprintWeaponSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintWeaponSaveConstructBootstrap
  {
    RUnitBlueprintWeaponSaveConstructBootstrap()
    {
      (void)moho::register_RUnitBlueprintWeaponSaveConstruct();
    }
  };

  RUnitBlueprintWeaponSaveConstructBootstrap gRUnitBlueprintWeaponSaveConstructBootstrap;
} // namespace
