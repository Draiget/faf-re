#include "moho/resource/blueprints/RUnitBlueprintWeaponConstruct.h"

#include <cstdlib>
#include <cstdint>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetOwned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  gpg::RType* gUnitBlueprintType = nullptr;
  gpg::RType* gUnitBlueprintWeaponType = nullptr;
  moho::RUnitBlueprintWeaponConstruct gUnitBlueprintWeaponConstruct;

  [[nodiscard]] moho::RUnitBlueprint* ReadUnitBlueprintPointer(gpg::ReadArchive* const archive)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (tracked.object == nullptr) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(
      source,
      moho::blueprint_ser::ResolveCachedType<moho::RUnitBlueprint>(gUnitBlueprintType)
    );
    return static_cast<moho::RUnitBlueprint*>(upcast.mObj);
  }

  void CleanupUnitBlueprintWeaponConstructAtexit()
  {
    (void)moho::cleanup_RUnitBlueprintWeaponConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00522F40 (FUN_00522F40, sub_522F40)
   *
   * What it does:
   * Reads owner `RUnitBlueprint*` plus weapon index and resolves one
   * `RUnitBlueprintWeapon*` from the owner blueprint weapon array.
   */
  void Construct_RUnitBlueprintWeapon(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    RUnitBlueprint* const ownerBlueprint = ReadUnitBlueprintPointer(archive);

    std::uint32_t weaponIndex = 0;
    archive->ReadUInt(&weaponIndex);

    RUnitBlueprintWeapon* weapon = nullptr;
    if (ownerBlueprint != nullptr) {
      weapon = &ownerBlueprint->Weapons.WeaponBlueprints[weaponIndex];
    }

    gpg::RRef weaponRef{};
    weaponRef.mObj = weapon;
    weaponRef.mType = weapon ? blueprint_ser::ResolveCachedType<RUnitBlueprintWeapon>(gUnitBlueprintWeaponType) : nullptr;
    result->SetOwned(weaponRef, 1u);
  }

  /**
   * Address: 0x00525E00 (FUN_00525E00, sub_525E00)
   *
   * What it does:
   * Deletes one constructed `RUnitBlueprintWeapon`.
   */
  void Delete_RUnitBlueprintWeapon(void* const objectPtr)
  {
    auto* const object = static_cast<RUnitBlueprintWeapon*>(objectPtr);
    if (object != nullptr) {
      object->~RUnitBlueprintWeapon();
      ::operator delete(object);
    }
  }

  /**
   * Address: 0x00523840 (FUN_00523840, sub_523840)
   *
   * What it does:
   * Binds `RUnitBlueprintWeapon` construct/delete callbacks into reflected
   * RTTI (`serConstructFunc_`, `deleteFunc_`).
   */
  void RUnitBlueprintWeaponConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RUnitBlueprintWeapon>(gUnitBlueprintWeaponType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BF37E0 (FUN_00BF37E0, sub_BF37E0)
   *
   * What it does:
   * Unlinks `RUnitBlueprintWeaponConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintWeaponConstruct()
  {
    return blueprint_ser::UnlinkHelperNode(gUnitBlueprintWeaponConstruct);
  }

  /**
   * Address: 0x00BC8CD0 (FUN_00BC8CD0, sub_BC8CD0)
   *
   * What it does:
   * Initializes and registers global construct helper for
   * `RUnitBlueprintWeapon`.
   */
  int register_RUnitBlueprintWeaponConstruct()
  {
    blueprint_ser::InitializeHelperNode(gUnitBlueprintWeaponConstruct);
    gUnitBlueprintWeaponConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RUnitBlueprintWeapon);
    gUnitBlueprintWeaponConstruct.mDeleteCallback = &Delete_RUnitBlueprintWeapon;
    gUnitBlueprintWeaponConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupUnitBlueprintWeaponConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintWeaponConstructBootstrap
  {
    RUnitBlueprintWeaponConstructBootstrap()
    {
      (void)moho::register_RUnitBlueprintWeaponConstruct();
    }
  };

  RUnitBlueprintWeaponConstructBootstrap gRUnitBlueprintWeaponConstructBootstrap;
} // namespace
