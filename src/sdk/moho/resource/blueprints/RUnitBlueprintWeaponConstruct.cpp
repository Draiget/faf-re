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
  // RUnitBlueprintWeapon has no plain `sType` static member of its own
  // (the binary's own Init() cache is `Moho__RUnitBlueprintWeapon__sType_0`,
  // IDA's disambiguation suffix implying another similarly-named RType
  // cache already exists for this type elsewhere). This TU keeps its own
  // lazily resolved cache instead of adding a new data member to
  // RUnitBlueprintWeapon's binary layout -- see the matching comment in
  // RUnitBlueprintConstruct.cpp for RUnitBlueprint's own sibling case.
  gpg::RType* gUnitBlueprintType = nullptr;
  gpg::RType* gUnitBlueprintWeaponType = nullptr;

  // Address: 0x010AB0D4 -- process-global `RUnitBlueprintWeaponConstruct`
  // singleton. Constructing it runs RUnitBlueprintWeaponConstruct::
  // RUnitBlueprintWeaponConstruct() (0x00BC8CD0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RUnitBlueprintWeaponConstruct gRUnitBlueprintWeaponConstructHelper;

  /**
   * Address: 0x00BF37E0 (FUN_00BF37E0)
   *
   * What it does:
   * Unlinks the `RUnitBlueprintWeaponConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8CD0) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x00522EE0 (FUN_00522EE0) and 0x00522F10 (FUN_00522F10) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRUnitBlueprintWeaponConstruct()
  {
    gRUnitBlueprintWeaponConstructHelper.ResetLinks();
  }

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
   * Address: 0x00BC8CD0 (FUN_00BC8CD0, dynamic initializer for the global
   * `RUnitBlueprintWeaponConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  RUnitBlueprintWeaponConstruct::RUnitBlueprintWeaponConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RUnitBlueprintWeapon))
    , mDeleteCallback(&Delete_RUnitBlueprintWeapon)
  {
    (void)std::atexit(&CleanupRUnitBlueprintWeaponConstruct);
  }

  /**
   * Address: 0x00523840 (FUN_00523840, gpg::SerConstructHelper<Moho::RUnitBlueprintWeapon>::Init)
   *
   * What it does:
   * Lazily resolves `RUnitBlueprintWeapon` RTTI and installs
   * construct/delete callbacks from this helper into the type descriptor.
   */
  void RUnitBlueprintWeaponConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RUnitBlueprintWeapon>(gUnitBlueprintWeaponType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
