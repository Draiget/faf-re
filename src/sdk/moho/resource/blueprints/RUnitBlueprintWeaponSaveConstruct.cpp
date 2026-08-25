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
  // See the matching comment in RUnitBlueprintWeaponConstruct.cpp:
  // RUnitBlueprintWeapon has no plain `sType` static member, so this TU
  // keeps its own lazily resolved cache rather than adding a new data
  // member to RUnitBlueprintWeapon's binary layout.
  gpg::RType* gUnitBlueprintType = nullptr;
  gpg::RType* gUnitBlueprintWeaponType = nullptr;

  // Address: 0x010AB4A8 -- process-global `RUnitBlueprintWeaponSaveConstruct`
  // singleton. Constructing it runs RUnitBlueprintWeaponSaveConstruct::
  // RUnitBlueprintWeaponSaveConstruct() (0x00BC8CA0), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction.
  moho::RUnitBlueprintWeaponSaveConstruct gRUnitBlueprintWeaponSaveConstructHelper;

  /**
   * Address: 0x00BF37B0 (FUN_00BF37B0)
   *
   * What it does:
   * Unlinks the `RUnitBlueprintWeaponSaveConstruct` helper node from
   * whatever intrusive list it currently sits in and restores a self-linked
   * sentinel state. Registered by the real dynamic initializer (0x00BC8CA0)
   * as the global's `atexit` teardown.
   *
   * ICF twins: 0x00522E00 (FUN_00522E00) and 0x00522E30 (FUN_00522E30) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRUnitBlueprintWeaponSaveConstruct()
  {
    gRUnitBlueprintWeaponSaveConstructHelper.ResetLinks();
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
   * Address: 0x00BC8CA0 (FUN_00BC8CA0, dynamic initializer for the global
   * `RUnitBlueprintWeaponSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RUnitBlueprintWeaponSaveConstruct::RUnitBlueprintWeaponSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RUnitBlueprintWeaponThunk)
      )
  {
    (void)std::atexit(&CleanupRUnitBlueprintWeaponSaveConstruct);
  }

  /**
   * Address: 0x005237C0 (FUN_005237C0, gpg::SerSaveConstructHelper<Moho::RUnitBlueprintWeapon>::Init)
   *
   * What it does:
   * Resolves `RUnitBlueprintWeapon` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RUnitBlueprintWeaponSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RUnitBlueprintWeapon>(gUnitBlueprintWeaponType);
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure(
        kSaveConstructAssertText,
        kSerializationSaveConstructLine,
        kSerializationSourcePath
      );
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho
