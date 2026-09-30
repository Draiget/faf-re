#include "moho/resource/blueprints/RProjectileBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

namespace
{
  gpg::RType* gRuleGameRulesType = nullptr;

  // Address: 0x010AAC54 -- process-global `RProjectileBlueprintSaveConstruct`
  // singleton. Constructing it runs RProjectileBlueprintSaveConstruct::
  // RProjectileBlueprintSaveConstruct() (0x00BC86D0), which splices this
  // helper into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::
  // InitNewHelpers() later dispatches Init() on it from within the first
  // ReadArchive/WriteArchive construction.
  moho::RProjectileBlueprintSaveConstruct gRProjectileBlueprintSaveConstructHelper;

} // namespace

namespace moho
{
  /**
   * Address: 0x0051C9C0 (FUN_0051C9C0, sub_51C9C0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RProjectileBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0051CA40 (FUN_0051CA40, sub_51CA40)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RProjectileBlueprint*>(objectPtr);

    gpg::RRef ruleRef{};
    ruleRef.mObj = blueprint->mOwner;
    ruleRef.mType = blueprint->mOwner
      ? blueprint_ser::ResolveCachedType<RRuleGameRules>(gRuleGameRulesType)
      : nullptr;

    gpg::WriteRawPointer(archive, ruleRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive->WriteString(&blueprint->mBlueprintId);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x00BC86D0 (FUN_00BC86D0, dynamic initializer for the global
   * `RProjectileBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RProjectileBlueprintSaveConstruct::RProjectileBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RProjectileBlueprintThunk)
      )
  {
  }

  /**
   * Address: 0x00BF2F50 (FUN_00BF2F50, dynamic atexit destructor for `gRProjectileBlueprintSaveConstructHelper`)
   *
   * What it does:
   * Unlinks this helper node from the serializer-helper list (the
   * `TDatListItem` base destructor). The compiler registers it with
   * `atexit` from the global's dynamic initializer (0x00BC86D0).
   * `FUN_0051C9E0` and `FUN_0051CA10` are
   * unreferenced out-of-line copies of the same body.
   */
  RProjectileBlueprintSaveConstruct::~RProjectileBlueprintSaveConstruct() = default;

  /**
   * Address: 0x0051CC90 (FUN_0051CC90, gpg::SerSaveConstructHelper<Moho::RProjectileBlueprint>::Init)
   *
   * What it does:
   * Resolves `RProjectileBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RProjectileBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RProjectileBlueprint>(RProjectileBlueprint::sType);
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
