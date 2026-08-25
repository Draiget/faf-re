#include "RTrailBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

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
  gpg::RType* gRuleGameRulesType = nullptr;

  // Address: 0x010AA63C -- process-global `RTrailBlueprintSaveConstruct`
  // singleton. Constructing it runs RTrailBlueprintSaveConstruct::
  // RTrailBlueprintSaveConstruct() (0x00BC8140), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RTrailBlueprintSaveConstruct gRTrailBlueprintSaveConstructHelper;

  /**
   * Address: 0x00BF2620 (FUN_00BF2620)
   *
   * What it does:
   * Unlinks the `RTrailBlueprintSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8140) as the
   * global's `atexit` teardown.
   */
  void CleanupRTrailBlueprintSaveConstruct()
  {
    gRTrailBlueprintSaveConstructHelper.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0050FF60 (FUN_0050FF60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RTrailBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0050FFE0 (FUN_0050FFE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RTrailBlueprint*>(objectPtr);

    gpg::RRef ruleRef{};
    ruleRef.mObj = blueprint->mOwnerRules;
    ruleRef.mType = blueprint->mOwnerRules
      ? blueprint_ser::ResolveCachedType<RRuleGameRules>(gRuleGameRulesType)
      : nullptr;

    gpg::WriteRawPointer(archive, ruleRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive->WriteString(&blueprint->BlueprintId.name);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x00BC8140 (FUN_00BC8140, dynamic initializer for the global
   * `RTrailBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RTrailBlueprintSaveConstruct::RTrailBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RTrailBlueprintThunk)
      )
  {
    (void)std::atexit(&CleanupRTrailBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00510680 (FUN_00510680, gpg::SerSaveConstructHelper<Moho::RTrailBlueprint>::Init)
   *
   * What it does:
   * Resolves `RTrailBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RTrailBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RTrailBlueprint>(RTrailBlueprint::sType);
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
