#include "RBeamBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
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

  // Address: 0x010AA81C -- process-global `RBeamBlueprintSaveConstruct`
  // singleton. Constructing it runs RBeamBlueprintSaveConstruct::
  // RBeamBlueprintSaveConstruct() (0x00BC81B0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RBeamBlueprintSaveConstruct gRBeamBlueprintSaveConstructHelper;

  /**
   * Address: 0x00BF2680 (FUN_00BF2680)
   *
   * What it does:
   * Unlinks the `RBeamBlueprintSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC81B0) as the
   * global's `atexit` teardown.
   *
   * ICF twin: 0x00510230 (FUN_00510230) is a byte-identical duplicate
   * hardcoded to this same global's link fields, confirmed zero independent
   * callers via the callgraph index -- a dead linker-emitted copy.
   */
  void CleanupRBeamBlueprintSaveConstruct()
  {
    gRBeamBlueprintSaveConstructHelper.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005101E0 (FUN_005101E0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RBeamBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00510260 (FUN_00510260)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RBeamBlueprint*>(objectPtr);

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
   * Address: 0x00BC81B0 (FUN_00BC81B0, dynamic initializer for the global
   * `RBeamBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RBeamBlueprintSaveConstruct::RBeamBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RBeamBlueprintThunk)
      )
  {
    (void)std::atexit(&CleanupRBeamBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00510780 (FUN_00510780, gpg::SerSaveConstructHelper<Moho::RBeamBlueprint>::Init)
   *
   * What it does:
   * Resolves `RBeamBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RBeamBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RBeamBlueprint>(RBeamBlueprint::sType);
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
