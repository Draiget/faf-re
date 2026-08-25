#include "moho/resource/blueprints/REmitterBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
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

  // Address: 0x010AA830 -- process-global `REmitterBlueprintSaveConstruct`
  // singleton. Constructing it runs REmitterBlueprintSaveConstruct::
  // REmitterBlueprintSaveConstruct() (0x00BC80D0), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::REmitterBlueprintSaveConstruct gREmitterBlueprintSaveConstructHelper;

  /**
   * Address: 0x00BF25C0 (FUN_00BF25C0)
   *
   * What it does:
   * Unlinks the `REmitterBlueprintSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC80D0) as the
   * global's `atexit` teardown.
   */
  void CleanupREmitterBlueprintSaveConstruct()
  {
    gREmitterBlueprintSaveConstructHelper.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0050FCE0 (FUN_0050FCE0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_REmitterBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0050FD60 (FUN_0050FD60)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<REmitterBlueprint*>(objectPtr);

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
   * Address: 0x00BC80D0 (FUN_00BC80D0, dynamic initializer for the global
   * `REmitterBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  REmitterBlueprintSaveConstruct::REmitterBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_REmitterBlueprintThunk)
      )
  {
    (void)std::atexit(&CleanupREmitterBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00510580 (FUN_00510580, gpg::SerSaveConstructHelper<Moho::REmitterBlueprint>::Init)
   *
   * What it does:
   * Resolves `REmitterBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void REmitterBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<REmitterBlueprint>(REmitterBlueprint::sType);
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
