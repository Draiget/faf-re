#include "moho/resource/blueprints/RMeshBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
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

  // Address: 0x010AAC3C -- process-global `RMeshBlueprintSaveConstruct`
  // singleton. Constructing it runs RMeshBlueprintSaveConstruct::
  // RMeshBlueprintSaveConstruct() (0x00BC8550), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RMeshBlueprintSaveConstruct gRMeshBlueprintSaveConstructHelper;

  /**
   * Address: 0x00BF2CC0 (FUN_00BF2CC0)
   *
   * What it does:
   * Unlinks the `RMeshBlueprintSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8550) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x00518F60 (FUN_00518F60) and 0x00518F90 (FUN_00518F90) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRMeshBlueprintSaveConstruct()
  {
    gRMeshBlueprintSaveConstructHelper.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00518F40 (FUN_00518F40, sub_518F40)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RMeshBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00518FC0 (FUN_00518FC0, sub_518FC0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RMeshBlueprint*>(objectPtr);

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
   * Address: 0x00BC8550 (FUN_00BC8550, dynamic initializer for the global
   * `RMeshBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RMeshBlueprintSaveConstruct::RMeshBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RMeshBlueprintThunk)
      )
  {
    (void)std::atexit(&CleanupRMeshBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00519470 (FUN_00519470, gpg::SerSaveConstructHelper<Moho::RMeshBlueprint>::Init)
   *
   * What it does:
   * Resolves `RMeshBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RMeshBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RMeshBlueprint>(RMeshBlueprint::sType);
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
