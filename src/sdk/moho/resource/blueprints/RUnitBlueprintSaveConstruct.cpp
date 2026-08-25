#include "moho/resource/blueprints/RUnitBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
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
  // See the matching comment in RUnitBlueprintConstruct.cpp: RUnitBlueprint
  // has no plain `sType` static member, so this TU keeps its own lazily
  // resolved cache rather than adding a new data member to RUnitBlueprint's
  // binary layout.
  gpg::RType* gRuleGameRulesType = nullptr;
  gpg::RType* gUnitBlueprintType = nullptr;

  // Address: 0x010AB3A8 -- process-global `RUnitBlueprintSaveConstruct`
  // singleton. Constructing it runs RUnitBlueprintSaveConstruct::
  // RUnitBlueprintSaveConstruct() (0x00BC8C30), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RUnitBlueprintSaveConstruct gRUnitBlueprintSaveConstructHelper;

  /**
   * Address: 0x00BF3750 (FUN_00BF3750)
   *
   * What it does:
   * Unlinks the `RUnitBlueprintSaveConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8C30) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x00522B80 (FUN_00522B80) and 0x00522BB0 (FUN_00522BB0) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRUnitBlueprintSaveConstruct()
  {
    gRUnitBlueprintSaveConstructHelper.ResetLinks();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00522B60 (FUN_00522B60, sub_522B60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RUnitBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00522BE0 (FUN_00522BE0, sub_522BE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RUnitBlueprint*>(objectPtr);

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
   * Address: 0x00BC8C30 (FUN_00BC8C30, dynamic initializer for the global
   * `RUnitBlueprintSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the save-construct-args callback field, and
   * registers process-exit cleanup.
   */
  RUnitBlueprintSaveConstruct::RUnitBlueprintSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RUnitBlueprintThunk)
      )
  {
    (void)std::atexit(&CleanupRUnitBlueprintSaveConstruct);
  }

  /**
   * Address: 0x005236C0 (FUN_005236C0, gpg::SerSaveConstructHelper<Moho::RUnitBlueprint>::Init)
   *
   * What it does:
   * Resolves `RUnitBlueprint` RTTI and installs this helper's
   * save-construct-args callback into the type descriptor.
   */
  void RUnitBlueprintSaveConstruct::Init()
  {
    constexpr const char* kSaveConstructAssertText = "!type->mSerSaveConstructArgsFunc";
    constexpr int kSerializationSaveConstructLine = 189;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType);
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
