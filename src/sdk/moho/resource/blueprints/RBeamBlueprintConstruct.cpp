#include "RBeamBlueprintConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

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
  gpg::RType* gRuleGameRulesType = nullptr;

  // Address: 0x010AA73C -- process-global `RBeamBlueprintConstruct` singleton.
  // Constructing it runs RBeamBlueprintConstruct::RBeamBlueprintConstruct()
  // (0x00BC81E0), which splices this helper into gpg::SerHelperBase::
  // sNewHelpers; gpg::SerHelperBase::InitNewHelpers() later dispatches
  // Init() on it from within the first ReadArchive/WriteArchive construction.
  moho::RBeamBlueprintConstruct gRBeamBlueprintConstructHelper;

  /**
   * Address: 0x00BF26B0 (FUN_00BF26B0)
   *
   * What it does:
   * Unlinks the `RBeamBlueprintConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC81E0) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x005102E0 (FUN_005102E0) and 0x00510310 (FUN_00510310) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRBeamBlueprintConstruct()
  {
    gRBeamBlueprintConstructHelper.ResetLinks();
  }

  [[nodiscard]] moho::RRuleGameRules* ReadRuleGameRulesPointer(gpg::ReadArchive* const archive)
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
      moho::blueprint_ser::ResolveCachedType<moho::RRuleGameRules>(gRuleGameRulesType)
    );
    return static_cast<moho::RRuleGameRules*>(upcast.mObj);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510340 (FUN_00510340, sub_510340)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves beam
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RBeamBlueprint(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    RRuleGameRules* const gameRules = ReadRuleGameRulesPointer(archive);

    msvc8::string serializedId{};
    archive->ReadString(&serializedId);

    RResId lookupId{};
    gpg::STR_InitFilename(&lookupId.name, serializedId.c_str());

    RBeamBlueprint* const blueprint = gameRules ? gameRules->GetBeamBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RBeamBlueprint>(RBeamBlueprint::sType) : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x00511150 (FUN_00511150)
   *
   * What it does:
   * Deletes one constructed `RBeamBlueprint`.
   */
  void Delete_RBeamBlueprint(void* const objectPtr)
  {
    delete static_cast<RBeamBlueprint*>(objectPtr);
  }

  /**
   * Address: 0x00BC81E0 (FUN_00BC81E0, dynamic initializer for the global
   * `RBeamBlueprintConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  RBeamBlueprintConstruct::RBeamBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RBeamBlueprint))
    , mDeleteCallback(&Delete_RBeamBlueprint)
  {
    (void)std::atexit(&CleanupRBeamBlueprintConstruct);
  }

  /**
   * Address: 0x00510800 (FUN_00510800, gpg::SerConstructHelper<Moho::RBeamBlueprint>::Init)
   *
   * What it does:
   * Lazily resolves `RBeamBlueprint` RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void RBeamBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RBeamBlueprint>(RBeamBlueprint::sType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
