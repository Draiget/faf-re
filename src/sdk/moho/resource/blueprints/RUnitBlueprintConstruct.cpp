#include "moho/resource/blueprints/RUnitBlueprintConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
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
  // RUnitBlueprint (unlike RBeamBlueprint/REmitterBlueprint/RMeshBlueprint/
  // RProjectileBlueprint/RTrailBlueprint) has no plain `sType` static member
  // of its own -- the binary's own cache for this Init() is a distinct
  // global (`Moho__RUnitBlueprint__sType2`, IDA's own disambiguation suffix
  // implying more than one similarly-named RUnitBlueprint-related RType
  // cache exists). Rather than add a new static data member to
  // RUnitBlueprint's layout for this, this TU keeps its own lazily-resolved
  // cache, matching the established fallback pattern used elsewhere in this
  // codebase when the owning type exposes no such member (see
  // `CachedCEconStorageType()` in CEconomy.cpp).
  gpg::RType* gRuleGameRulesType = nullptr;
  gpg::RType* gUnitBlueprintType = nullptr;

  // Address: 0x010AAFE4 -- process-global `RUnitBlueprintConstruct` singleton.
  // Constructing it runs RUnitBlueprintConstruct::RUnitBlueprintConstruct()
  // (0x00BC8C60), which splices this helper into gpg::SerHelperBase::
  // sNewHelpers; gpg::SerHelperBase::InitNewHelpers() later dispatches
  // Init() on it from within the first ReadArchive/WriteArchive construction.
  moho::RUnitBlueprintConstruct gRUnitBlueprintConstructHelper;

  /**
   * Address: 0x00BF3780 (FUN_00BF3780)
   *
   * What it does:
   * Unlinks the `RUnitBlueprintConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8C60) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x00522C60 (FUN_00522C60) and 0x00522C90 (FUN_00522C90) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRUnitBlueprintConstruct()
  {
    gRUnitBlueprintConstructHelper.ResetLinks();
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
   * Address: 0x00522CC0 (FUN_00522CC0, sub_522CC0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves unit
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RUnitBlueprint(
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

    RUnitBlueprint* const blueprint = gameRules ? gameRules->GetUnitBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType) : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x00525D80 (FUN_00525D80, sub_525D80)
   *
   * What it does:
   * Deletes one constructed `RUnitBlueprint`.
   */
  void Delete_RUnitBlueprint(void* const objectPtr)
  {
    auto* const object = static_cast<RUnitBlueprint*>(objectPtr);
    if (object != nullptr) {
      object->~RUnitBlueprint();
      ::operator delete(object);
    }
  }

  /**
   * Address: 0x00BC8C60 (FUN_00BC8C60, dynamic initializer for the global
   * `RUnitBlueprintConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  RUnitBlueprintConstruct::RUnitBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RUnitBlueprint))
    , mDeleteCallback(&Delete_RUnitBlueprint)
  {
    (void)std::atexit(&CleanupRUnitBlueprintConstruct);
  }

  /**
   * Address: 0x00523740 (FUN_00523740, gpg::SerConstructHelper<Moho::RUnitBlueprint>::Init)
   *
   * What it does:
   * Lazily resolves `RUnitBlueprint` RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void RUnitBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
