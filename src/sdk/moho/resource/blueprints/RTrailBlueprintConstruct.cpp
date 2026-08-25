#include "RTrailBlueprintConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
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

  // Address: 0x010AA64C -- process-global `RTrailBlueprintConstruct`
  // singleton. Constructing it runs RTrailBlueprintConstruct::
  // RTrailBlueprintConstruct() (0x00BC8170), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::RTrailBlueprintConstruct gRTrailBlueprintConstructHelper;

  /**
   * Address: 0x00BF2650 (FUN_00BF2650)
   *
   * What it does:
   * Unlinks the `RTrailBlueprintConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8170) as the
   * global's `atexit` teardown.
   */
  void CleanupRTrailBlueprintConstruct()
  {
    gRTrailBlueprintConstructHelper.ResetLinks();
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
   * Address: 0x005100C0 (FUN_005100C0, sub_5100C0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves trail
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RTrailBlueprint(
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

    RTrailBlueprint* const blueprint = gameRules ? gameRules->GetTrailBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RTrailBlueprint>(RTrailBlueprint::sType) : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x00511100 (FUN_00511100)
   *
   * What it does:
   * Deletes one constructed `RTrailBlueprint`.
   */
  void Delete_RTrailBlueprint(void* const objectPtr)
  {
    delete static_cast<RTrailBlueprint*>(objectPtr);
  }

  /**
   * Address: 0x00BC8170 (FUN_00BC8170, dynamic initializer for the global
   * `RTrailBlueprintConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  RTrailBlueprintConstruct::RTrailBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RTrailBlueprint))
    , mDeleteCallback(&Delete_RTrailBlueprint)
  {
    (void)std::atexit(&CleanupRTrailBlueprintConstruct);
  }

  /**
   * Address: 0x00510700 (FUN_00510700, gpg::SerConstructHelper<Moho::RTrailBlueprint>::Init)
   *
   * What it does:
   * Lazily resolves `RTrailBlueprint` RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void RTrailBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RTrailBlueprint>(RTrailBlueprint::sType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
