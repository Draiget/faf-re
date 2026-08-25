#include "REmitterBlueprintConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
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

  // Address: 0x010AA6C4 -- process-global `REmitterBlueprintConstruct`
  // singleton. Constructing it runs REmitterBlueprintConstruct::
  // REmitterBlueprintConstruct() (0x00BC8100), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::REmitterBlueprintConstruct gREmitterBlueprintConstructHelper;

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
   * Address: 0x0050FE40 (FUN_0050FE40)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves emitter
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_REmitterBlueprint(
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

    REmitterBlueprint* const blueprint = gameRules ? gameRules->GetEmitterBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint
      ? blueprint_ser::ResolveCachedType<REmitterBlueprint>(REmitterBlueprint::sType)
      : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x005110A0 (FUN_005110A0)
   *
   * What it does:
   * Deletes one constructed `REmitterBlueprint`.
   */
  void Delete_REmitterBlueprint(void* const objectPtr)
  {
    delete static_cast<REmitterBlueprint*>(objectPtr);
  }

  /**
   * Address: 0x00BC8100 (FUN_00BC8100, dynamic initializer for the global
   * `REmitterBlueprintConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  REmitterBlueprintConstruct::REmitterBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_REmitterBlueprint))
    , mDeleteCallback(&Delete_REmitterBlueprint)
  {}

  /**
   * Address: 0x00BF25F0 (FUN_00BF25F0, Moho::REmitterBlueprintConstruct::~REmitterBlueprintConstruct)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  REmitterBlueprintConstruct::~REmitterBlueprintConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00510600 (FUN_00510600, gpg::SerConstructHelper<Moho::REmitterBlueprint>::Init)
   *
   * What it does:
   * Lazily resolves `REmitterBlueprint` RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void REmitterBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<REmitterBlueprint>(REmitterBlueprint::sType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
