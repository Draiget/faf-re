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
  gpg::RType* gTrailBlueprintType = nullptr;
  moho::RTrailBlueprintConstruct gTrailBlueprintConstruct;

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

  void CleanupTrailBlueprintConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gTrailBlueprintConstruct);
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
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RTrailBlueprint>(gTrailBlueprintType) : nullptr;
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
   * Address: 0x00510700 (FUN_00510700, sub_510700)
   *
   * What it does:
   * Binds construct/delete callbacks into RTrailBlueprint RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void RTrailBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RTrailBlueprint>(gTrailBlueprintType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BC8170 (FUN_00BC8170, sub_BC8170)
   *
   * What it does:
   * Initializes and registers global construct helper for `RTrailBlueprint`.
   */
  int register_RTrailBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gTrailBlueprintConstruct);
    gTrailBlueprintConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RTrailBlueprint);
    gTrailBlueprintConstruct.mDeleteCallback = &Delete_RTrailBlueprint;
    gTrailBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupTrailBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RTrailBlueprintConstructBootstrap
  {
    RTrailBlueprintConstructBootstrap()
    {
      (void)moho::register_RTrailBlueprintConstruct();
    }
  };

  RTrailBlueprintConstructBootstrap gRTrailBlueprintConstructBootstrap;
} // namespace
