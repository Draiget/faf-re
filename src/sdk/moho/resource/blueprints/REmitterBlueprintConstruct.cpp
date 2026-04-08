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
  gpg::RType* gEmitterBlueprintType = nullptr;
  moho::REmitterBlueprintConstruct gEmitterBlueprintConstruct;

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

  void CleanupEmitterBlueprintConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gEmitterBlueprintConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510600 (FUN_00510600, sub_510600)
   *
   * What it does:
   * Binds construct/delete callbacks into REmitterBlueprint RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void REmitterBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<REmitterBlueprint>(gEmitterBlueprintType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

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
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<REmitterBlueprint>(gEmitterBlueprintType) : nullptr;
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
   * Address: 0x00BC8100 (FUN_00BC8100, register_REmitterBlueprintConstruct)
   *
   * What it does:
   * Initializes and registers global construct helper for `REmitterBlueprint`.
   */
  int register_REmitterBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gEmitterBlueprintConstruct);
    gEmitterBlueprintConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_REmitterBlueprint);
    gEmitterBlueprintConstruct.mDeleteCallback = &Delete_REmitterBlueprint;
    gEmitterBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupEmitterBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct REmitterBlueprintConstructBootstrap
  {
    REmitterBlueprintConstructBootstrap()
    {
      (void)moho::register_REmitterBlueprintConstruct();
    }
  };

  REmitterBlueprintConstructBootstrap gREmitterBlueprintConstructBootstrap;
} // namespace
