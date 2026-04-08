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
  gpg::RType* gBeamBlueprintType = nullptr;
  moho::RBeamBlueprintConstruct gBeamBlueprintConstruct;

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

  void CleanupBeamBlueprintConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gBeamBlueprintConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510800 (FUN_00510800, sub_510800)
   *
   * What it does:
   * Binds construct/delete callbacks into RBeamBlueprint RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void RBeamBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RBeamBlueprint>(gBeamBlueprintType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

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
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RBeamBlueprint>(gBeamBlueprintType) : nullptr;
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
   * Address: 0x00BC81E0 (FUN_00BC81E0, sub_BC81E0)
   *
   * What it does:
   * Initializes and registers global construct helper for `RBeamBlueprint`.
   */
  int register_RBeamBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gBeamBlueprintConstruct);
    gBeamBlueprintConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RBeamBlueprint);
    gBeamBlueprintConstruct.mDeleteCallback = &Delete_RBeamBlueprint;
    gBeamBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupBeamBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RBeamBlueprintConstructBootstrap
  {
    RBeamBlueprintConstructBootstrap()
    {
      (void)moho::register_RBeamBlueprintConstruct();
    }
  };

  RBeamBlueprintConstructBootstrap gRBeamBlueprintConstructBootstrap;
} // namespace
