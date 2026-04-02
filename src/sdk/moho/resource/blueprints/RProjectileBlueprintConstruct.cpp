#include "moho/resource/blueprints/RProjectileBlueprintConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
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
  moho::RProjectileBlueprintConstruct gProjectileBlueprintConstruct;

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

  void CleanupProjectileBlueprintConstructAtexit()
  {
    (void)moho::cleanup_RProjectileBlueprintConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0051CB20 (FUN_0051CB20, sub_51CB20)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves
   * projectile blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RProjectileBlueprint(
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

    RProjectileBlueprint* const blueprint = gameRules ? gameRules->GetProjectileBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RProjectileBlueprint>(RProjectileBlueprint::sType) : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x0051CF40 (FUN_0051CF40, sub_51CF40)
   *
   * What it does:
   * Deletes one constructed `RProjectileBlueprint`.
   */
  void Delete_RProjectileBlueprint(void* const objectPtr)
  {
    auto* const object = static_cast<RProjectileBlueprint*>(objectPtr);
    if (object != nullptr) {
      object->~RProjectileBlueprint();
      ::operator delete(object);
    }
  }

  /**
   * Address: 0x0051CD10 (FUN_0051CD10, sub_51CD10)
   *
   * What it does:
   * Binds `RProjectileBlueprint` construct/delete callbacks into reflected
   * RTTI (`serConstructFunc_`, `deleteFunc_`).
   */
  void RProjectileBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RProjectileBlueprint>(RProjectileBlueprint::sType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BF2F80 (FUN_00BF2F80, sub_BF2F80)
   *
   * What it does:
   * Unlinks `RProjectileBlueprintConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RProjectileBlueprintConstruct()
  {
    return blueprint_ser::UnlinkHelperNode(gProjectileBlueprintConstruct);
  }

  /**
   * Address: 0x00BC8700 (FUN_00BC8700, sub_BC8700)
   *
   * What it does:
   * Initializes and registers global construct helper for
   * `RProjectileBlueprint`.
   */
  int register_RProjectileBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gProjectileBlueprintConstruct);
    gProjectileBlueprintConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RProjectileBlueprint);
    gProjectileBlueprintConstruct.mDeleteCallback = &Delete_RProjectileBlueprint;
    gProjectileBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupProjectileBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RProjectileBlueprintConstructBootstrap
  {
    RProjectileBlueprintConstructBootstrap()
    {
      (void)moho::register_RProjectileBlueprintConstruct();
    }
  };

  RProjectileBlueprintConstructBootstrap gRProjectileBlueprintConstructBootstrap;
} // namespace
