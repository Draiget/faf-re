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
  gpg::RType* gRuleGameRulesType = nullptr;
  gpg::RType* gUnitBlueprintType = nullptr;
  moho::RUnitBlueprintConstruct gUnitBlueprintConstruct;

  /**
   * Address: 0x00522C60 (FUN_00522C60)
   *
   * What it does:
   * Unlinks `RUnitBlueprintConstruct` helper node from the global
   * serializer-helper intrusive list and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupUnitBlueprintConstructHelperNodePrimary() noexcept
  {
    return moho::blueprint_ser::UnlinkHelperNode(gUnitBlueprintConstruct);
  }

  /**
   * Address: 0x00522C90 (FUN_00522C90)
   *
   * What it does:
   * Secondary unlink entrypoint for `RUnitBlueprintConstruct` helper-node
   * cleanup; behavior matches the primary lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupUnitBlueprintConstructHelperNodeSecondary() noexcept
  {
    return moho::blueprint_ser::UnlinkHelperNode(gUnitBlueprintConstruct);
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

  void CleanupUnitBlueprintConstructAtexit()
  {
    (void)CleanupUnitBlueprintConstructHelperNodePrimary();
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
   * Address: 0x00523740 (FUN_00523740, sub_523740)
   *
   * What it does:
   * Binds `RUnitBlueprint` construct/delete callbacks into reflected RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void RUnitBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BF3780 (FUN_00BF3780, sub_BF3780)
   *
   * What it does:
   * Unlinks `RUnitBlueprintConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintConstruct()
  {
    return CleanupUnitBlueprintConstructHelperNodePrimary();
  }

  /**
   * Address: 0x00BC8C60 (FUN_00BC8C60, sub_BC8C60)
   *
   * What it does:
   * Initializes and registers global construct helper for `RUnitBlueprint`.
   */
  int register_RUnitBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gUnitBlueprintConstruct);
    gUnitBlueprintConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RUnitBlueprint);
    gUnitBlueprintConstruct.mDeleteCallback = &Delete_RUnitBlueprint;
    gUnitBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupUnitBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintConstructBootstrap
  {
    RUnitBlueprintConstructBootstrap()
    {
      (void)moho::register_RUnitBlueprintConstruct();
    }
  };

  RUnitBlueprintConstructBootstrap gRUnitBlueprintConstructBootstrap;
} // namespace
