#include "moho/resource/blueprints/RMeshBlueprintConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprintLODTypeInfo.h"
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
  gpg::RType* gMeshBlueprintType = nullptr;
  moho::RMeshBlueprintConstruct gMeshBlueprintConstruct;

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

  void CleanupMeshBlueprintConstructAtexit()
  {
    (void)moho::cleanup_RMeshBlueprintConstructPrimary();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005190A0 (FUN_005190A0, sub_5190A0)
   *
   * What it does:
   * Reads construct args (`RRuleGameRules*`, blueprint id), resolves mesh
   * blueprint pointer, and stores it as owned construct result.
   */
  void Construct_RMeshBlueprint(
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

    RMeshBlueprint* const blueprint = gameRules ? gameRules->GetMeshBlueprint(lookupId) : nullptr;

    gpg::RRef blueprintRef{};
    blueprintRef.mObj = blueprint;
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RMeshBlueprint>(gMeshBlueprintType) : nullptr;
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x0051A3B0 (FUN_0051A3B0, sub_51A3B0)
   *
   * What it does:
   * Deletes one constructed `RMeshBlueprint`. The LOD vector storage is
   * explicitly torn down via `ClearAndFreeMeshBlueprintLodVectorStorage`
   * (`FUN_005195B0`) so the blueprint destructor flow matches the binary's
   * `RMeshBlueprint::dtr` (`FUN_00528410`) shape before releasing the
   * blueprint object block.
   */
  void Delete_RMeshBlueprint(void* const objectPtr)
  {
    auto* const object = static_cast<RMeshBlueprint*>(objectPtr);
    if (object != nullptr) {
      moho::ClearAndFreeMeshBlueprintLodVectorStorage(&object->mLods);
      object->~RMeshBlueprint();
      ::operator delete(object);
    }
  }

  /**
   * Address: 0x005194F0 (FUN_005194F0, sub_5194F0)
   *
   * What it does:
   * Binds `RMeshBlueprint` construct/delete callbacks into reflected RTTI
   * (`serConstructFunc_`, `deleteFunc_`).
   */
  void RMeshBlueprintConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RMeshBlueprint>(gMeshBlueprintType);
    GPG_ASSERT(typeInfo->serConstructFunc_ == nullptr);
    typeInfo->serConstructFunc_ = mConstructCallback;
    typeInfo->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00519040 (FUN_00519040, sub_519040)
   *
   * What it does:
   * Unlinks `RMeshBlueprintConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintConstructPrimary()
  {
    return blueprint_ser::UnlinkHelperNode(gMeshBlueprintConstruct);
  }

  /**
   * Address: 0x00519070 (FUN_00519070, sub_519070)
   *
   * What it does:
   * Secondary unlink thunk for `RMeshBlueprintConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintConstructSecondary()
  {
    return cleanup_RMeshBlueprintConstructPrimary();
  }

  /**
   * Address: 0x00BC8580 (FUN_00BC8580, sub_BC8580)
   *
   * What it does:
   * Initializes and registers global construct helper for `RMeshBlueprint`.
   */
  int register_RMeshBlueprintConstruct()
  {
    blueprint_ser::InitializeHelperNode(gMeshBlueprintConstruct);
    gMeshBlueprintConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RMeshBlueprint);
    gMeshBlueprintConstruct.mDeleteCallback = &Delete_RMeshBlueprint;
    gMeshBlueprintConstruct.RegisterConstructFunction();
    return std::atexit(&CleanupMeshBlueprintConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RMeshBlueprintConstructBootstrap
  {
    RMeshBlueprintConstructBootstrap()
    {
      (void)moho::register_RMeshBlueprintConstruct();
    }
  };

  RMeshBlueprintConstructBootstrap gRMeshBlueprintConstructBootstrap;
} // namespace
