#include "moho/resource/blueprints/RMeshBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetOwned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gRuleGameRulesType = nullptr;
  gpg::RType* gMeshBlueprintType = nullptr;
  moho::RMeshBlueprintSaveConstruct gMeshBlueprintSaveConstruct;

  void CleanupMeshBlueprintSaveConstructAtexit()
  {
    (void)moho::cleanup_RMeshBlueprintSaveConstructPrimary();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00518F40 (FUN_00518F40, sub_518F40)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RMeshBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00518FC0 (FUN_00518FC0, sub_518FC0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RMeshBlueprint`.
   */
  void SaveConstructArgs_RMeshBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RMeshBlueprint*>(objectPtr);

    gpg::RRef ruleRef{};
    ruleRef.mObj = blueprint->mOwner;
    ruleRef.mType = blueprint->mOwner
      ? blueprint_ser::ResolveCachedType<RRuleGameRules>(gRuleGameRulesType)
      : nullptr;

    gpg::WriteRawPointer(archive, ruleRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive->WriteString(&blueprint->mBlueprintId);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x00519470 (FUN_00519470, sub_519470)
   *
   * What it does:
   * Binds `RMeshBlueprint` save-construct-args callback into reflected RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void RMeshBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RMeshBlueprint>(gMeshBlueprintType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00518F60 (FUN_00518F60, sub_518F60)
   *
   * What it does:
   * Unlinks `RMeshBlueprintSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintSaveConstructPrimary()
  {
    return blueprint_ser::UnlinkHelperNode(gMeshBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00518F90 (FUN_00518F90, sub_518F90)
   *
   * What it does:
   * Secondary unlink thunk for `RMeshBlueprintSaveConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_RMeshBlueprintSaveConstructSecondary()
  {
    return cleanup_RMeshBlueprintSaveConstructPrimary();
  }

  /**
   * Address: 0x00BC8550 (FUN_00BC8550, sub_BC8550)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RMeshBlueprint`.
   */
  int register_RMeshBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gMeshBlueprintSaveConstruct);
    gMeshBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RMeshBlueprintThunk);
    gMeshBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupMeshBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RMeshBlueprintSaveConstructBootstrap
  {
    RMeshBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_RMeshBlueprintSaveConstruct();
    }
  };

  RMeshBlueprintSaveConstructBootstrap gRMeshBlueprintSaveConstructBootstrap;
} // namespace

