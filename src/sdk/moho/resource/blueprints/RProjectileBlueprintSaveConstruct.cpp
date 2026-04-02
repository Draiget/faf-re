#include "moho/resource/blueprints/RProjectileBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
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
  moho::RProjectileBlueprintSaveConstruct gProjectileBlueprintSaveConstruct;

  void CleanupProjectileBlueprintSaveConstructAtexit()
  {
    (void)moho::cleanup_RProjectileBlueprintSaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0051C9C0 (FUN_0051C9C0, sub_51C9C0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RProjectileBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0051CA40 (FUN_0051CA40, sub_51CA40)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RProjectileBlueprint`.
   */
  void SaveConstructArgs_RProjectileBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RProjectileBlueprint*>(objectPtr);

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
   * Address: 0x0051CC90 (FUN_0051CC90, sub_51CC90)
   *
   * What it does:
   * Binds `RProjectileBlueprint` save-construct-args callback into reflected
   * RTTI (`serSaveConstructArgsFunc_`).
   */
  void RProjectileBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RProjectileBlueprint>(RProjectileBlueprint::sType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BF2F50 (FUN_00BF2F50, sub_BF2F50)
   *
   * What it does:
   * Unlinks `RProjectileBlueprintSaveConstruct` helper links and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_RProjectileBlueprintSaveConstruct()
  {
    return blueprint_ser::UnlinkHelperNode(gProjectileBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00BC86D0 (FUN_00BC86D0, sub_BC86D0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RProjectileBlueprint`.
   */
  int register_RProjectileBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gProjectileBlueprintSaveConstruct);
    gProjectileBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RProjectileBlueprintThunk);
    gProjectileBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupProjectileBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RProjectileBlueprintSaveConstructBootstrap
  {
    RProjectileBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_RProjectileBlueprintSaveConstruct();
    }
  };

  RProjectileBlueprintSaveConstructBootstrap gRProjectileBlueprintSaveConstructBootstrap;
} // namespace
