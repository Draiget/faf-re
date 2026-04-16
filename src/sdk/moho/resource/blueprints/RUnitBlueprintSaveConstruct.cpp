#include "moho/resource/blueprints/RUnitBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
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
  gpg::RType* gUnitBlueprintType = nullptr;
  moho::RUnitBlueprintSaveConstruct gUnitBlueprintSaveConstruct;

  /**
   * Address: 0x00522B80 (FUN_00522B80)
   *
   * What it does:
   * Unlinks `RUnitBlueprintSaveConstruct` helper node from the global
   * serializer-helper intrusive list and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupUnitBlueprintSaveConstructHelperNodePrimary() noexcept
  {
    return moho::blueprint_ser::UnlinkHelperNode(gUnitBlueprintSaveConstruct);
  }

  /**
   * Address: 0x00522BB0 (FUN_00522BB0)
   *
   * What it does:
   * Secondary unlink entrypoint for `RUnitBlueprintSaveConstruct`
   * helper-node cleanup; behavior matches the primary lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupUnitBlueprintSaveConstructHelperNodeSecondary() noexcept
  {
    return moho::blueprint_ser::UnlinkHelperNode(gUnitBlueprintSaveConstruct);
  }

  void CleanupUnitBlueprintSaveConstructAtexit()
  {
    (void)CleanupUnitBlueprintSaveConstructHelperNodePrimary();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00522B60 (FUN_00522B60, sub_522B60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RUnitBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00522BE0 (FUN_00522BE0, sub_522BE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RUnitBlueprint`.
   */
  void SaveConstructArgs_RUnitBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RUnitBlueprint*>(objectPtr);

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
   * Address: 0x005236C0 (FUN_005236C0, sub_5236C0)
   *
   * What it does:
   * Binds `RUnitBlueprint` save-construct-args callback into reflected RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void RUnitBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RUnitBlueprint>(gUnitBlueprintType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BF3750 (FUN_00BF3750, sub_BF3750)
   *
   * What it does:
   * Unlinks `RUnitBlueprintSaveConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_RUnitBlueprintSaveConstruct()
  {
    return CleanupUnitBlueprintSaveConstructHelperNodePrimary();
  }

  /**
   * Address: 0x00BC8C30 (FUN_00BC8C30, sub_BC8C30)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RUnitBlueprint`.
   */
  int register_RUnitBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gUnitBlueprintSaveConstruct);
    gUnitBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RUnitBlueprintThunk);
    gUnitBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupUnitBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RUnitBlueprintSaveConstructBootstrap
  {
    RUnitBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_RUnitBlueprintSaveConstruct();
    }
  };

  RUnitBlueprintSaveConstructBootstrap gRUnitBlueprintSaveConstructBootstrap;
} // namespace
