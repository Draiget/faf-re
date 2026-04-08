#include "RTrailBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
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
  gpg::RType* gTrailBlueprintType = nullptr;
  moho::RTrailBlueprintSaveConstruct gTrailBlueprintSaveConstruct;

  void CleanupTrailBlueprintSaveConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gTrailBlueprintSaveConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0050FF60 (FUN_0050FF60)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RTrailBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0050FFE0 (FUN_0050FFE0)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RTrailBlueprint`.
   */
  void SaveConstructArgs_RTrailBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RTrailBlueprint*>(objectPtr);

    gpg::RRef ruleRef{};
    ruleRef.mObj = blueprint->mOwnerRules;
    ruleRef.mType = blueprint->mOwnerRules
      ? blueprint_ser::ResolveCachedType<RRuleGameRules>(gRuleGameRulesType)
      : nullptr;

    gpg::WriteRawPointer(archive, ruleRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive->WriteString(&blueprint->BlueprintId.name);
    result->SetOwned(1u);
  }

  /**
   * Address: 0x00510680 (FUN_00510680, sub_510680)
   *
   * What it does:
   * Binds save-construct-args callback into RTrailBlueprint RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void RTrailBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RTrailBlueprint>(gTrailBlueprintType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BC8140 (FUN_00BC8140, sub_BC8140)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RTrailBlueprint`.
   */
  int register_RTrailBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gTrailBlueprintSaveConstruct);
    gTrailBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RTrailBlueprintThunk);
    gTrailBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupTrailBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RTrailBlueprintSaveConstructBootstrap
  {
    RTrailBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_RTrailBlueprintSaveConstruct();
    }
  };

  RTrailBlueprintSaveConstructBootstrap gRTrailBlueprintSaveConstructBootstrap;
} // namespace
