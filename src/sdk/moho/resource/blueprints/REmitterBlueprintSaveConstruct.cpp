#include "moho/resource/blueprints/REmitterBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
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
  gpg::RType* gEmitterBlueprintType = nullptr;
  moho::REmitterBlueprintSaveConstruct gEmitterBlueprintSaveConstruct;

  void CleanupEmitterBlueprintSaveConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gEmitterBlueprintSaveConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510580 (FUN_00510580, sub_510580)
   *
   * What it does:
   * Binds save-construct-args callback into REmitterBlueprint RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void REmitterBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<REmitterBlueprint>(gEmitterBlueprintType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x0050FCE0 (FUN_0050FCE0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_REmitterBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x0050FD60 (FUN_0050FD60)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `REmitterBlueprint`.
   */
  void SaveConstructArgs_REmitterBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<REmitterBlueprint*>(objectPtr);

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
   * Address: 0x00BC80D0 (FUN_00BC80D0, sub_BC80D0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `REmitterBlueprint`.
   */
  int register_REmitterBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gEmitterBlueprintSaveConstruct);
    gEmitterBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_REmitterBlueprintThunk);
    gEmitterBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupEmitterBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct REmitterBlueprintSaveConstructBootstrap
  {
    REmitterBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_REmitterBlueprintSaveConstruct();
    }
  };

  REmitterBlueprintSaveConstructBootstrap gREmitterBlueprintSaveConstructBootstrap;
} // namespace
