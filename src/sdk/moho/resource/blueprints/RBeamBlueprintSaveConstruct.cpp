#include "RBeamBlueprintSaveConstruct.h"

#include <cstdlib>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/resource/blueprints/BlueprintConstructSerializationHelpers.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
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
  gpg::RType* gBeamBlueprintType = nullptr;
  moho::RBeamBlueprintSaveConstruct gBeamBlueprintSaveConstruct;

  void CleanupBeamBlueprintSaveConstructAtexit()
  {
    (void)moho::blueprint_ser::UnlinkHelperNode(gBeamBlueprintSaveConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00510780 (FUN_00510780, sub_510780)
   *
   * What it does:
   * Binds save-construct-args callback into RBeamBlueprint RTTI
   * (`serSaveConstructArgsFunc_`).
   */
  void RBeamBlueprintSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = blueprint_ser::ResolveCachedType<RBeamBlueprint>(gBeamBlueprintType);
    GPG_ASSERT(typeInfo->serSaveConstructArgsFunc_ == nullptr);
    typeInfo->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x005101E0 (FUN_005101E0)
   *
   * What it does:
   * Thin callback thunk forwarding save-construct arg serialization for one
   * `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprintThunk(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const ownerRef,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_RBeamBlueprint(archive, objectPtr, version, ownerRef, result);
  }

  /**
   * Address: 0x00510260 (FUN_00510260)
   *
   * What it does:
   * Writes owner game-rules pointer plus blueprint id string save-construct
   * args for one `RBeamBlueprint`.
   */
  void SaveConstructArgs_RBeamBlueprint(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const blueprint = reinterpret_cast<RBeamBlueprint*>(objectPtr);

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
   * Address: 0x00BC81B0 (FUN_00BC81B0, sub_BC81B0)
   *
   * What it does:
   * Initializes and registers global save-construct helper for
   * `RBeamBlueprint`.
   */
  int register_RBeamBlueprintSaveConstruct()
  {
    blueprint_ser::InitializeHelperNode(gBeamBlueprintSaveConstruct);
    gBeamBlueprintSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_RBeamBlueprintThunk);
    gBeamBlueprintSaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&CleanupBeamBlueprintSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct RBeamBlueprintSaveConstructBootstrap
  {
    RBeamBlueprintSaveConstructBootstrap()
    {
      (void)moho::register_RBeamBlueprintSaveConstruct();
    }
  };

  RBeamBlueprintSaveConstructBootstrap gRBeamBlueprintSaveConstructBootstrap;
} // namespace
