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

  // Address: 0x010AABC4 -- process-global `RMeshBlueprintConstruct` singleton.
  // Constructing it runs RMeshBlueprintConstruct::RMeshBlueprintConstruct()
  // (0x00BC8580), which splices this helper into gpg::SerHelperBase::
  // sNewHelpers; gpg::SerHelperBase::InitNewHelpers() later dispatches
  // Init() on it from within the first ReadArchive/WriteArchive construction.
  moho::RMeshBlueprintConstruct gRMeshBlueprintConstructHelper;

  /**
   * Address: 0x00BF2CF0 (FUN_00BF2CF0)
   *
   * What it does:
   * Unlinks the `RMeshBlueprintConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BC8580) as the
   * global's `atexit` teardown.
   *
   * ICF twins: 0x00519040 (FUN_00519040) and 0x00519070 (FUN_00519070) are
   * byte-identical duplicates hardcoded to this same global's link fields,
   * confirmed zero independent callers via the callgraph index -- dead
   * linker-emitted copies, not separate binary behavior.
   */
  void CleanupRMeshBlueprintConstruct()
  {
    gRMeshBlueprintConstructHelper.ResetLinks();
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
    blueprintRef.mType = blueprint ? blueprint_ser::ResolveCachedType<RMeshBlueprint>(RMeshBlueprint::sType) : nullptr;
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
   * Address: 0x00BC8580 (FUN_00BC8580, dynamic initializer for the global
   * `RMeshBlueprintConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  RMeshBlueprintConstruct::RMeshBlueprintConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_RMeshBlueprint))
    , mDeleteCallback(&Delete_RMeshBlueprint)
  {
    (void)std::atexit(&CleanupRMeshBlueprintConstruct);
  }

  /**
   * Address: 0x005194F0 (FUN_005194F0, gpg::SerConstructHelper<Moho::RMeshBlueprint>::Init)
   *
   * What it does:
   * Lazily resolves `RMeshBlueprint` RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void RMeshBlueprintConstruct::Init()
  {
    constexpr const char* kConstructAssertText = "!type->mSerConstructFunc";
    constexpr int kSerializationConstructLine = 231;
    constexpr const char* kSerializationSourcePath =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";

    gpg::RType* const type = blueprint_ser::ResolveCachedType<RMeshBlueprint>(RMeshBlueprint::sType);
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure(kConstructAssertText, kSerializationConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
