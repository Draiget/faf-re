#include "RPropBlueprint.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RResId.h"
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
  struct SerSaveLoadHelperNodeRuntime
  {
    void* mVtable = nullptr;
    gpg::SerHelperBase* mNext = nullptr;
    gpg::SerHelperBase* mPrev = nullptr;
  };

  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mNext) == 0x04,
    "SerSaveLoadHelperNodeRuntime::mNext offset must be 0x04"
  );
  static_assert(
    offsetof(SerSaveLoadHelperNodeRuntime, mPrev) == 0x08,
    "SerSaveLoadHelperNodeRuntime::mPrev offset must be 0x08"
  );
  static_assert(sizeof(SerSaveLoadHelperNodeRuntime) == 0x0C, "SerSaveLoadHelperNodeRuntime size must be 0x0C");

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerSaveLoadHelperNode(SerSaveLoadHelperNodeRuntime& helper) noexcept
  {
    helper.mNext->mPrev = helper.mPrev;
    helper.mPrev->mNext = helper.mNext;

    gpg::SerHelperBase* const self = reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  SerSaveLoadHelperNodeRuntime gRPropBlueprintConstructHelper{};
} // namespace

namespace moho
{
  gpg::RType* RPropBlueprint::sType = nullptr;

  /**
   * Address: 0x0051DC30 (FUN_0051DC30)
   *
   * What it does:
   * Unlinks `RPropBlueprint` construct-helper links and restores the node to
   * self-linked sentinel state.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRPropBlueprintConstructHelperPrimary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRPropBlueprintConstructHelper);
  }

  /**
   * Address: 0x0051DC60 (FUN_0051DC60)
   *
   * What it does:
   * Secondary entrypoint for unlink/reset of the same
   * `RPropBlueprint` construct-helper lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupRPropBlueprintConstructHelperSecondary() noexcept
  {
    return UnlinkSerSaveLoadHelperNode(gRPropBlueprintConstructHelper);
  }

  /**
   * Address: 0x0051DC90 (FUN_0051DC90)
   *
   * What it does:
   * Reads save-construct args (`RRuleGameRules*`, prop blueprint id),
   * resolves the owning prop blueprint from game rules, and stores it as
   * owned construct-result payload.
   */
  void Construct_RPropBlueprint(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    RRuleGameRules* gameRules = nullptr;
    gpg::RRef ownerRef{};
    archive->ReadPointer_RRuleGameRules(&gameRules, &ownerRef);

    msvc8::string serializedId{};
    archive->ReadString(&serializedId);

    msvc8::string lookupId{};
    gpg::STR_CopyFilename(&lookupId, &serializedId);

    RPropBlueprint* const blueprint = gameRules != nullptr
      ? gameRules->GetPropBlueprint(lookupId)
      : nullptr;

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RPropBlueprint(&blueprintRef, blueprint);
    result->SetOwned(blueprintRef, 1u);
  }

  /**
   * Address: 0x0051E0A0 (FUN_0051E0A0)
   *
   * What it does:
   * Writes one reflected `{object,type}` lane from one `RPropBlueprint*`
   * into caller-provided `RRef` storage.
   */
  [[maybe_unused]] gpg::RRef* BuildRRefFromRPropBlueprint(
    RPropBlueprint* const blueprint,
    gpg::RRef* const outRef
  )
  {
    (void)gpg::RRef_RPropBlueprint(outRef, blueprint);
    return outRef;
  }

  /**
   * Address: 0x0051D250 (FUN_0051D250)
   * Mangled: ??0RPropBlueprint@Moho@@QAE@PAVRRuleGameRules@1@ABVRResId@1@@Z
   *
   * What it does:
   * Runs base entity-blueprint construction with `(owner, resId)` and
   * restores prop blueprint display/defense/economy defaults.
   */
  RPropBlueprint::RPropBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : REntityBlueprint(owner, resId)
    , Display()
    , Defense()
    , Economy()
  {
    Display.MeshBlueprint.name.tidy(false, 0U);
    Display.UniformScale = 1.0f;
    Defense.MaxHealth = 1.0f;
    Defense.Health = 1.0f;
    Economy.ReclaimMassMax = 0.0f;
    Economy.ReclaimEnergyMax = 0.0f;
  }

  /**
   * Local source-compat convenience constructor for scratch/default lanes.
   */
  RPropBlueprint::RPropBlueprint()
    : RPropBlueprint(nullptr, RResId{})
  {}

  /**
   * Address: 0x0051D210 (FUN_0051D210)
   * Mangled: ?GetClass@RPropBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RPropBlueprint`.
   */
  gpg::RType* RPropBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RPropBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0051D230 (FUN_0051D230)
   * Mangled: ?GetDerivedObjectRef@RPropBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RPropBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0051D370 (FUN_0051D370)
   * Mangled: ?OnInitBlueprint@RPropBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
   * to a completed, lowercase, slash-normalized resource path.
   */
  void RPropBlueprint::OnInitBlueprint()
  {
    REntityBlueprint::OnInitBlueprint();

    msvc8::string completedMeshPath = RES_CompletePath(Display.MeshBlueprint.name.c_str(), mSource.c_str());
    gpg::STR_NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath.view());
  }
} // namespace moho
