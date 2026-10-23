#include "RPropBlueprint.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "gpg/core/containers/ArchiveSerialization.h"

namespace
{
  [[nodiscard]] gpg::RType* ResolveRPropBlueprintTypeCached() noexcept
  {
    gpg::RType* type = moho::RPropBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RPropBlueprint));
      moho::RPropBlueprint::sType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  gpg::RType* RPropBlueprint::sType = nullptr;

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
   * Address: 0x0051D2B0 (FUN_0051D2B0, Moho::RPropBlueprint::dtr)
   *
   * What it does:
   * Releases `Display.MeshBlueprint.name` storage -- the only lane
   * `RPropBlueprint` owns beyond its `REntityBlueprint` base -- then chains
   * into base destruction.
   */
  RPropBlueprint::~RPropBlueprint()
  {
    Display.MeshBlueprint.name.tidy(true, 0U);
  }

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

namespace moho
{
  void RPropBlueprint::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    RRuleGameRules* rules = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&rules, &owner);
    msvc8::string id;
    archive.ReadString(&id);
    RResId resId{};
    gpg::STR_CopyFilename(&resId.name, &id);
    result.SetOwned(gpg::MakeRRef(rules->GetPropBlueprint(resId)), 1u);
  }

  /**
   * Address: 0x0051DBB0 (FUN_0051DBB0)
   */
  void RPropBlueprint::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(mOwner, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive.WriteString(&mBlueprintId);
    result.SetOwned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<RPropBlueprint>`, vtable 0x00E11078.
   *
   * Address: 0x00BC8830 (FUN_00BC8830 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3150 (FUN_00BF3150 -- the global's destructor.)
   * Address: 0x0051DDD0 (FUN_0051DDD0 -- `Init`.)
   * Address: 0x0051DB30 (FUN_0051DB30 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct RPropBlueprintSaveConstruct : gpg::SerSaveConstructHelper<RPropBlueprint>
  {};

  /**
   * `gpg::SerConstructHelper<RPropBlueprint>`, vtable 0x00E11088.
   *
   * Address: 0x00BC8860 (FUN_00BC8860 -- constructs the global and registers its destructor.)
   * Address: 0x00BF3180 (FUN_00BF3180 -- the global's destructor.)
   * Address: 0x0051DE50 (FUN_0051DE50 -- `Init`.)
   * Address: 0x0051DC90 (FUN_0051DC90 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x0051E080 (FUN_0051E080 -- `Delete`.)
   */
  struct RPropBlueprintConstruct : gpg::SerConstructHelper<RPropBlueprint>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AAFCC -- process-global `RPropBlueprintSaveConstruct` singleton.
  moho::RPropBlueprintSaveConstruct gRPropBlueprintSaveConstruct;

  // Address: 0x010AAEEC -- process-global `RPropBlueprintConstruct` singleton.
  moho::RPropBlueprintConstruct gRPropBlueprintConstruct;
} // namespace
