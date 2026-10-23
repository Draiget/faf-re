#include "RBeamBlueprint.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  gpg::RType* RBeamBlueprint::sType = nullptr;

  /**
   * Address: 0x0050EEF0 (FUN_0050EEF0, ??0RBeamBlueprint@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes base effect-blueprint ownership lanes and beam defaults:
   * length/lifetime/thickness, texture/color ramps, LOD cutoff, and blend mode.
   */
  RBeamBlueprint::RBeamBlueprint()
  {
    mOwnerRules = nullptr;
    BlueprintId = RResId{};

    Length = 10.0f;
    Lifetime = 1.0f;
    Thickness = 1.0f;
    UShift = 0.0f;
    VShift = 0.0f;

    HighFidelity = 1u;
    MedFidelity = 1u;
    LowFidelity = 1u;

    TextureName = msvc8::string{};
    StartColor = Vector4f(1.0f, 1.0f, 1.0f, 0.0f);
    EndColor = Vector4f(1.0f, 1.0f, 1.0f, 0.0f);

    LODCutoff = 200.0f;
    RepeatRate = 0.0f;
    BlendMode = 3;
  }

  /**
   * Address: 0x0050EFD0 (FUN_0050EFD0, Moho::RBeamBlueprint::dtr core)
   * Address: 0x0050EFB0 (FUN_0050EFB0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the core body above then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * What it does:
   * Releases beam texture string storage and resets base resource-id storage.
   */
  RBeamBlueprint::~RBeamBlueprint()
  {
    TextureName.tidy(true, 0U);
    BlueprintId.name.tidy(true, 0U);
  }

  /**
   * Address: 0x0050EEB0 (FUN_0050EEB0)
   * Mangled: ?GetClass@RBeamBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RBeamBlueprint`.
   */
  gpg::RType* RBeamBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RBeamBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0050EED0 (FUN_0050EED0)
   * Mangled: ?GetDerivedObjectRef@RBeamBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RBeamBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0050EFA0 (FUN_0050EFA0)
   *
   * What it does:
   * Beam cast hook for effect-blueprint unions. Returns `this`.
   */
  RBeamBlueprint* RBeamBlueprint::IsBeam()
  {
    return this;
  }
} // namespace moho

namespace moho
{
  void RBeamBlueprint::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    RRuleGameRules* rules = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&rules, &owner);
    msvc8::string id;
    archive.ReadString(&id);
    RResId resId{};
    gpg::STR_CopyFilename(&resId.name, &id);
    result.SetOwned(gpg::MakeRRef(rules->GetBeamBlueprint(resId)), 1u);
  }

  /**
   * Address: 0x00510260 (FUN_00510260)
   */
  void RBeamBlueprint::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(mOwnerRules, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive.WriteString(&BlueprintId.name);
    result.SetOwned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<RBeamBlueprint>`, vtable 0x00E0EC5C.
   *
   * Address: 0x00BC81B0 (FUN_00BC81B0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF2680 (FUN_00BF2680 -- the global's destructor.)
   * Address: 0x00510780 (FUN_00510780 -- `Init`.)
   * Address: 0x005101E0 (FUN_005101E0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct RBeamBlueprintSaveConstruct : gpg::SerSaveConstructHelper<RBeamBlueprint>
  {};

  /**
   * `gpg::SerConstructHelper<RBeamBlueprint>`, vtable 0x00E0EC6C.
   *
   * Address: 0x00BC81E0 (FUN_00BC81E0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF26B0 (FUN_00BF26B0 -- the global's destructor.)
   * Address: 0x00510800 (FUN_00510800 -- `Init`.)
   * Address: 0x00510340 (FUN_00510340 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00511150 (FUN_00511150 -- `Delete`.)
   */
  struct RBeamBlueprintConstruct : gpg::SerConstructHelper<RBeamBlueprint>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AA81C -- process-global `RBeamBlueprintSaveConstruct` singleton.
  moho::RBeamBlueprintSaveConstruct gRBeamBlueprintSaveConstruct;

  // Address: 0x010AA73C -- process-global `RBeamBlueprintConstruct` singleton.
  moho::RBeamBlueprintConstruct gRBeamBlueprintConstruct;
} // namespace
