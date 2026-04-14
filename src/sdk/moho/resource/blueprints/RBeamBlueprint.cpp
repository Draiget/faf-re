#include "RBeamBlueprint.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

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
