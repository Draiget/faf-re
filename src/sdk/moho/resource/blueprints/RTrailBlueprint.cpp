#include "RTrailBlueprint.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* RTrailBlueprint::sType = nullptr;

  /**
   * Address: 0x0050ED80 (FUN_0050ED80)
   *
   * What it does:
   * Initializes trail-blueprint defaults and empty texture string storage.
   */
  RTrailBlueprint::RTrailBlueprint()
    : Lifetime(0.0f)
    , TrailLength(0.0f)
    , StartSize(0.0f)
    , SortOrder(0.0f)
    , BlendMode(0)
    , LODCutoff(100.0f)
    , EmitIfVisible(1)
    , CatchupEmit(1)
    , pad_0042_0044{0, 0}
    , TextureRepeatRate(0.0f)
    , RepeatTexture()
    , RampTexture()
  {}

  /**
   * Address: 0x0050ED40 (FUN_0050ED40)
   * Mangled: ?GetClass@RTrailBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RTrailBlueprint`.
   */
  gpg::RType* RTrailBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RTrailBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0050ED60 (FUN_0050ED60)
   * Mangled: ?GetDerivedObjectRef@RTrailBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RTrailBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0050EDF0 (FUN_0050EDF0)
   *
   * What it does:
   * Trail cast hook for effect-blueprint unions. Returns `this`.
   */
  RTrailBlueprint* RTrailBlueprint::IsTrail()
  {
    return this;
  }
} // namespace moho
