#include "REmitterBlueprint.h"

#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  gpg::RType* REmitterCurveKey::sType = nullptr;
  gpg::RType* REmitterBlueprintCurve::sType = nullptr;
  gpg::RType* REmitterBlueprint::sType = nullptr;

  std::size_t REmitterCurveKeyListStorage::Count() const noexcept
  {
    if (!mBegin || !mEnd || mEnd < mBegin) {
      return 0U;
    }
    return static_cast<std::size_t>(mEnd - mBegin);
  }

  bool REmitterCurveKeyListStorage::Empty() const noexcept
  {
    return Count() == 0U;
  }

  /**
   * Address: 0x00514B30 (FUN_00514B30)
   * Mangled: ?GetClass@REmitterCurveKey@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `REmitterCurveKey`.
   */
  gpg::RType* REmitterCurveKey::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(REmitterCurveKey));
    }
    return sType;
  }

  /**
   * Address: 0x00514B50 (FUN_00514B50)
   * Mangled: ?GetDerivedObjectRef@REmitterCurveKey@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef REmitterCurveKey::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x00514B90 (FUN_00514B90, scalar deleting dtor thunk)
   *
   * What it does:
   * Runtime destructor for curve-key samples.
   */
  REmitterCurveKey::~REmitterCurveKey() = default;

  /**
   * Address: 0x0050E4F0 (FUN_0050E4F0)
   * Mangled: ?GetClass@REmitterBlueprintCurve@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `REmitterBlueprintCurve`.
   */
  gpg::RType* REmitterBlueprintCurve::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(REmitterBlueprintCurve));
    }
    return sType;
  }

  /**
   * Address: 0x0050E510 (FUN_0050E510)
   * Mangled: ?GetDerivedObjectRef@REmitterBlueprintCurve@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef REmitterBlueprintCurve::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0050E580 (FUN_0050E580, scalar deleting dtor thunk)
   *
   * What it does:
   * Releases key-storage payload for this curve instance.
   */
  REmitterBlueprintCurve::~REmitterBlueprintCurve()
  {
    if (Keys.mBegin && Keys.mEnd && Keys.mEnd >= Keys.mBegin) {
      for (REmitterCurveKey* it = Keys.mBegin; it != Keys.mEnd; ++it) {
        it->~REmitterCurveKey();
      }
    }

    if (Keys.mBegin) {
      ::operator delete(Keys.mBegin);
    }

    Keys.mAllocProxy = nullptr;
    Keys.mBegin = nullptr;
    Keys.mEnd = nullptr;
    Keys.mCapacityEnd = nullptr;
  }

  /**
   * Address: 0x0050E710 (FUN_0050E710)
   * Mangled: ?GetClass@REmitterBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `REmitterBlueprint`.
   */
  gpg::RType* REmitterBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(REmitterBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0050E730 (FUN_0050E730)
   * Mangled: ?GetDerivedObjectRef@REmitterBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef REmitterBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0050EAE0 (FUN_0050EAE0)
   *
   * What it does:
   * Emitter cast hook for effect-blueprint unions. Returns `this`.
   */
  REmitterBlueprint* REmitterBlueprint::IsEmitter()
  {
    return this;
  }
} // namespace moho
