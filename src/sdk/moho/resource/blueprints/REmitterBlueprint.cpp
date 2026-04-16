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
   * Address: 0x005108A0 (FUN_005108A0)
   *
   * What it does:
   * Destroys each curve-key entry in the half-open `[begin,end)` lane, frees
   * the backing payload, and resets begin/end/capacity pointers to null.
   */
  void ResetEmitterCurveKeyStorageRuntime(REmitterCurveKeyListStorage* const storage)
  {
    if (storage == nullptr) {
      return;
    }

    REmitterCurveKey* cursor = storage->mBegin;
    if (cursor != nullptr) {
      const REmitterCurveKey* const end = storage->mEnd;
      while (cursor != end) {
        cursor->~REmitterCurveKey();
        ++cursor;
      }

      ::operator delete(storage->mBegin);
    }

    storage->mBegin = nullptr;
    storage->mEnd = nullptr;
    storage->mCapacityEnd = nullptr;
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
   * Address: 0x0050E530 (FUN_0050E530, ??0REmitterBlueprintCurve@Moho@@QAE@XZ)
   *
   * What it does:
   * Installs the curve vftable and zero-initializes range/key-storage lanes.
   */
  REmitterBlueprintCurve::REmitterBlueprintCurve() = default;

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
   * Address: 0x0050E5A0 (FUN_0050E5A0, base dtor thunk lane)
   *
   * What it does:
   * Releases key-storage payload for this curve instance; shared dtor thunks
   * at both addresses funnel through this same teardown lane.
   */
  REmitterBlueprintCurve::~REmitterBlueprintCurve()
  {
    ResetEmitterCurveKeyStorageRuntime(&Keys);
    Keys.mAllocProxy = nullptr;
  }

  /**
   * Address: 0x0050E750 (FUN_0050E750)
   * Mangled: ??0REmitterBlueprint@Moho@@QAE@XZ
   *
   * IDA signature:
   * Moho::REmitterBlueprint *__thiscall Moho::REmitterBlueprint::REmitterBlueprint(
   *   Moho::REmitterBlueprint *this);
   *
   * What it does:
   * Default-constructs an emitter blueprint. The base `REffectBlueprint` ctor
   * runs first to install the `RObject` vftable, clear `mOwnerRules`, and
   * default-construct `BlueprintId` (empty SSO `msvc8::string`); the 21
   * `REmitterBlueprintCurve` subobjects each install their `RObject` vftable
   * and zero their key-storage triplets via the curve's default ctor; finally
   * the in-class field initializers set the fidelity flags, emitter behavior
   * flags, scalar timings, and the two texture-name strings to empty SSO.
   * Behavior matches the binary writes at 0x0050E750..0x0050EAD4 1:1.
   */
  REmitterBlueprint::REmitterBlueprint() = default;

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
