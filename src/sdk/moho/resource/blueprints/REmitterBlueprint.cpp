#include "REmitterBlueprint.h"

#include <new>
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
  gpg::RType* REmitterCurveKey::sType = nullptr;
  gpg::RType* REmitterBlueprintCurve::sType = nullptr;
  gpg::RType* REmitterBlueprint::sType = nullptr;



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
   * Nothing of its own: `~vector<REmitterCurveKey>` is the whole teardown,
   * and MSVC emits it. Both thunks funnel here.
   */
  REmitterBlueprintCurve::~REmitterBlueprintCurve() = default;

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
   * Address: 0x0050EB10 (FUN_0050EB10, ??1REmitterBlueprint@Moho@@UAE@XZ)
   * Address: 0x0050EAF0 (FUN_0050EAF0, vtable-slot-2 scalar deleting
   * destructor: tail-calls `Moho::REmitterBlueprint::~REmitterBlueprint(this)`
   * then conditionally frees the object -- ordinary C++ `delete` semantics,
   * not modeled as a separate function here)
   * Mangled: ??1REmitterBlueprint@Moho@@UAE@XZ
   *
   * IDA signature:
   * void __stdcall Moho::REmitterBlueprint::~REmitterBlueprint(Moho::REmitterBlueprint *this);
   *
   * What it does:
   * Compiler-emitted member-destruction body for `REmitterBlueprint`. The MSVC8
   * codegen tears down `RampTextureName` (+0x268), `TextureName` (+0x24C), the
   * 21 `REmitterBlueprintCurve` subobjects in reverse declaration order
   * (`RampSelectionCurve` +0x208 ... `SizeCurve` +0x28), and the inherited
   * `BlueprintId` (`RResId`) at +0x08, then chains into
   * `~REffectBlueprint` (which rewrites the vftable to `gpg::RObject`). This
   * `= default` request preserves the binary's exact destruction order because
   * the field declaration order in `REmitterBlueprint.h` mirrors the binary's
   * offset layout.
   */
  REmitterBlueprint::~REmitterBlueprint() = default;

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

namespace moho
{
  void REmitterBlueprint::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    RRuleGameRules* rules = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&rules, &owner);
    msvc8::string id;
    archive.ReadString(&id);
    RResId resId{};
    gpg::STR_CopyFilename(&resId.name, &id);
    result.SetOwned(gpg::MakeRRef(rules->GetEmitterBlueprint(resId)), 1u);
  }

  /**
   * Address: 0x0050FD60 (FUN_0050FD60)
   */
  void REmitterBlueprint::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(mOwnerRules, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    archive.WriteString(&BlueprintId.name);
    result.SetOwned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<REmitterBlueprint>`, vtable 0x00E0EC1C.
   *
   * Address: 0x00BC80D0 (FUN_00BC80D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF25C0 (FUN_00BF25C0 -- the global's destructor.)
   * Address: 0x00510580 (FUN_00510580 -- `Init`.)
   * Address: 0x0050FCE0 (FUN_0050FCE0 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct REmitterBlueprintSaveConstruct : gpg::SerSaveConstructHelper<REmitterBlueprint>
  {};

  /**
   * `gpg::SerConstructHelper<REmitterBlueprint>`, vtable 0x00E0EC2C.
   *
   * Address: 0x00BC8100 (FUN_00BC8100 -- constructs the global and registers its destructor.)
   * Address: 0x00BF25F0 (FUN_00BF25F0 -- the global's destructor.)
   * Address: 0x00510600 (FUN_00510600 -- `Init`.)
   * Address: 0x0050FE40 (FUN_0050FE40 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x005110A0 (FUN_005110A0 -- `Delete`.)
   */
  struct REmitterBlueprintConstruct : gpg::SerConstructHelper<REmitterBlueprint>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AA830 -- process-global `REmitterBlueprintSaveConstruct` singleton.
  moho::REmitterBlueprintSaveConstruct gREmitterBlueprintSaveConstruct;

  // Address: 0x010AA6C4 -- process-global `REmitterBlueprintConstruct` singleton.
  moho::REmitterBlueprintConstruct gREmitterBlueprintConstruct;
} // namespace
