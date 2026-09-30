#include "moho/unit/ECommandEventTypeInfo.h"

#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BFEB40 (FUN_00BFEB40, atexit destructor of the ECommandEventTypeInfo object)
   */
  [[nodiscard]] moho::ECommandEventTypeInfo& AcquireECommandEventTypeInfo()
  {
    static moho::ECommandEventTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BD8EF0 (FUN_00BD8EF0, dynamic initializer for the global
   * `PrimitiveSerHelper<ECommandEvent,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `ECommandEventTypeInfo`'s own
   * initializer below -- the prior recovery wrongly coupled both into one
   * shared bootstrap struct.
   *
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ECommandEvent,int>
   *
   * Investigated per RTTI: `ECommandEvent` has vtable_writer entries for
   * BOTH `?$PrimitiveSerHelper@W4ECommandEvent@Moho@@H@gpg` (two ctor
   * writers) and `?$SerSaveLoadHelper@W4ECommandEvent@Moho@@@gpg` (one ctor
   * writer). Only ONE of the three is `__xc_a`-reachable:
   *   - `FUN_00BD8EF0` (`PrimitiveSerHelper<ECommandEvent,int>` ctor):
   *     `incoming_xrefs=1`, `reachable via ctor_static depth 0` -- REAL.
   *   - `FUN_006E9730` (`PrimitiveSerHelper<ECommandEvent,int>` ctor, same
   *     vtable as above): `incoming_xrefs=0`, unreachable -- dead duplicate
   *     (same low-address/high-address shape as every other
   *     `PrimitiveSerHelper<T,int>` instantiation; a prior recovery pass
   *     wrongly labeled THIS address "the real, distinct ctor").
   *   - `FUN_006EA770` (`SerSaveLoadHelper<ECommandEvent>` ctor):
   *     `incoming_xrefs=0`, unreachable -- dead sibling-writer, same
   *     "shares a global's storage address but is itself unreachable" shape
   *     already documented for ELayer/EVisibilityMode/ESquadClass in
   *     `gpg::PrimitiveSerHelper<T,IntType>`'s Reflection.h class comment.
   * `Init()` confirmed at `FUN_006E9760` via the RTTI vftable dump
   * (`vftable@0xE2E968` slot 0) -- a THIRD address, previously mis-cited in
   * `ArchiveSerialization.cpp` as a generic
   * `InstallSerSaveLoadHelperCallbacksByTypeName(helper, "Moho::ECommandEvent")`
   * dispatch; the real body does a direct `typeid`/`sType`-cache lookup and
   * hardcoded callback install, matching this template's `Init()` exactly
   * (same mis-citation family already caught this session for
   * ESTITargetType/EResourceType/EUnitCommandType/CAniPose/CAniPoseBone).
   * `Deserialize`/`Serialize` at 0x006EA730/0x006EA750 already matched this
   * template's generic bodies exactly (no fabricated null-check needed).
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BFEB50` (atexit target
   * pushed by the real ctor `FUN_00BD8EF0`); `FUN_006E7E30`/`FUN_006E7E60`
   * are dead, zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed; distinct from the ctor-side dead
   * duplicates `FUN_006E9730`/`FUN_006EA770` above), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneAQ` and its two reset thunks; removed in
   * favor of this citation.
   */
  gpg::PrimitiveSerHelper<moho::ECommandEvent, int> gECommandEventPrimitiveSerializer;
} // namespace

namespace moho
{
  ECommandEventTypeInfo::ECommandEventTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ECommandEvent), this);
  }

  /**
   * Address: 0x006E7DF0 (FUN_006E7DF0, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ECommandEventTypeInfo::~ECommandEventTypeInfo() = default;

  const char* ECommandEventTypeInfo::GetName() const
  {
    return "ECommandEvent";
  }

  void ECommandEventTypeInfo::Init()
  {
    size_ = sizeof(ECommandEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD8ED0 (FUN_00BD8ED0, sub_BD8ED0)
   *
   * What it does:
   * Ensures `ECommandEvent` type-info is constructed and registered.
   */
  void register_ECommandEventTypeInfo()
  {
    (void)AcquireECommandEventTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ECommandEventTypeInfo_a42648, moho::register_ECommandEventTypeInfo)
