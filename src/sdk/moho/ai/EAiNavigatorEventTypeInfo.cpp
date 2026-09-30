#include "moho/ai/EAiNavigatorEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiNavigator.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6C70 (FUN_00BF6C70, atexit destructor of the EAiNavigatorEventTypeInfo object)
   */
  [[nodiscard]] EAiNavigatorEventTypeInfo* AcquireEAiNavigatorEventTypeInfo()
  {
    static EAiNavigatorEventTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AE6EC -- process-global `PrimitiveSerHelper<EAiNavigatorEvent,int>`
  // singleton (constructed by FUN_00BCC660, self-registering via `__xc_a`; see
  // EAiNavigatorEventTypeInfo.h for the real-ctor/atexit-target evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiNavigatorEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiNavigatorEvent@Moho@@H@gpg'`):
   * `FUN_00BCC660` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found for this instantiation). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005A7720`/`FUN_005A7740`, installs the
   * `PrimitiveSerHelper<EAiNavigatorEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF6CD0` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   * `FUN_005A3130`/`FUN_005A3160` are dead, zero-xref duplicate-emission
   * twins of that exact `FUN_00BF6CD0` body (function_sha256-confirmed),
   * formerly modeled in `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneN` and its two reset thunks; removed in
   * favor of this citation.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_EAiNavigatorEventPrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `EAiNavigatorEventTypeInfoBootstrap` constructor -- absent from the real
   * ctor's disassembly (`FUN_00BCC660` already self-registers via `__xc_a`);
   * removed.
   */
  gpg::PrimitiveSerHelper<moho::EAiNavigatorEvent, int> gEAiNavigatorEventPrimitiveSerializer;
} // namespace

/**
 * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
 */
/**
 * Address: 0x005A3020 (FUN_005A3020,
 *   Moho::EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo)
 *
 * IDA signature:
 * gpg::REnumType *Moho::EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo();
 *
 * What it does:
 * Runs the REnumType base constructor, installs the most-derived vftable lane,
 * and pre-registers the descriptor under `typeid(EAiNavigatorEvent)`.
 *
 * The recovery previously declared no constructor at all, so the implicit one
 * ran the base chain but never pre-registered - leaving
 * LookupRType(typeid(EAiNavigatorEvent)) to throw during REF_RegisterAllTypes
 * even though the registrar and its bootstrap were both present.
 */
EAiNavigatorEventTypeInfo::EAiNavigatorEventTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(EAiNavigatorEvent), this);
}

EAiNavigatorEventTypeInfo::~EAiNavigatorEventTypeInfo() = default;

/**
 * Address: 0x005A30A0 (FUN_005A30A0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorEvent.
 */
const char* EAiNavigatorEventTypeInfo::GetName() const
{
  return "EAiNavigatorEvent";
}

/**
 * Address: 0x005A30E0 (FUN_005A30E0)
 *
 * What it does:
 * Registers EAiNavigatorEvent enum option names/values.
 */
void EAiNavigatorEventTypeInfo::AddEnums()
{
  mPrefix = "AINAVEVENT_";
  AddEnum(StripPrefix("AINAVEVENT_Failed"), static_cast<std::int32_t>(AINAVEVENT_Failed));
  AddEnum(StripPrefix("AINAVEVENT_Aborted"), static_cast<std::int32_t>(AINAVEVENT_Aborted));
  AddEnum(StripPrefix("AINAVEVENT_Succeeded"), static_cast<std::int32_t>(AINAVEVENT_Succeeded));
}

/**
 * Address: 0x005A3080 (FUN_005A3080)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorEventTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCC640 (FUN_00BCC640, register_EAiNavigatorEventTypeInfo)
 *
 * What it does:
 * Preregisters startup construction for the `EAiNavigatorEvent` enum RTTI
 * descriptor and installs exit-time teardown.
 */
void moho::register_EAiNavigatorEventTypeInfo()
{
  (void)AcquireEAiNavigatorEventTypeInfo();
}

namespace
{
  struct EAiNavigatorEventTypeInfoBootstrap
  {
    EAiNavigatorEventTypeInfoBootstrap()
    {
      (void)moho::register_EAiNavigatorEventTypeInfo();
    }
  };

  [[maybe_unused]] EAiNavigatorEventTypeInfoBootstrap gEAiNavigatorEventTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiNavigatorEventTypeInfo_0c1335, moho::register_EAiNavigatorEventTypeInfo)
