#include "moho/ai/EAiTransportEventTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF8960 (FUN_00BF8960, atexit destructor of the EAiTransportEventTypeInfo object)
   */
  [[nodiscard]] EAiTransportEventTypeInfo* AcquireEAiTransportEventTypeInfo()
  {
    static EAiTransportEventTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010B074C -- process-global `PrimitiveSerHelper<EAiTransportEvent,int>`
  // singleton (constructed by FUN_00BCED30, self-registering via `__xc_a`; see
  // EAiTransportEventTypeInfo.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EAiTransportEvent,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EAiTransportEvent@Moho@@H@gpg'`):
   * `FUN_00BCED30` (real, `__xc_a`-reachable). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mLoadCallback`/
   * `mSaveCallback` to `FUN_005E9DD0`/`FUN_005E9DF0`, installs the
   * `PrimitiveSerHelper<EAiTransportEvent,int>` vtable, and pushes plain
   * unmangled `FUN_00BF8970` (bare unlink-then-self-link shape, matching
   * the helper node's unlink (`gpg::DListItem::ListUnlink`)) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * Unlike the other AI enum serializers in this cluster, this global has
   * TWO dead zero-caller/zero-xref duplicate ctors sharing its storage
   * address (both write the same fields, neither calls `atexit`, so
   * neither is ever live): `FUN_005E8B60` and `FUN_005E9E10`. The previous
   * recovery wrongly modeled `FUN_005E9E10` as a helper function CALLED BY
   * `register_EAiTransportEventPrimitiveSerializer()` -- the real ctor's
   * disassembly sets its fields inline and calls no such helper. Both dead
   * duplicates marked `skip`.
   *
   * The previous recovery also modeled this as a hand-rolled raw-struct
   * mimic of `SerHelperBase` plus a fabricated
   * `register_EAiTransportEventPrimitiveSerializer()` free function eagerly
   * invoked a second time from `IAiTransport.cpp`'s
   * `IAiTransportReflectionBootstrap` constructor -- absent from the real
   * ctor's disassembly; removed from both files.
   */
  gpg::PrimitiveSerHelper<moho::EAiTransportEvent, int> gEAiTransportEventPrimitiveSerializer;

  // NOTE: FUN_005E3E80 ("zero_EAiTransportEventRuntimeLanes" in the prior
  // recovery) was removed from this file. It is a real, distinct 117-byte
  // SEH-wrapped function, but has zero callers/xrefs anywhere in the binary
  // (confirmed via incoming_xrefs, data_refs both directions, and .xrefs.txt)
  // and zero connection to EAiTransportEvent's real PrimitiveSerHelper ctor
  // chain traced above -- the only place in src/sdk/** that ever cited this
  // address was this file's own fabricated attribution. Left un-reattributed
  // pending a dedicated orphan-function investigation; its progress-DB
  // "recovered" status was NOT changed by this pass since none of
  // recovered/skip/external_dependency honestly fit a genuinely-unresolved
  // zero-evidence orphan (see recovery report for this cluster).
} // namespace

/**
 * Address: 0x005E3D10 (FUN_005E3D10, Moho::EAiTransportEventTypeInfo::EAiTransportEventTypeInfo)
 */
EAiTransportEventTypeInfo::EAiTransportEventTypeInfo()
{
  gpg::PreRegisterRType(typeid(EAiTransportEvent), this);
}

/**
 * Address: 0x005E3DA0 (FUN_005E3DA0, scalar deleting thunk)
 */
EAiTransportEventTypeInfo::~EAiTransportEventTypeInfo() = default;

/**
 * Address: 0x005E3D90 (FUN_005E3D90)
 *
 * What it does:
 * Returns the reflection type name literal for EAiTransportEvent.
 */
const char* EAiTransportEventTypeInfo::GetName() const
{
  return "EAiTransportEvent";
}

/**
 * Address: 0x005E3DD0 (FUN_005E3DD0)
 *
 * What it does:
 * Registers EAiTransportEvent enum option names/values.
 */
void EAiTransportEventTypeInfo::AddEnums()
{
  mPrefix = "AITRANSPORTEVENT_";
  AddEnum(StripPrefix("AITRANSPORTEVENT_LoadFailed"), static_cast<std::int32_t>(AITRANSPORTEVENT_LoadFailed));
  AddEnum(StripPrefix("AITRANSPORTEVENT_Load"), static_cast<std::int32_t>(AITRANSPORTEVENT_Load));
  AddEnum(StripPrefix("AITRANSPORTEVENT_Unload"), static_cast<std::int32_t>(AITRANSPORTEVENT_Unload));
}

/**
 * Address: 0x005E3D70 (FUN_005E3D70)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiTransportEventTypeInfo::Init()
{
  size_ = sizeof(EAiTransportEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}

/**
 * Address: 0x00BCED10 (FUN_00BCED10, register_EAiTransportEventTypeInfo)
 *
 * What it does:
 * Registers `EAiTransportEvent` enum type-info.
 */
void moho::register_EAiTransportEventTypeInfo()
{
  (void)AcquireEAiTransportEventTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiTransportEventTypeInfo_b34ccd, moho::register_EAiTransportEventTypeInfo)
