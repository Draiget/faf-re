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
  alignas(EAiTransportEventTypeInfo) unsigned char gEAiTransportEventTypeInfoStorage[sizeof(EAiTransportEventTypeInfo)];
  bool gEAiTransportEventTypeInfoConstructed = false;

  [[nodiscard]] EAiTransportEventTypeInfo* AcquireEAiTransportEventTypeInfo()
  {
    if (!gEAiTransportEventTypeInfoConstructed) {
      auto* const typeInfo = new (gEAiTransportEventTypeInfoStorage) EAiTransportEventTypeInfo();
      gEAiTransportEventTypeInfoConstructed = true;
    }

    return reinterpret_cast<EAiTransportEventTypeInfo*>(gEAiTransportEventTypeInfoStorage);
  }

  void cleanup_EAiTransportEventTypeInfo()
  {
    if (!gEAiTransportEventTypeInfoConstructed) {
      return;
    }

    AcquireEAiTransportEventTypeInfo()->~EAiTransportEventTypeInfo();
    gEAiTransportEventTypeInfoConstructed = false;
  }

  // Address: 0x010B074C -- process-global `PrimitiveSerHelper<EAiTransportEvent,int>`
  // singleton (constructed by FUN_00BCED30, self-registering via `__xc_a`; see
  // EAiTransportEventTypeInfo.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  moho::EAiTransportEventPrimitiveSerializer gEAiTransportEventPrimitiveSerializer;

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
 * Registers `EAiTransportEvent` enum type-info and installs process-exit
 * cleanup.
 */
int moho::register_EAiTransportEventTypeInfo()
{
  (void)AcquireEAiTransportEventTypeInfo();
  return std::atexit(&cleanup_EAiTransportEventTypeInfo);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EAiTransportEventTypeInfo_b34ccd, moho::register_EAiTransportEventTypeInfo)
