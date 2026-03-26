#include "moho/ai/EAiTransportEventTypeInfo.h"

#include <cstdint>

#include "moho/ai/IAiTransport.h"

using namespace moho;

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
