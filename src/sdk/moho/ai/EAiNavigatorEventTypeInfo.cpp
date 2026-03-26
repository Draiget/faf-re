#include "moho/ai/EAiNavigatorEventTypeInfo.h"

#include <cstdint>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

/**
 * Address: 0x005A30B0 (FUN_005A30B0, scalar deleting thunk)
 */
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
