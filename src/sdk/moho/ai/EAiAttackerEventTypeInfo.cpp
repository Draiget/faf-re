#include "moho/ai/EAiAttackerEventTypeInfo.h"

#include <cstdint>

#include "moho/ai/EAiAttackerEvent.h"

using namespace moho;

/**
 * Address: 0x005D5A30 (FUN_005D5A30, scalar deleting thunk)
 */
EAiAttackerEventTypeInfo::~EAiAttackerEventTypeInfo() = default;

/**
 * Address: 0x005D5A20 (FUN_005D5A20)
 *
 * What it does:
 * Returns the reflection type name literal for EAiAttackerEvent.
 */
const char* EAiAttackerEventTypeInfo::GetName() const
{
  return "EAiAttackerEvent";
}

/**
 * Address: 0x005D5A60 (FUN_005D5A60)
 *
 * What it does:
 * Registers EAiAttackerEvent enum option names/values.
 */
void EAiAttackerEventTypeInfo::AddEnums()
{
  mPrefix = "AIATTACKEVENT_";
  AddEnum(
    StripPrefix("AIATTACKEVENT_AcquiredDesiredTarget"),
    static_cast<std::int32_t>(AIATTACKEVENT_AcquiredDesiredTarget)
  );
  AddEnum(StripPrefix("AIATTACKEVENT_OutOfRange"), static_cast<std::int32_t>(AIATTACKEVENT_OutOfRange));
  AddEnum(StripPrefix("AIATTACKEVENT_Success"), static_cast<std::int32_t>(AIATTACKEVENT_Success));
}

/**
 * Address: 0x005D5A00 (FUN_005D5A00)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiAttackerEventTypeInfo::Init()
{
  size_ = sizeof(EAiAttackerEvent);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
