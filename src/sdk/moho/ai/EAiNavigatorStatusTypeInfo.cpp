#include "moho/ai/EAiNavigatorStatusTypeInfo.h"

#include <cstdint>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

/**
 * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
 */
EAiNavigatorStatusTypeInfo::~EAiNavigatorStatusTypeInfo() = default;

/**
 * Address: 0x005A2F30 (FUN_005A2F30)
 *
 * What it does:
 * Returns the reflection type name literal for EAiNavigatorStatus.
 */
const char* EAiNavigatorStatusTypeInfo::GetName() const
{
  return "EAiNavigatorStatus";
}

/**
 * Address: 0x005A2F70 (FUN_005A2F70)
 *
 * What it does:
 * Registers EAiNavigatorStatus enum option names/values.
 */
void EAiNavigatorStatusTypeInfo::AddEnums()
{
  mPrefix = "AINAVSTATUS_";
  AddEnum(StripPrefix("AINAVSTATUS_Idle"), static_cast<std::int32_t>(AINAVSTATUS_Idle));
  AddEnum(StripPrefix("AINAVSTATUS_Thinking"), static_cast<std::int32_t>(AINAVSTATUS_Thinking));
  AddEnum(StripPrefix("AINAVSTATUS_Steering"), static_cast<std::int32_t>(AINAVSTATUS_Steering));
}

/**
 * Address: 0x005A2F10 (FUN_005A2F10)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiNavigatorStatusTypeInfo::Init()
{
  size_ = sizeof(EAiNavigatorStatus);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
