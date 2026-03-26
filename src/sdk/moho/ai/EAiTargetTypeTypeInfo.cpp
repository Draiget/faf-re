#include "moho/ai/EAiTargetTypeTypeInfo.h"

#include <cstdint>

#include "moho/ai/EAiTargetType.h"

using namespace moho;

/**
 * Address: 0x005E2400 (FUN_005E2400, scalar deleting thunk)
 */
EAiTargetTypeTypeInfo::~EAiTargetTypeTypeInfo() = default;

/**
 * Address: 0x005E23F0 (FUN_005E23F0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiTargetType.
 */
const char* EAiTargetTypeTypeInfo::GetName() const
{
  return "EAiTargetType";
}

/**
 * Address: 0x005E2430 (FUN_005E2430)
 *
 * What it does:
 * Registers `EAiTargetType` enum option names/values.
 */
void EAiTargetTypeTypeInfo::AddEnums()
{
  mPrefix = "AITARGET_";
  AddEnum(StripPrefix("AITARGET_None"), static_cast<std::int32_t>(EAiTargetType::AITARGET_None));
  AddEnum(StripPrefix("AITARGET_Entity"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Entity));
  AddEnum(StripPrefix("AITARGET_Ground"), static_cast<std::int32_t>(EAiTargetType::AITARGET_Ground));
}

/**
 * Address: 0x005E23D0 (FUN_005E23D0)
 *
 * What it does:
 * Writes enum width, registers enum values, then finalizes metadata.
 */
void EAiTargetTypeTypeInfo::Init()
{
  size_ = sizeof(EAiTargetType);
  gpg::RType::Init();
  AddEnums();
  Finish();
}
