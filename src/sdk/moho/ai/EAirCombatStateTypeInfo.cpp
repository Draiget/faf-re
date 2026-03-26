#include "moho/ai/EAirCombatStateTypeInfo.h"

#include "moho/ai/EAirCombatState.h"

using namespace moho;

/**
 * Address: 0x006B7700 (FUN_006B7700, scalar deleting thunk)
 */
EAirCombatStateTypeInfo::~EAirCombatStateTypeInfo() = default;

/**
 * Address: 0x006B76F0 (FUN_006B76F0)
 *
 * What it does:
 * Returns the reflection type name literal for EAirCombatState.
 */
const char* EAirCombatStateTypeInfo::GetName() const
{
  return "EAirCombatState";
}

/**
 * Address: 0x006B76D0 (FUN_006B76D0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAirCombatStateTypeInfo::Init()
{
  size_ = sizeof(EAirCombatState);
  gpg::RType::Init();
  Finish();
}
