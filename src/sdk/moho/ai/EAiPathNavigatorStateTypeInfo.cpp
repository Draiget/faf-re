#include "moho/ai/EAiPathNavigatorStateTypeInfo.h"

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

/**
 * Address: 0x005AD2D0 (FUN_005AD2D0, scalar deleting thunk)
 */
EAiPathNavigatorStateTypeInfo::~EAiPathNavigatorStateTypeInfo() = default;

/**
 * Address: 0x005AD2C0 (FUN_005AD2C0)
 *
 * What it does:
 * Returns the reflection type name literal for EAiPathNavigatorState.
 */
const char* EAiPathNavigatorStateTypeInfo::GetName() const
{
  return "EAiPathNavigatorState";
}

/**
 * Address: 0x005AD2A0 (FUN_005AD2A0)
 *
 * What it does:
 * Writes enum width and finalizes metadata.
 */
void EAiPathNavigatorStateTypeInfo::Init()
{
  size_ = sizeof(EAiPathNavigatorState);
  gpg::RType::Init();
  Finish();
}
