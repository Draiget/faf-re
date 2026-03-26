#include "moho/ai/CAiTargetTypeInfo.h"

#include "moho/ai/CAiTarget.h"

using namespace moho;

/**
 * Address: 0x005E2570 (FUN_005E2570, scalar deleting thunk)
 */
CAiTargetTypeInfo::~CAiTargetTypeInfo() = default;

/**
 * Address: 0x005E2560 (FUN_005E2560)
 *
 * What it does:
 * Returns the reflection type name literal for CAiTarget.
 */
const char* CAiTargetTypeInfo::GetName() const
{
  return "CAiTarget";
}

/**
 * Address: 0x005E2540 (FUN_005E2540)
 *
 * What it does:
 * Writes `size_` for CAiTarget, then performs base-init/finalization.
 */
void CAiTargetTypeInfo::Init()
{
  size_ = sizeof(CAiTarget);
  gpg::RType::Init();
  Finish();
}
