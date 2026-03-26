#include "moho/ai/IAiCommandDispatchTypeInfo.h"

#include "moho/ai/IAiCommandDispatch.h"

using namespace moho;

/**
 * Address: 0x00598C50 (FUN_00598C50, scalar deleting thunk)
 */
IAiCommandDispatchTypeInfo::~IAiCommandDispatchTypeInfo() = default;

/**
 * Address: 0x00598C40 (FUN_00598C40, ?GetName@IAiCommandDispatchTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiCommandDispatchTypeInfo::GetName() const
{
  return "IAiCommandDispatch";
}

/**
 * Address: 0x00598C20 (FUN_00598C20, ?Init@IAiCommandDispatchTypeInfo@Moho@@UAEXXZ)
 */
void IAiCommandDispatchTypeInfo::Init()
{
  size_ = sizeof(IAiCommandDispatch);
  gpg::RType::Init();
  Finish();
}

