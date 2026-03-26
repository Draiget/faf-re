#include "moho/ai/IAiNavigatorTypeInfo.h"

#include "moho/ai/IAiNavigator.h"

using namespace moho;

/**
 * Address: 0x005A3220 (FUN_005A3220, scalar deleting thunk)
 */
IAiNavigatorTypeInfo::~IAiNavigatorTypeInfo() = default;

/**
 * Address: 0x005A3210 (FUN_005A3210, ?GetName@IAiNavigatorTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiNavigatorTypeInfo::GetName() const
{
  return "IAiNavigator";
}

/**
 * Address: 0x005A31F0 (FUN_005A31F0, ?Init@IAiNavigatorTypeInfo@Moho@@UAEXXZ)
 */
void IAiNavigatorTypeInfo::Init()
{
  size_ = sizeof(IAiNavigator);
  gpg::RType::Init();
  Finish();
}

