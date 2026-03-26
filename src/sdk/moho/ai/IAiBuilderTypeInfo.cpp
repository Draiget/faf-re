#include "moho/ai/IAiBuilderTypeInfo.h"

#include "moho/ai/IAiBuilder.h"

using namespace moho;

/**
 * Address: 0x0059EE20 (FUN_0059EE20, scalar deleting thunk)
 */
IAiBuilderTypeInfo::~IAiBuilderTypeInfo() = default;

/**
 * Address: 0x0059EE10 (FUN_0059EE10, ?GetName@IAiBuilderTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiBuilderTypeInfo::GetName() const
{
  return "IAiBuilder";
}

/**
 * Address: 0x0059EDF0 (FUN_0059EDF0, ?Init@IAiBuilderTypeInfo@Moho@@UAEXXZ)
 */
void IAiBuilderTypeInfo::Init()
{
  size_ = sizeof(IAiBuilder);
  gpg::RType::Init();
  Finish();
}
