#include "moho/ai/IAiSteeringTypeInfo.h"

#include "moho/ai/IAiSteering.h"

using namespace moho;

/**
 * Address: 0x005D2060 (FUN_005D2060, scalar deleting thunk)
 */
IAiSteeringTypeInfo::~IAiSteeringTypeInfo() = default;

/**
 * Address: 0x005D2050 (FUN_005D2050, ?GetName@IAiSteeringTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiSteeringTypeInfo::GetName() const
{
  return "IAiSteering";
}

/**
 * Address: 0x005D2030 (FUN_005D2030, ?Init@IAiSteeringTypeInfo@Moho@@UAEXXZ)
 */
void IAiSteeringTypeInfo::Init()
{
  size_ = sizeof(IAiSteering);
  gpg::RType::Init();
  Finish();
}
