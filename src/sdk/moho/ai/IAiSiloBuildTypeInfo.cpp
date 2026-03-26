#include "moho/ai/IAiSiloBuildTypeInfo.h"

#include "moho/ai/IAiSiloBuild.h"

using namespace moho;

/**
 * Address: 0x005CE940 (FUN_005CE940, scalar deleting thunk)
 */
IAiSiloBuildTypeInfo::~IAiSiloBuildTypeInfo() = default;

/**
 * Address: 0x005CE930 (FUN_005CE930, ?GetName@IAiSiloBuildTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiSiloBuildTypeInfo::GetName() const
{
  return "IAiSiloBuild";
}

/**
 * Address: 0x005CE910 (FUN_005CE910, ?Init@IAiSiloBuildTypeInfo@Moho@@UAEXXZ)
 */
void IAiSiloBuildTypeInfo::Init()
{
  size_ = sizeof(IAiSiloBuild);
  gpg::RType::Init();
  Finish();
}
