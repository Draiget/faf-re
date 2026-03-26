#include "moho/ai/IAiReconDBTypeInfo.h"

#include "moho/ai/IAiReconDB.h"

using namespace moho;

/**
 * Address: 0x005C2700 (FUN_005C2700, scalar deleting thunk)
 */
IAiReconDBTypeInfo::~IAiReconDBTypeInfo() = default;

/**
 * Address: 0x005C26F0 (FUN_005C26F0)
 */
const char* IAiReconDBTypeInfo::GetName() const
{
  return "IAiReconDB";
}

/**
 * Address: 0x005C26D0 (FUN_005C26D0)
 */
void IAiReconDBTypeInfo::Init()
{
  size_ = sizeof(IAiReconDB);
  gpg::RType::Init();
  Finish();
}
