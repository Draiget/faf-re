#include "moho/ai/IAiFormationDBTypeInfo.h"

#include "moho/ai/IAiFormationDB.h"

using namespace moho;

/**
 * Address: 0x0059C460 (FUN_0059C460, scalar deleting thunk)
 */
IAiFormationDBTypeInfo::~IAiFormationDBTypeInfo() = default;

/**
 * Address: 0x0059C450 (FUN_0059C450, ?GetName@IAiFormationDBTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiFormationDBTypeInfo::GetName() const
{
  return "IAiFormationDB";
}

/**
 * Address: 0x0059C430 (FUN_0059C430, ?Init@IAiFormationDBTypeInfo@Moho@@UAEXXZ)
 */
void IAiFormationDBTypeInfo::Init()
{
  size_ = sizeof(IAiFormationDB);
  gpg::RType::Init();
  Finish();
}

