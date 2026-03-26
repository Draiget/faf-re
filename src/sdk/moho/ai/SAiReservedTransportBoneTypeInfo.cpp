#include "moho/ai/SAiReservedTransportBoneTypeInfo.h"

#include "moho/ai/SAiReservedTransportBone.h"

using namespace moho;

gpg::RType* SAiReservedTransportBone::sType = nullptr;

/**
 * Address: 0x005E3FF0 (FUN_005E3FF0, scalar deleting thunk)
 */
SAiReservedTransportBoneTypeInfo::~SAiReservedTransportBoneTypeInfo() = default;

/**
 * Address: 0x005E3FE0 (FUN_005E3FE0, ?GetName@SAiReservedTransportBoneTypeInfo@Moho@@UBEPBDXZ)
 */
const char* SAiReservedTransportBoneTypeInfo::GetName() const
{
  return "SAiReservedTransportBone";
}

/**
 * Address: 0x005E3FC0 (FUN_005E3FC0, ?Init@SAiReservedTransportBoneTypeInfo@Moho@@UAEXXZ)
 */
void SAiReservedTransportBoneTypeInfo::Init()
{
  size_ = sizeof(SAiReservedTransportBone);
  gpg::RType::Init();
  Finish();
}
