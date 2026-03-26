#include "moho/sim/CInfluenceMapSerializer.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00718B60 (FUN_00718B60, gpg::SerSaveLoadHelper_CInfluenceMap::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_718B60(void (__cdecl **this)(...)))(...);
   */
  void CInfluenceMapSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CInfluenceMap::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
