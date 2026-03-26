#include "moho/sim/SThreatSerializer.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00719370 (FUN_00719370, gpg::SerSaveLoadHelper_SThreat::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_719370(void (__cdecl **this)(...)))(...);
   */
  void SThreatSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SThreat::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
