#include "moho/sim/InfluenceGridSerializer.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00719410 (FUN_00719410, gpg::SerSaveLoadHelper_InfluenceGrid::Init)
   *
   * IDA signature:
   * void __thiscall sub_719410(_DWORD *this);
   */
  void InfluenceGridSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = InfluenceGrid::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
