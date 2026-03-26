#include "moho/sim/InfluenceMapEntrySerializer.h"

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00718C00 (FUN_00718C00, gpg::SerSaveLoadHelper_InfluenceMapEntry::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_InfluenceMapEntry::Init(_DWORD *this);
   */
  void InfluenceMapEntrySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = InfluenceMapEntry::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
