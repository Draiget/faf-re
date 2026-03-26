#include "moho/sim/CArmyStatsSaveConstruct.h"

#include "moho/sim/CArmyStats.h"

namespace moho
{
  /**
   * Address: 0x0070F4E0 (FUN_0070F4E0, gpg::SerSaveConstructHelper_CArmyStats::Init)
   *
   * IDA signature:
   * gpg::RType *__thiscall sub_70F4E0(void (__cdecl **this)(...));
   */
  void CArmyStatsSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho
