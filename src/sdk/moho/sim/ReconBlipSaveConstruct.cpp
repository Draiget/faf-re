#include "moho/sim/ReconBlipSaveConstruct.h"

#include "moho/sim/ReconBlip.h"

namespace moho
{
  /**
   * Address: 0x005C42B0 (FUN_005C42B0, gpg::SerSaveConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs save-construct-args callback
   * from this helper into the type descriptor.
   */
  void ReconBlipSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho
