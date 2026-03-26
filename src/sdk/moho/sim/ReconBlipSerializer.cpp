#include "moho/sim/ReconBlipSerializer.h"

#include "moho/sim/ReconBlip.h"

namespace moho
{
  /**
   * Address: 0x005C43B0 (FUN_005C43B0, gpg::SerSaveLoadHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void ReconBlipSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
