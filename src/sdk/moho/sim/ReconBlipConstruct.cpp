#include "moho/sim/ReconBlipConstruct.h"

#include "moho/sim/ReconBlip.h"

namespace moho
{
  /**
   * Address: 0x005C4330 (FUN_005C4330, gpg::SerConstructHelper_ReconBlip::Init)
   *
   * What it does:
   * Lazily resolves ReconBlip RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void ReconBlipConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ReconBlip::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
