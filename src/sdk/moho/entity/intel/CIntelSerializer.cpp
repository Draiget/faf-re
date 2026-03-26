#include "moho/entity/intel/CIntelSerializer.h"

#include "moho/entity/intel/CIntel.h"

namespace moho
{
  /**
   * Address: 0x0076E810 (FUN_0076E810, gpg::SerSaveLoadHelper_CIntel::Init)
   *
   * What it does:
   * Lazily resolves CIntel RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void CIntelSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CIntel::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
