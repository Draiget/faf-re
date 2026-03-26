#include "moho/ai/CAiNavigatorAirSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A7550 (FUN_005A7550)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorAirSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

