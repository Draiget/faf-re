#include "moho/ai/CAiNavigatorLandSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorLandType()
  {
    gpg::RType* type = CAiNavigatorLand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorLand));
      CAiNavigatorLand::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A7430 (FUN_005A7430)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorLandSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

