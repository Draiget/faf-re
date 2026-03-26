#include "moho/ai/CAiPathNavigatorSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathNavigatorType()
  {
    gpg::RType* type = CAiPathNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathNavigator));
      CAiPathNavigator::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005B0130 (FUN_005B0130)
 *
 * What it does:
 * Lazily resolves CAiPathNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathNavigatorSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiPathNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
