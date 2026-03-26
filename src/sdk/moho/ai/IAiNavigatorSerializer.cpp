#include "moho/ai/IAiNavigatorSerializer.h"

#include <typeinfo>

#include "moho/ai/IAiNavigator.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    gpg::RType* type = IAiNavigator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiNavigator));
      IAiNavigator::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A71A0 (FUN_005A71A0)
 *
 * What it does:
 * Lazily resolves IAiNavigator RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiNavigatorSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedIAiNavigatorType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

