#include "moho/ai/CAiNavigatorImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    gpg::RType* type = CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorImpl));
      CAiNavigatorImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A72A0 (FUN_005A72A0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiNavigatorImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiNavigatorImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

