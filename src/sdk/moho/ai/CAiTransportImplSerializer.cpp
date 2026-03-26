#include "moho/ai/CAiTransportImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiTransportImplType()
  {
    gpg::RType* type = CAiTransportImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiTransportImpl));
      CAiTransportImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E9C30 (FUN_005E9C30)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiTransportImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
