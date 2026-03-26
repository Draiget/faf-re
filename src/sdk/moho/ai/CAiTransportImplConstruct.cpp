#include "moho/ai/CAiTransportImplConstruct.h"

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
 * Address: 0x005E9BB0 (FUN_005E9BB0)
 *
 * What it does:
 * Lazily resolves CAiTransportImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiTransportImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiTransportImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
