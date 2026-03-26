#include "moho/ai/CAiSiloBuildImplConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiSiloBuildImplType()
  {
    gpg::RType* type = CAiSiloBuildImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSiloBuildImpl));
      CAiSiloBuildImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005CFEB0 (FUN_005CFEB0)
 *
 * void ()
 *
 * IDA signature:
 * int __thiscall sub_5CFEB0(_DWORD *this);
 *
 * What it does:
 * Lazily resolves CAiSiloBuildImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiSiloBuildImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCAiSiloBuildImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
