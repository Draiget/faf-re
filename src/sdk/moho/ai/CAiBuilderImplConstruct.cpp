#include "moho/ai/CAiBuilderImplConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiBuilderImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiBuilderImplType()
  {
    gpg::RType* type = CAiBuilderImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBuilderImpl));
      CAiBuilderImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A0650 (FUN_005A0650)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiBuilderImplConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
