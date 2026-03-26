#include "moho/ai/CAiBuilderImplSerializer.h"

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
 * Address: 0x005A06D0 (FUN_005A06D0)
 *
 * What it does:
 * Lazily resolves CAiBuilderImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiBuilderImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiBuilderImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
