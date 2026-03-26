#include "moho/ai/IAiCommandDispatchImplSerializer.h"

#include <typeinfo>

#include "moho/ai/IAiCommandDispatchImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchImplType()
  {
    gpg::RType* type = IAiCommandDispatchImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatchImpl));
      IAiCommandDispatchImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005996D0 (FUN_005996D0)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

