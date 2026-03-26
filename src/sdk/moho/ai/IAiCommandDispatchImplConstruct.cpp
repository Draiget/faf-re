#include "moho/ai/IAiCommandDispatchImplConstruct.h"

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
 * Address: 0x00599650 (FUN_00599650)
 *
 * What it does:
 * Lazily resolves IAiCommandDispatchImpl RTTI and installs construct/delete
 * callbacks from this helper object into the type descriptor.
 */
void IAiCommandDispatchImplConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedIAiCommandDispatchImplType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

