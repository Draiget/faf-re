#include "moho/ai/CAiBrainConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiBrain.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x0057E3E0 (FUN_0057E3E0)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs construct/delete callbacks from
 * this helper object into the type descriptor.
 */
void CAiBrainConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
