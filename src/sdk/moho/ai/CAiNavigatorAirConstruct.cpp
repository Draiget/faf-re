#include "moho/ai/CAiNavigatorAirConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorAirType()
  {
    gpg::RType* type = CAiNavigatorAir::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorAir));
      CAiNavigatorAir::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A74D0 (FUN_005A74D0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorAir RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorAirConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiNavigatorAirType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

