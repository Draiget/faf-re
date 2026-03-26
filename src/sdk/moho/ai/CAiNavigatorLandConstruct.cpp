#include "moho/ai/CAiNavigatorLandConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorLandType()
  {
    gpg::RType* type = CAiNavigatorLand::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorLand));
      CAiNavigatorLand::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A73B0 (FUN_005A73B0)
 *
 * What it does:
 * Lazily resolves CAiNavigatorLand RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiNavigatorLandConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiNavigatorLandType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}

