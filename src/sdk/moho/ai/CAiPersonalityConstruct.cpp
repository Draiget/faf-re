#include "moho/ai/CAiPersonalityConstruct.h"

#include <typeinfo>

#include "moho/ai/CAiPersonality.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPersonalityType()
  {
    gpg::RType* type = CAiPersonality::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPersonality));
      CAiPersonality::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005B92D0 (FUN_005B92D0)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs construct/delete callbacks
 * from this helper object into the type descriptor.
 */
void CAiPersonalityConstruct::RegisterConstructFunction()
{
  gpg::RType* type = CachedCAiPersonalityType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
