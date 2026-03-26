#include "moho/ai/CAiPersonalitySerializer.h"

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
 * Address: 0x005B9350 (FUN_005B9350)
 *
 * What it does:
 * Lazily resolves CAiPersonality RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPersonalitySerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiPersonalityType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
