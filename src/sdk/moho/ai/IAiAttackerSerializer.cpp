#include "moho/ai/IAiAttackerSerializer.h"

#include <typeinfo>

#include "moho/ai/IAiAttacker.h"

using namespace moho;

/**
 * Address: 0x005DBC90 (FUN_005DBC90)
 *
 * What it does:
 * Lazily resolves IAiAttacker RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void IAiAttackerSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = IAiAttacker::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(IAiAttacker));
    IAiAttacker::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
