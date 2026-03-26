#include "moho/ai/CAiBrainSerializer.h"

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
 * Address: 0x0057E460 (FUN_0057E460)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs load/save callbacks from this
 * helper object into the type descriptor.
 */
void CAiBrainSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
