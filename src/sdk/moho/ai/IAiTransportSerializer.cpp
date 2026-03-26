#include "moho/ai/IAiTransportSerializer.h"

#include <typeinfo>

#include "moho/ai/IAiTransport.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    gpg::RType* type = IAiTransport::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiTransport));
      IAiTransport::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E9530 (FUN_005E9530)
 *
 * What it does:
 * Lazily resolves IAiTransport RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void IAiTransportSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedIAiTransportType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
