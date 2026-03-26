#include "moho/ai/SAiReservedTransportBoneSerializer.h"

#include <typeinfo>

#include "moho/ai/SAiReservedTransportBone.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedSAiReservedTransportBoneType()
  {
    gpg::RType* type = SAiReservedTransportBone::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(SAiReservedTransportBone));
      SAiReservedTransportBone::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005E8F70 (FUN_005E8F70)
 *
 * What it does:
 * Lazily resolves SAiReservedTransportBone RTTI and installs load/save
 * callbacks from this helper object into the type descriptor.
 */
void SAiReservedTransportBoneSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedSAiReservedTransportBoneType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
