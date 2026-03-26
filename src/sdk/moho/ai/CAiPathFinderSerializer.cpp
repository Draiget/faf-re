#include "moho/ai/CAiPathFinderSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiPathFinderType()
  {
    gpg::RType* type = CAiPathFinder::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathFinder));
      CAiPathFinder::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005AB210 (FUN_005AB210)
 *
 * What it does:
 * Lazily resolves CAiPathFinder RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiPathFinderSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiPathFinderType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
