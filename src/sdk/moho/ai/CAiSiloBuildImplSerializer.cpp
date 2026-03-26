#include "moho/ai/CAiSiloBuildImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiSiloBuildImplType()
  {
    gpg::RType* type = CAiSiloBuildImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiSiloBuildImpl));
      CAiSiloBuildImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005CFF30 (FUN_005CFF30)
 *
 * void ()
 *
 * IDA signature:
 * void (__cdecl *__thiscall sub_5CFF30(_DWORD *this))(gpg::ReadArchive *, int, int, gpg::RRef *);
 *
 * What it does:
 * Lazily resolves CAiSiloBuildImpl RTTI and installs load/save callbacks from
 * this helper object into the type descriptor.
 */
void CAiSiloBuildImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCAiSiloBuildImplType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
