#include "moho/ai/CAiFormationDBImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiFormationDBImpl.h"

using namespace moho;

/**
 * Address: 0x0059CBA0 (FUN_0059CBA0)
 *
 * What it does:
 * Lazily resolves CAiFormationDBImpl RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationDBImplSerializer::RegisterSerializeFunctions()
{
  static gpg::RType* sCachedType = nullptr;
  if (!sCachedType) {
    sCachedType = gpg::LookupRType(typeid(CAiFormationDBImpl));
  }

  gpg::RType* const type = sCachedType;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
