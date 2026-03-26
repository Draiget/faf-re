#include "moho/ai/CAiFormationInstanceSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiFormationInstance.h"

using namespace moho;

/**
 * Address: 0x0059C820 (FUN_0059C820)
 *
 * What it does:
 * Lazily resolves CAiFormationInstance RTTI and installs load/save callbacks
 * from this helper object into the type descriptor.
 */
void CAiFormationInstanceSerializer::RegisterSerializeFunctions()
{
  static gpg::RType* sCachedType = nullptr;
  if (!sCachedType) {
    sCachedType = gpg::LookupRType(typeid(CAiFormationInstance));
  }

  gpg::RType* const type = sCachedType;
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}
