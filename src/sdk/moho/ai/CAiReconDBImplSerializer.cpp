#include "moho/ai/CAiReconDBImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiReconDBImpl.h"

using namespace moho;

/**
 * Address: 0x005C4EE0 (FUN_005C4EE0)
 */
void CAiReconDBImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CAiReconDBImpl::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiReconDBImpl));
    CAiReconDBImpl::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}
