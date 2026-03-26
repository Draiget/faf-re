#include "moho/ai/CAiSteeringImplSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiSteeringImpl.h"

using namespace moho;

/**
 * Address: 0x005D3EB0 (FUN_005D3EB0)
 */
void CAiSteeringImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CAiSteeringImpl::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiSteeringImpl));
    CAiSteeringImpl::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}
