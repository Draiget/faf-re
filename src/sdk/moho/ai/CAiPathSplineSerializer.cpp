#include "moho/ai/CAiPathSplineSerializer.h"

#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

/**
 * Address: 0x005B48E0 (FUN_005B48E0)
 */
void CAiPathSplineSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CAiPathSpline::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiPathSpline));
    CAiPathSpline::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}
