#include "moho/ai/CAiNavigatorAirTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    gpg::RType* type = CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorImpl));
      CAiNavigatorImpl::sType = type;
    }
    return type;
  }
} // namespace

/**
 * Address: 0x005A54F0 (FUN_005A54F0, scalar deleting thunk)
 */
CAiNavigatorAirTypeInfo::~CAiNavigatorAirTypeInfo() = default;

/**
 * Address: 0x005A54E0 (FUN_005A54E0, ?GetName@CAiNavigatorAirTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorAirTypeInfo::GetName() const
{
  return "CAiNavigatorAir";
}

/**
 * Address: 0x005A54C0 (FUN_005A54C0, ?Init@CAiNavigatorAirTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorAirTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorAir);
  gpg::RType::Init();

  gpg::RField baseField{};
  baseField.mName = CachedCAiNavigatorImplType()->GetName();
  baseField.mType = CachedCAiNavigatorImplType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}

