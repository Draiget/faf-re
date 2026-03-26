#include "moho/ai/CAiNavigatorLandTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

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
 * Address: 0x005A45F0 (FUN_005A45F0, scalar deleting thunk)
 */
CAiNavigatorLandTypeInfo::~CAiNavigatorLandTypeInfo() = default;

/**
 * Address: 0x005A45E0 (FUN_005A45E0, ?GetName@CAiNavigatorLandTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorLandTypeInfo::GetName() const
{
  return "CAiNavigatorLand";
}

/**
 * Address: 0x005A45C0 (FUN_005A45C0, ?Init@CAiNavigatorLandTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorLandTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorLand);
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

