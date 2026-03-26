#include "moho/ai/CAiSiloBuildImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiSiloBuildImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiSiloBuildType()
  {
    if (!IAiSiloBuild::sType) {
      IAiSiloBuild::sType = gpg::LookupRType(typeid(IAiSiloBuild));
    }
    return IAiSiloBuild::sType;
  }
} // namespace

/**
 * Address: 0x005CF700 (FUN_005CF700, scalar deleting thunk)
 */
CAiSiloBuildImplTypeInfo::~CAiSiloBuildImplTypeInfo() = default;

/**
 * Address: 0x005CF6F0 (FUN_005CF6F0, ?GetName@CAiSiloBuildImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiSiloBuildImplTypeInfo::GetName() const
{
  return "CAiSiloBuildImpl";
}

/**
 * Address: 0x005CF6D0 (FUN_005CF6D0, ?Init@CAiSiloBuildImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiSiloBuildImplTypeInfo::Init()
{
  size_ = sizeof(CAiSiloBuildImpl);
  gpg::RType::Init();

  gpg::RType* const baseType = CachedIAiSiloBuildType();
  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
}
