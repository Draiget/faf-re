#include "moho/ai/CAiNavigatorImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiNavigatorImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    if (!IAiNavigator::sType) {
      IAiNavigator::sType = gpg::LookupRType(typeid(IAiNavigator));
    }
    return IAiNavigator::sType;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }
} // namespace

/**
 * Address: 0x005A3930 (FUN_005A3930, scalar deleting thunk)
 */
CAiNavigatorImplTypeInfo::~CAiNavigatorImplTypeInfo() = default;

/**
 * Address: 0x005A3920 (FUN_005A3920, ?GetName@CAiNavigatorImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorImplTypeInfo::GetName() const
{
  return "CAiNavigatorImpl";
}

/**
 * Address: 0x005A38E0 (FUN_005A38E0, ?Init@CAiNavigatorImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorImplTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorImpl);
  Version(1);
  gpg::RType::Init();

  gpg::RField baseField{};

  baseField.mName = CachedIAiNavigatorType()->GetName();
  baseField.mType = CachedIAiNavigatorType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  baseField.mName = CachedCTaskType()->GetName();
  baseField.mType = CachedCTaskType();
  baseField.mOffset = 0x10;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  baseField.mName = CachedCScriptObjectType()->GetName();
  baseField.mType = CachedCScriptObjectType();
  baseField.mOffset = 0x28;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}

