#include "moho/ai/CAiFormationDBImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/IAiFormationDB.h"

using namespace moho;

/**
 * Address: 0x0059C5C0 (FUN_0059C5C0, scalar deleting thunk)
 */
CAiFormationDBImplTypeInfo::~CAiFormationDBImplTypeInfo() = default;

/**
 * Address: 0x0059C5B0 (FUN_0059C5B0, ?GetName@CAiFormationDBImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiFormationDBImplTypeInfo::GetName() const
{
  return "CAiFormationDBImpl";
}

/**
 * Address: 0x0059C570 (FUN_0059C570, ?Init@CAiFormationDBImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiFormationDBImplTypeInfo::Init()
{
  size_ = sizeof(CAiFormationDBImpl);
  gpg::RType::Init();

  static gpg::RType* sCachedIAiFormationDBType = nullptr;
  if (!sCachedIAiFormationDBType) {
    sCachedIAiFormationDBType = gpg::LookupRType(typeid(IAiFormationDB));
  }

  gpg::RType* const baseType = sCachedIAiFormationDBType;
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
