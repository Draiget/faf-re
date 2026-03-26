#include "moho/ai/CAiBuilderImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiBuilderImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiBuilderType()
  {
    if (!IAiBuilder::sType) {
      IAiBuilder::sType = gpg::LookupRType(typeid(IAiBuilder));
    }
    return IAiBuilder::sType;
  }
} // namespace

/**
 * Address: 0x0059FC40 (FUN_0059FC40, scalar deleting thunk)
 */
CAiBuilderImplTypeInfo::~CAiBuilderImplTypeInfo() = default;

/**
 * Address: 0x0059FC30 (FUN_0059FC30, ?GetName@CAiBuilderImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBuilderImplTypeInfo::GetName() const
{
  return "CAiBuilderImpl";
}

/**
 * Address: 0x0059FC10 (FUN_0059FC10, ?Init@CAiBuilderImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiBuilderImplTypeInfo::Init()
{
  size_ = sizeof(CAiBuilderImpl);
  gpg::RType::Init();

  gpg::RField baseField{};
  baseField.mName = CachedIAiBuilderType()->GetName();
  baseField.mType = CachedIAiBuilderType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}
