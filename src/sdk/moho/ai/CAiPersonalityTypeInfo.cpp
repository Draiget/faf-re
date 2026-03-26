#include "moho/ai/CAiPersonalityTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiPersonality.h"
#include "moho/script/CScriptObject.h"

using namespace moho;

namespace
{
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
 * Address: 0x005B68A0 (FUN_005B68A0, scalar deleting thunk)
 */
CAiPersonalityTypeInfo::~CAiPersonalityTypeInfo() = default;

/**
 * Address: 0x005B6890 (FUN_005B6890, ?GetName@CAiPersonalityTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPersonalityTypeInfo::GetName() const
{
  return "CAiPersonality";
}

/**
 * Address: 0x005B6870 (FUN_005B6870, ?Init@CAiPersonalityTypeInfo@Moho@@UAEXXZ)
 */
void CAiPersonalityTypeInfo::Init()
{
  size_ = sizeof(CAiPersonality);
  gpg::RType::Init();

  gpg::RField baseField{};
  baseField.mName = CachedCScriptObjectType()->GetName();
  baseField.mType = CachedCScriptObjectType();
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}
