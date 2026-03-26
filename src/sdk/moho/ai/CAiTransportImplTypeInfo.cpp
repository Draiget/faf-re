#include "moho/ai/CAiTransportImplTypeInfo.h"

#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    if (!IAiTransport::sType) {
      IAiTransport::sType = gpg::LookupRType(typeid(IAiTransport));
    }
    return IAiTransport::sType;
  }
} // namespace

/**
 * Address: 0x005E83B0 (FUN_005E83B0, scalar deleting thunk)
 */
CAiTransportImplTypeInfo::~CAiTransportImplTypeInfo() = default;

/**
 * Address: 0x005E83A0 (FUN_005E83A0, ?GetName@CAiTransportImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiTransportImplTypeInfo::GetName() const
{
  return "CAiTransportImpl";
}

/**
 * Address: 0x005E8380 (FUN_005E8380, ?Init@CAiTransportImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiTransportImplTypeInfo::Init()
{
  size_ = sizeof(CAiTransportImpl);
  gpg::RType::Init();

  gpg::RField baseField{};
  gpg::RType* const baseType = CachedIAiTransportType();
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  AddBase(baseField);

  Finish();
}
