#include "moho/ai/IAiTransportTypeInfo.h"

#include <typeinfo>

#include "moho/ai/IAiTransport.h"
#include "moho/unit/Broadcaster.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedBroadcasterType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Broadcaster));
    }
    return cached;
  }
} // namespace

/**
 * Address: 0x005E47D0 (FUN_005E47D0, scalar deleting thunk)
 */
IAiTransportTypeInfo::~IAiTransportTypeInfo() = default;

/**
 * Address: 0x005E47C0 (FUN_005E47C0, ?GetName@IAiTransportTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiTransportTypeInfo::GetName() const
{
  return "IAiTransport";
}

/**
 * Address: 0x005E47A0 (FUN_005E47A0, ?Init@IAiTransportTypeInfo@Moho@@UAEXXZ)
 */
void IAiTransportTypeInfo::Init()
{
  size_ = sizeof(IAiTransport);
  gpg::RType::Init();

  gpg::RType* const baseType = CachedBroadcasterType();
  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 4;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  Finish();
}
