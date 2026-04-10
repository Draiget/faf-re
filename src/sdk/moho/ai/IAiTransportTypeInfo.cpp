#include "moho/ai/IAiTransportTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiTransport.h"
#include "moho/unit/Broadcaster.h"

using namespace moho;

namespace
{
  alignas(IAiTransportTypeInfo) unsigned char gIAiTransportTypeInfoStorage[sizeof(IAiTransportTypeInfo)];
  bool gIAiTransportTypeInfoConstructed = false;

  [[nodiscard]] IAiTransportTypeInfo* AcquireIAiTransportTypeInfo()
  {
    if (!gIAiTransportTypeInfoConstructed) {
      new (gIAiTransportTypeInfoStorage) IAiTransportTypeInfo();
      gIAiTransportTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiTransportTypeInfo*>(gIAiTransportTypeInfoStorage);
  }

  void cleanup_IAiTransportTypeInfo()
  {
    if (!gIAiTransportTypeInfoConstructed) {
      return;
    }

    AcquireIAiTransportTypeInfo()->~IAiTransportTypeInfo();
    gIAiTransportTypeInfoConstructed = false;
  }

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
 * Address: 0x005E4740 (FUN_005E4740, ??0IAiTransportTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `IAiTransport` RTTI so lookup resolves to this type helper.
 */
IAiTransportTypeInfo::IAiTransportTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(IAiTransport), this);
}

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

/**
 * Address: 0x00BCEE90 (FUN_00BCEE90, register_IAiTransportTypeInfo)
 *
 * What it does:
 * Registers `IAiTransport` type-info object and installs process-exit
 * cleanup.
 */
int moho::register_IAiTransportTypeInfo()
{
  (void)AcquireIAiTransportTypeInfo();
  return std::atexit(&cleanup_IAiTransportTypeInfo);
}
