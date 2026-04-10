#include "moho/ai/CAiTransportImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(CAiTransportImplTypeInfo) unsigned char gCAiTransportImplTypeInfoStorage[sizeof(CAiTransportImplTypeInfo)];
  bool gCAiTransportImplTypeInfoConstructed = false;

  [[nodiscard]] CAiTransportImplTypeInfo* AcquireCAiTransportImplTypeInfo()
  {
    if (!gCAiTransportImplTypeInfoConstructed) {
      new (gCAiTransportImplTypeInfoStorage) CAiTransportImplTypeInfo();
      gCAiTransportImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiTransportImplTypeInfo*>(gCAiTransportImplTypeInfoStorage);
  }

  void cleanup_CAiTransportImplTypeInfo()
  {
    if (!gCAiTransportImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiTransportImplTypeInfo()->~CAiTransportImplTypeInfo();
    gCAiTransportImplTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedIAiTransportType()
  {
    if (!IAiTransport::sType) {
      IAiTransport::sType = gpg::LookupRType(typeid(IAiTransport));
    }
    return IAiTransport::sType;
  }
} // namespace

/**
 * Address: 0x005E8320 (FUN_005E8320, ??0CAiTransportImplTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `CAiTransportImpl` RTTI so lookup resolves to this type
 * helper.
 */
CAiTransportImplTypeInfo::CAiTransportImplTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiTransportImpl), this);
}

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

/**
 * Address: 0x00BCEEF0 (FUN_00BCEEF0, register_CAiTransportImplTypeInfo)
 *
 * What it does:
 * Registers `CAiTransportImpl` type-info object and installs process-exit
 * cleanup.
 */
int moho::register_CAiTransportImplTypeInfo()
{
  (void)AcquireCAiTransportImplTypeInfo();
  return std::atexit(&cleanup_CAiTransportImplTypeInfo);
}
