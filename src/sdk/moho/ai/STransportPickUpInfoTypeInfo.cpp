#include "moho/ai/STransportPickUpInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"

using namespace moho;

namespace
{
  alignas(STransportPickUpInfoTypeInfo)
    unsigned char gSTransportPickUpInfoTypeInfoStorage[sizeof(STransportPickUpInfoTypeInfo)];
  bool gSTransportPickUpInfoTypeInfoConstructed = false;

  [[nodiscard]] STransportPickUpInfoTypeInfo* AcquireSTransportPickUpInfoTypeInfo()
  {
    if (!gSTransportPickUpInfoTypeInfoConstructed) {
      new (gSTransportPickUpInfoTypeInfoStorage) STransportPickUpInfoTypeInfo();
      gSTransportPickUpInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<STransportPickUpInfoTypeInfo*>(gSTransportPickUpInfoTypeInfoStorage);
  }

  void cleanup_STransportPickUpInfoTypeInfo()
  {
    if (!gSTransportPickUpInfoTypeInfoConstructed) {
      return;
    }

    AcquireSTransportPickUpInfoTypeInfo()->~STransportPickUpInfoTypeInfo();
    gSTransportPickUpInfoTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005E4520 (FUN_005E4520, ??0STransportPickUpInfoTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `STransportPickUpInfo` RTTI so lookup resolves to this type
 * helper.
 */
STransportPickUpInfoTypeInfo::STransportPickUpInfoTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(STransportPickUpInfo), this);
}

/**
 * Address: 0x005E45B0 (FUN_005E45B0, scalar deleting thunk)
 */
STransportPickUpInfoTypeInfo::~STransportPickUpInfoTypeInfo() = default;

/**
 * Address: 0x005E45A0 (FUN_005E45A0, STransportPickUpInfoTypeInfo::GetName)
 */
const char* STransportPickUpInfoTypeInfo::GetName() const
{
  return "STransportPickUpInfo";
}

/**
 * Address: 0x005E4580 (FUN_005E4580, STransportPickUpInfoTypeInfo::Init)
 */
void STransportPickUpInfoTypeInfo::Init()
{
  size_ = sizeof(STransportPickUpInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCEE30 (FUN_00BCEE30, register_STransportPickUpInfoTypeInfo)
 *
 * What it does:
 * Registers `STransportPickUpInfo` type-info and installs process-exit
 * cleanup.
 */
int moho::register_STransportPickUpInfoTypeInfo()
{
  (void)AcquireSTransportPickUpInfoTypeInfo();
  return std::atexit(&cleanup_STransportPickUpInfoTypeInfo);
}
