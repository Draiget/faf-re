#include "moho/sim/SMassInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/SMassInfo.h"

using namespace moho;

namespace
{
  alignas(SMassInfoTypeInfo) unsigned char gSMassInfoTypeInfoStorage[sizeof(SMassInfoTypeInfo)];
  bool gSMassInfoTypeInfoConstructed = false;

  [[nodiscard]] SMassInfoTypeInfo& AcquireSMassInfoTypeInfo()
  {
    if (!gSMassInfoTypeInfoConstructed) {
      new (gSMassInfoTypeInfoStorage) SMassInfoTypeInfo();
      gSMassInfoTypeInfoConstructed = true;
    }
    return *reinterpret_cast<SMassInfoTypeInfo*>(gSMassInfoTypeInfoStorage);
  }

  [[nodiscard]] SMassInfoTypeInfo* PeekSMassInfoTypeInfo() noexcept
  {
    if (!gSMassInfoTypeInfoConstructed) {
      return nullptr;
    }
    return reinterpret_cast<SMassInfoTypeInfo*>(gSMassInfoTypeInfoStorage);
  }

  void cleanup_SMassInfoTypeInfoStartup()
  {
    SMassInfoTypeInfo* const typeInfo = PeekSMassInfoTypeInfo();
    if (!typeInfo) {
      return;
    }
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct SMassInfoTypeInfoStartupBootstrap
  {
    SMassInfoTypeInfoStartupBootstrap()
    {
      moho::register_SMassInfoTypeInfoStartup();
    }
  };

  SMassInfoTypeInfoStartupBootstrap gSMassInfoTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00585CD0 (FUN_00585CD0, ??0SMassInfoTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `SMassInfo` RTTI for this type-info helper.
 */
SMassInfoTypeInfo::SMassInfoTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(SMassInfo), this);
}

/**
 * Address: 0x00585D60 (FUN_00585D60, scalar deleting thunk)
 */
SMassInfoTypeInfo::~SMassInfoTypeInfo() = default;

/**
 * Address: 0x00585D50 (FUN_00585D50, ?GetName@SMassInfoTypeInfo@Moho@@UBEPBDXZ)
 */
const char* SMassInfoTypeInfo::GetName() const
{
  return "SMassInfo";
}

/**
 * Address: 0x00585D30 (FUN_00585D30, ?Init@SMassInfoTypeInfo@Moho@@UAEXXZ)
 *
 * What it does:
 * Sets size = 0x0C and finalizes.
 */
void SMassInfoTypeInfo::Init()
{
  size_ = sizeof(SMassInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCB6E0 (FUN_00BCB6E0, register_SMassInfoTypeInfo)
 */
void moho::register_SMassInfoTypeInfoStartup()
{
  (void)AcquireSMassInfoTypeInfo();
  (void)std::atexit(&cleanup_SMassInfoTypeInfoStartup);
}
