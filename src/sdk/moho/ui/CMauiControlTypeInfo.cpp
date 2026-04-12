#include "moho/ui/CMauiControlTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"

using namespace moho;

namespace
{
  alignas(CMauiControlTypeInfo) unsigned char gCMauiControlTypeInfoStorage[sizeof(CMauiControlTypeInfo)];
  bool gCMauiControlTypeInfoConstructed = false;

  [[nodiscard]] CMauiControlTypeInfo& AcquireCMauiControlTypeInfo()
  {
    if (!gCMauiControlTypeInfoConstructed) {
      new (gCMauiControlTypeInfoStorage) CMauiControlTypeInfo();
      gCMauiControlTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiControlTypeInfo*>(gCMauiControlTypeInfoStorage);
  }

  void cleanup_CMauiControlTypeInfo()
  {
    if (!gCMauiControlTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<CMauiControlTypeInfo*>(gCMauiControlTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiControlTypeInfoBootstrap
  {
    CMauiControlTypeInfoBootstrap() { moho::register_CMauiControlTypeInfoStartup(); }
  };
  CMauiControlTypeInfoBootstrap gCMauiControlTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x00786660 (Moho::CMauiControlTypeInfo::CMauiControlTypeInfo)
 */
CMauiControlTypeInfo::CMauiControlTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiControl), this);
}

/**
 * Address: 0x00786700
 */
CMauiControlTypeInfo::~CMauiControlTypeInfo() = default;

/**
 * Address: 0x007866F0
 */
const char* CMauiControlTypeInfo::GetName() const
{
  return "CMauiControl";
}

/**
 * Address: 0x007866C0
 */
void CMauiControlTypeInfo::Init()
{
  size_ = 0x11C;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDDD60
 */
void moho::register_CMauiControlTypeInfoStartup()
{
  (void)AcquireCMauiControlTypeInfo();
  (void)std::atexit(&cleanup_CMauiControlTypeInfo);
}
