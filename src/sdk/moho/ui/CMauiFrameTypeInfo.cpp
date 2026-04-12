#include "moho/ui/CMauiFrameTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"

using namespace moho;

namespace
{
  alignas(CMauiFrameTypeInfo) unsigned char gCMauiFrameTypeInfoStorage[sizeof(CMauiFrameTypeInfo)];
  bool gCMauiFrameTypeInfoConstructed = false;

  [[nodiscard]] CMauiFrameTypeInfo& AcquireCMauiFrameTypeInfo()
  {
    if (!gCMauiFrameTypeInfoConstructed) {
      new (gCMauiFrameTypeInfoStorage) CMauiFrameTypeInfo();
      gCMauiFrameTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiFrameTypeInfo*>(gCMauiFrameTypeInfoStorage);
  }

  void cleanup_CMauiFrameTypeInfo()
  {
    if (!gCMauiFrameTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<CMauiFrameTypeInfo*>(gCMauiFrameTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiFrameTypeInfoBootstrap
  {
    CMauiFrameTypeInfoBootstrap() { moho::register_CMauiFrameTypeInfoStartup(); }
  };
  CMauiFrameTypeInfoBootstrap gCMauiFrameTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x00796060 (Moho::CMauiFrameTypeInfo::CMauiFrameTypeInfo)
 */
CMauiFrameTypeInfo::CMauiFrameTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiFrame), this);
}

/**
 * Address: 0x00796100
 */
CMauiFrameTypeInfo::~CMauiFrameTypeInfo() = default;

/**
 * Address: 0x007960F0
 */
const char* CMauiFrameTypeInfo::GetName() const
{
  return "CMauiFrame";
}

/**
 * Address: 0x007960C0
 */
void CMauiFrameTypeInfo::Init()
{
  size_ = 0x134;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDE5B0
 */
void moho::register_CMauiFrameTypeInfoStartup()
{
  (void)AcquireCMauiFrameTypeInfo();
  (void)std::atexit(&cleanup_CMauiFrameTypeInfo);
}
