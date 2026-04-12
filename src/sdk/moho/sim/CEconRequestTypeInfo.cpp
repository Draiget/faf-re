#include "moho/sim/CEconRequestTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/misc/CEconomyEvent.h"

using namespace moho;

namespace
{
  alignas(CEconRequestTypeInfo) unsigned char gCEconRequestTypeInfoStorage[sizeof(CEconRequestTypeInfo)];
  bool gCEconRequestTypeInfoConstructed = false;

  [[nodiscard]] CEconRequestTypeInfo& AcquireCEconRequestTypeInfo()
  {
    if (!gCEconRequestTypeInfoConstructed) {
      new (gCEconRequestTypeInfoStorage) CEconRequestTypeInfo();
      gCEconRequestTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CEconRequestTypeInfo*>(gCEconRequestTypeInfoStorage);
  }

  void cleanup_CEconRequestTypeInfo()
  {
    if (!gCEconRequestTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<CEconRequestTypeInfo*>(gCEconRequestTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CEconRequestTypeInfoBootstrap
  {
    CEconRequestTypeInfoBootstrap() { moho::register_CEconRequestTypeInfoStartup(); }
  };
  CEconRequestTypeInfoBootstrap gCEconRequestTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x007737B0 (Moho::CEconRequestTypeInfo::CEconRequestTypeInfo)
 */
CEconRequestTypeInfo::CEconRequestTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconRequest), this);
}

/**
 * Address: 0x00773840
 */
CEconRequestTypeInfo::~CEconRequestTypeInfo() = default;

/**
 * Address: 0x00773830
 */
const char* CEconRequestTypeInfo::GetName() const
{
  return "CEconRequest";
}

/**
 * Address: 0x00773810
 */
void CEconRequestTypeInfo::Init()
{
  size_ = 0x18;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDD1F0
 */
void moho::register_CEconRequestTypeInfoStartup()
{
  (void)AcquireCEconRequestTypeInfo();
  (void)std::atexit(&cleanup_CEconRequestTypeInfo);
}
