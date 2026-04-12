#include "moho/sim/CEconomyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CEconomy.h"

using namespace moho;

namespace
{
  alignas(CEconomyTypeInfo) unsigned char gCEconomyTypeInfoStorage[sizeof(CEconomyTypeInfo)];
  bool gCEconomyTypeInfoConstructed = false;

  [[nodiscard]] CEconomyTypeInfo& AcquireCEconomyTypeInfo()
  {
    if (!gCEconomyTypeInfoConstructed) {
      new (gCEconomyTypeInfoStorage) CEconomyTypeInfo();
      gCEconomyTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CEconomyTypeInfo*>(gCEconomyTypeInfoStorage);
  }

  void cleanup_CEconomyTypeInfo()
  {
    if (!gCEconomyTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<CEconomyTypeInfo*>(gCEconomyTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CEconomyTypeInfoBootstrap
  {
    CEconomyTypeInfoBootstrap() { moho::register_CEconomyTypeInfoStartup(); }
  };
  CEconomyTypeInfoBootstrap gCEconomyTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x00772DE0 (Moho::CEconomyTypeInfo::CEconomyTypeInfo)
 */
CEconomyTypeInfo::CEconomyTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconomy), this);
}

/**
 * Address: 0x00772E70
 */
CEconomyTypeInfo::~CEconomyTypeInfo() = default;

/**
 * Address: 0x00772E60
 */
const char* CEconomyTypeInfo::GetName() const
{
  return "CEconomy";
}

/**
 * Address: 0x00772E40
 */
void CEconomyTypeInfo::Init()
{
  size_ = 0x60;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDD0B0
 */
void moho::register_CEconomyTypeInfoStartup()
{
  (void)AcquireCEconomyTypeInfo();
  (void)std::atexit(&cleanup_CEconomyTypeInfo);
}
