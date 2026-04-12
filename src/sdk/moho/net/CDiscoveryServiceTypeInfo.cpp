#include "moho/net/CDiscoveryServiceTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/net/CDiscoveryService.h"

using namespace moho;

namespace
{
  alignas(CDiscoveryServiceTypeInfo) unsigned char gStorage[sizeof(CDiscoveryServiceTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] CDiscoveryServiceTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) CDiscoveryServiceTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<CDiscoveryServiceTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<CDiscoveryServiceTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { moho::register_CDiscoveryServiceTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x007BF500 (Moho::CDiscoveryServiceTypeInfo::CDiscoveryServiceTypeInfo)
 */
CDiscoveryServiceTypeInfo::CDiscoveryServiceTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CDiscoveryService), this);
}

CDiscoveryServiceTypeInfo::~CDiscoveryServiceTypeInfo() = default;

const char* CDiscoveryServiceTypeInfo::GetName() const { return "CDiscoveryService"; }

void CDiscoveryServiceTypeInfo::Init()
{
  size_ = 0x90;
  gpg::RType::Init();
  Finish();
}

void moho::register_CDiscoveryServiceTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
