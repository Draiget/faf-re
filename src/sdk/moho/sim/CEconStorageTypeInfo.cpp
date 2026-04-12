#include "moho/sim/CEconStorageTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CEconStorage.h"

using namespace moho;

namespace
{
  alignas(CEconStorageTypeInfo) unsigned char gStorage[sizeof(CEconStorageTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] CEconStorageTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) CEconStorageTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<CEconStorageTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<CEconStorageTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { moho::register_CEconStorageTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x00773320 (Moho::CEconStorageTypeInfo::CEconStorageTypeInfo)
 */
CEconStorageTypeInfo::CEconStorageTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconStorage), this);
}

CEconStorageTypeInfo::~CEconStorageTypeInfo() = default;

const char* CEconStorageTypeInfo::GetName() const { return "CEconStorage"; }

void CEconStorageTypeInfo::Init()
{
  size_ = 0x0C;
  gpg::RType::Init();
  Finish();
}

void moho::register_CEconStorageTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
