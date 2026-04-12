#include "gpg/core/reflection/RTypeTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

using TypeInfo = gpg::RTypeTypeInfo;

namespace
{
  alignas(TypeInfo) unsigned char gStorage[sizeof(TypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] TypeInfo& Acquire()
  {
    if (!gConstructed) { new (gStorage) TypeInfo(); gConstructed = true; }
    return *reinterpret_cast<TypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<TypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { gpg::register_RTypeTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/** Address: 0x008E0580 */
gpg::RTypeTypeInfo::RTypeTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(gpg::RType), this);
}

gpg::RTypeTypeInfo::~RTypeTypeInfo() = default;

/** Address: 0x008E05F0 */
const char* gpg::RTypeTypeInfo::GetName() const { return "RType"; }

/** Address: 0x008E1560 */
void gpg::RTypeTypeInfo::Init()
{
  size_ = 0x64;
  gpg::RType::Init();
  Finish();
}

/** Address: 0x00BE9980 */
void gpg::register_RTypeTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
