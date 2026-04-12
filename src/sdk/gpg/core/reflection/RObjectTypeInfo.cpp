#include "gpg/core/reflection/RObjectTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

using TypeInfo = gpg::RObjectTypeInfo;

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

  struct Bootstrap { Bootstrap() { gpg::register_RObjectTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/** Address: 0x008E0660 */
gpg::RObjectTypeInfo::RObjectTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(gpg::RObject), this);
}

gpg::RObjectTypeInfo::~RObjectTypeInfo() = default;

/** Address: 0x008E06D0 */
const char* gpg::RObjectTypeInfo::GetName() const { return "RObject"; }

/** Address: 0x008E06E0 */
void gpg::RObjectTypeInfo::Init()
{
  size_ = 4;
  gpg::RType::Init();
  Finish();
}

/** Address: 0x00BE99A0 */
void gpg::register_RObjectTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
