#include "gpg/core/reflection/voidTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

using TypeInfo = voidTypeInfo;

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

  struct Bootstrap { Bootstrap() { register_voidTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/** Address: 0x008DF9E0 */
voidTypeInfo::voidTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(void), this);
}

voidTypeInfo::~voidTypeInfo() = default;

/** Address: 0x008DFA60 */
const char* voidTypeInfo::GetName() const { return "void"; }

/** Address: 0x008DFA50 */
void voidTypeInfo::Init()
{
  size_ = 0;
  gpg::RType::Init();
  Finish();
}

/** Address: 0x00BE97E0 */
void register_voidTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
