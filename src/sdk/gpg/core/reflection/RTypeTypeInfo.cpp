#include "gpg/core/reflection/RTypeTypeInfo.h"
#include "gpg/core/reflection/Reflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

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
/**
 * Address: 0x008E09C0 (FUN_008E09C0, gpg::RTypeTypeInfo::AddBase_RObject)
 *
 * What it does:
 * Registers `RObject` as `RType`'s reflected base at offset 0.
 */
void gpg::RTypeTypeInfo::AddBase_RObject(gpg::RType* const typeInfo)
{
  static gpg::RType* sRObjectType = nullptr;
  if (!sRObjectType) {
    sRObjectType = gpg::LookupRType(typeid(gpg::RObject));
  }
  gpg::AddBaseIfPresent(typeInfo, sRObjectType, 0);
}

void gpg::RTypeTypeInfo::Init()
{
  size_ = 0x64;
  gpg::RType::Init();
  AddBase_RObject(this);
  Finish();
}

/** Address: 0x00BE9980 */
void gpg::register_RTypeTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RTypeTypeInfoStartup_668427, gpg::register_RTypeTypeInfoStartup)
