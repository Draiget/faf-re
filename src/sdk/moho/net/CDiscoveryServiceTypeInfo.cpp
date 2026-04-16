#include "moho/net/CDiscoveryServiceTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/net/CDiscoveryService.h"
#include "moho/script/CScriptObject.h"

using namespace moho;

namespace
{
  alignas(CDiscoveryServiceTypeInfo) unsigned char gStorage[sizeof(CDiscoveryServiceTypeInfo)];
  bool gConstructed = false;
  gpg::RType* gCDiscoveryServiceTypeCache = nullptr;

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!CScriptObject::sType) {
      CScriptObject::sType = gpg::LookupRType(typeid(CScriptObject));
    }
    return CScriptObject::sType;
  }

  /**
   * Address: 0x007BF490 (FUN_007BF490)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for
   * `CDiscoveryService`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCDiscoveryServiceTypePrimary()
  {
    if (gCDiscoveryServiceTypeCache == nullptr) {
      gCDiscoveryServiceTypeCache = gpg::LookupRType(typeid(CDiscoveryService));
    }
    return gCDiscoveryServiceTypeCache;
  }

  /**
   * Address: 0x007C8910 (FUN_007C8910)
   *
   * What it does:
   * Secondary cache accessor returning the reflection descriptor for
   * `CDiscoveryService`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCDiscoveryServiceTypeSecondary()
  {
    if (gCDiscoveryServiceTypeCache == nullptr) {
      gCDiscoveryServiceTypeCache = gpg::LookupRType(typeid(CDiscoveryService));
    }
    return gCDiscoveryServiceTypeCache;
  }

  /**
   * Address: 0x007CB2A0 (FUN_007CB2A0)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected `CDiscoveryService` base lane
   * at offset `+0x00`.
   */
  void AddCScriptObjectBaseToCDiscoveryServiceType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

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
    if (!gConstructed) {
      return;
    }
    auto& ti = *reinterpret_cast<CDiscoveryServiceTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { moho::register_CDiscoveryServiceTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x007BF500 (FUN_007BF500, Moho::CDiscoveryServiceTypeInfo::CDiscoveryServiceTypeInfo)
 */
CDiscoveryServiceTypeInfo::CDiscoveryServiceTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CDiscoveryService), this);
}

/**
 * Address: 0x007BF5A0 (FUN_007BF5A0, scalar deleting thunk)
 */
CDiscoveryServiceTypeInfo::~CDiscoveryServiceTypeInfo() = default;

/**
 * Address: 0x007BF590 (FUN_007BF590, Moho::CDiscoveryServiceTypeInfo::GetName)
 */
const char* CDiscoveryServiceTypeInfo::GetName() const
{
  return "CDiscoveryService";
}

/**
 * Address: 0x007BF560 (FUN_007BF560, Moho::CDiscoveryServiceTypeInfo::Init)
 */
void CDiscoveryServiceTypeInfo::Init()
{
  size_ = 0x90;
  AddCScriptObjectBaseToCDiscoveryServiceType(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDFD90 (FUN_00BDFD90, register_CDiscoveryServiceTypeInfo)
 */
void moho::register_CDiscoveryServiceTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
