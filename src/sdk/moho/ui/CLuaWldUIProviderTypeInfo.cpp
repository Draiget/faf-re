#include "moho/ui/CLuaWldUIProviderTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CLuaWldUIProviderTypeInfo) unsigned char gCLuaWldUIProviderTypeInfoStorage[sizeof(CLuaWldUIProviderTypeInfo)];
  bool gCLuaWldUIProviderTypeInfoConstructed = false;

  [[nodiscard]] CLuaWldUIProviderTypeInfo& AcquireCLuaWldUIProviderTypeInfo()
  {
    if (!gCLuaWldUIProviderTypeInfoConstructed) {
      new (gCLuaWldUIProviderTypeInfoStorage) CLuaWldUIProviderTypeInfo();
      gCLuaWldUIProviderTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CLuaWldUIProviderTypeInfo*>(gCLuaWldUIProviderTypeInfoStorage);
  }

  void cleanup_CLuaWldUIProviderTypeInfo()
  {
    if (!gCLuaWldUIProviderTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CLuaWldUIProviderTypeInfo*>(gCLuaWldUIProviderTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CLuaWldUIProviderTypeInfoBootstrap
  {
    CLuaWldUIProviderTypeInfoBootstrap() { moho::register_CLuaWldUIProviderTypeInfoStartup(); }
  };
  CLuaWldUIProviderTypeInfoBootstrap gCLuaWldUIProviderTypeInfoBootstrap;

  /**
   * Address: 0x0086ABF0 (FUN_0086ABF0, Moho::CLuaWldUIProviderTypeInfo::AddBase_CScriptObject)
   *
   * What it does:
   * Declares CScriptObject as CLuaWldUIProvider's reflected base, at offset 0, resolving it
   * through the cached `CScriptObject::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CLuaWldUIProvider standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CLuaWldUIProvider fails its upcast.
   */
  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    gpg::RType* baseType = moho::CScriptObject::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::CScriptObject));
      moho::CScriptObject::sType = baseType;
    }
    return baseType;
  }

  void AddCScriptObjectBase(gpg::RType& typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x0086A3E0 (FUN_0086A3E0, Moho::CLuaWldUIProviderTypeInfo::CLuaWldUIProviderTypeInfo)
 */
CLuaWldUIProviderTypeInfo::CLuaWldUIProviderTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CLuaWldUIProvider), this);
}

/**
 * Address: 0x0086A480 (FUN_0086A480, Moho::CLuaWldUIProviderTypeInfo::dtr)
 */
CLuaWldUIProviderTypeInfo::~CLuaWldUIProviderTypeInfo() = default;

/**
 * Address: 0x0086A470 (FUN_0086A470, Moho::CLuaWldUIProviderTypeInfo::GetName)
 */
const char* CLuaWldUIProviderTypeInfo::GetName() const
{
  return "CLuaWldUIProvider";
}

/**
 * Address: 0x0086A440 (FUN_0086A440, Moho::CLuaWldUIProviderTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CLuaWldUIProviderTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 72 (0x48 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CScriptObject
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CLuaWldUIProviderTypeInfo::Init()
{
  size_ = 0x48;
  AddCScriptObjectBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CLuaWldUIProviderTypeInfoStartup()
{
  (void)AcquireCLuaWldUIProviderTypeInfo();
  (void)std::atexit(&cleanup_CLuaWldUIProviderTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CLuaWldUIProviderTypeInfoStartup_86a3e0, moho::register_CLuaWldUIProviderTypeInfoStartup)
