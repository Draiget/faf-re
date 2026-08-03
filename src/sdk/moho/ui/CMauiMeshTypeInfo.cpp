#include "moho/ui/CMauiMeshTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiMeshTypeInfo) unsigned char gCMauiMeshTypeInfoStorage[sizeof(CMauiMeshTypeInfo)];
  bool gCMauiMeshTypeInfoConstructed = false;

  [[nodiscard]] CMauiMeshTypeInfo& AcquireCMauiMeshTypeInfo()
  {
    if (!gCMauiMeshTypeInfoConstructed) {
      new (gCMauiMeshTypeInfoStorage) CMauiMeshTypeInfo();
      gCMauiMeshTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiMeshTypeInfo*>(gCMauiMeshTypeInfoStorage);
  }

  void cleanup_CMauiMeshTypeInfo()
  {
    if (!gCMauiMeshTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiMeshTypeInfo*>(gCMauiMeshTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiMeshTypeInfoBootstrap
  {
    CMauiMeshTypeInfoBootstrap() { moho::register_CMauiMeshTypeInfoStartup(); }
  };
  CMauiMeshTypeInfoBootstrap gCMauiMeshTypeInfoBootstrap;

  /**
   * Address: 0x0079EAC0 (FUN_0079EAC0, Moho::CMauiMeshTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiMesh's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiMesh standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiMesh fails its upcast.
   */
  [[nodiscard]] gpg::RType* CachedCMauiControlType()
  {
    gpg::RType* baseType = moho::CMauiControl::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::CMauiControl));
      moho::CMauiControl::sType = baseType;
    }
    return baseType;
  }

  void AddCMauiControlBase(gpg::RType& typeInfo)
  {
    gpg::RType* const baseType = CachedCMauiControlType();

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
 * Address: 0x0079DC60 (FUN_0079DC60, Moho::CMauiMeshTypeInfo::CMauiMeshTypeInfo)
 */
CMauiMeshTypeInfo::CMauiMeshTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiMesh), this);
}

/**
 * Address: 0x0079DD00 (FUN_0079DD00, Moho::CMauiMeshTypeInfo::dtr)
 */
CMauiMeshTypeInfo::~CMauiMeshTypeInfo() = default;

/**
 * Address: 0x0079DCF0 (FUN_0079DCF0, Moho::CMauiMeshTypeInfo::GetName)
 */
const char* CMauiMeshTypeInfo::GetName() const
{
  return "CMauiMesh";
}

/**
 * Address: 0x0079DCC0 (FUN_0079DCC0, Moho::CMauiMeshTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiMeshTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 320 (0x140 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiMeshTypeInfo::Init()
{
  size_ = 0x140;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiMeshTypeInfoStartup()
{
  (void)AcquireCMauiMeshTypeInfo();
  (void)std::atexit(&cleanup_CMauiMeshTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiMeshTypeInfoStartup_79dc60, moho::register_CMauiMeshTypeInfoStartup)
