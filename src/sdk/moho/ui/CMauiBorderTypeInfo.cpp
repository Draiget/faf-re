#include "moho/ui/CMauiBorderTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiBorderTypeInfo) unsigned char gCMauiBorderTypeInfoStorage[sizeof(CMauiBorderTypeInfo)];
  bool gCMauiBorderTypeInfoConstructed = false;

  [[nodiscard]] CMauiBorderTypeInfo& AcquireCMauiBorderTypeInfo()
  {
    if (!gCMauiBorderTypeInfoConstructed) {
      new (gCMauiBorderTypeInfoStorage) CMauiBorderTypeInfo();
      gCMauiBorderTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiBorderTypeInfo*>(gCMauiBorderTypeInfoStorage);
  }

  void cleanup_CMauiBorderTypeInfo()
  {
    if (!gCMauiBorderTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiBorderTypeInfo*>(gCMauiBorderTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiBorderTypeInfoBootstrap
  {
    CMauiBorderTypeInfoBootstrap() { moho::register_CMauiBorderTypeInfoStartup(); }
  };
  CMauiBorderTypeInfoBootstrap gCMauiBorderTypeInfoBootstrap;

  /**
   * Address: 0x007861B0 (FUN_007861B0, Moho::CMauiBorderTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiBorder's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiBorder standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiBorder fails its upcast.
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
 * Address: 0x007848C0 (FUN_007848C0, Moho::CMauiBorderTypeInfo::CMauiBorderTypeInfo)
 */
CMauiBorderTypeInfo::CMauiBorderTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiBorder), this);
}

/**
 * Address: 0x00784960 (FUN_00784960, Moho::CMauiBorderTypeInfo::dtr)
 */
CMauiBorderTypeInfo::~CMauiBorderTypeInfo() = default;

/**
 * Address: 0x00784950 (FUN_00784950, Moho::CMauiBorderTypeInfo::GetName)
 */
const char* CMauiBorderTypeInfo::GetName() const
{
  return "CMauiBorder";
}

/**
 * Address: 0x00784920 (FUN_00784920, Moho::CMauiBorderTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiBorderTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 372 (0x174 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiBorderTypeInfo::Init()
{
  size_ = 0x174;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiBorderTypeInfoStartup()
{
  (void)AcquireCMauiBorderTypeInfo();
  (void)std::atexit(&cleanup_CMauiBorderTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiBorderTypeInfoStartup_7848c0, moho::register_CMauiBorderTypeInfoStartup)
