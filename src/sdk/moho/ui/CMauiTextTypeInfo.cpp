#include "moho/ui/CMauiTextTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiTextTypeInfo) unsigned char gCMauiTextTypeInfoStorage[sizeof(CMauiTextTypeInfo)];
  bool gCMauiTextTypeInfoConstructed = false;

  [[nodiscard]] CMauiTextTypeInfo& AcquireCMauiTextTypeInfo()
  {
    if (!gCMauiTextTypeInfoConstructed) {
      new (gCMauiTextTypeInfoStorage) CMauiTextTypeInfo();
      gCMauiTextTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiTextTypeInfo*>(gCMauiTextTypeInfoStorage);
  }

  void cleanup_CMauiTextTypeInfo()
  {
    if (!gCMauiTextTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiTextTypeInfo*>(gCMauiTextTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiTextTypeInfoBootstrap
  {
    CMauiTextTypeInfoBootstrap() { moho::register_CMauiTextTypeInfoStartup(); }
  };
  CMauiTextTypeInfoBootstrap gCMauiTextTypeInfoBootstrap;

  /**
   * Address: 0x007A4280 (FUN_007A4280, Moho::CMauiTextTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiText's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiText standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiText fails its upcast.
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
 * Address: 0x007A2A90 (FUN_007A2A90, Moho::CMauiTextTypeInfo::CMauiTextTypeInfo)
 */
CMauiTextTypeInfo::CMauiTextTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiText), this);
}

/**
 * Address: 0x007A2B30 (FUN_007A2B30, Moho::CMauiTextTypeInfo::dtr)
 */
CMauiTextTypeInfo::~CMauiTextTypeInfo() = default;

/**
 * Address: 0x007A2B20 (FUN_007A2B20, Moho::CMauiTextTypeInfo::GetName)
 */
const char* CMauiTextTypeInfo::GetName() const
{
  return "CMauiText";
}

/**
 * Address: 0x007A2AF0 (FUN_007A2AF0, Moho::CMauiTextTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiTextTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 404 (0x194 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiTextTypeInfo::Init()
{
  size_ = 0x194;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiTextTypeInfoStartup()
{
  (void)AcquireCMauiTextTypeInfo();
  (void)std::atexit(&cleanup_CMauiTextTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiTextTypeInfoStartup_7a2a90, moho::register_CMauiTextTypeInfoStartup)
