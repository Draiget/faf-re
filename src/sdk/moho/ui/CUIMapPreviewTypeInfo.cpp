#include "moho/ui/CUIMapPreviewTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CUIMapPreviewTypeInfo) unsigned char gCUIMapPreviewTypeInfoStorage[sizeof(CUIMapPreviewTypeInfo)];
  bool gCUIMapPreviewTypeInfoConstructed = false;

  [[nodiscard]] CUIMapPreviewTypeInfo& AcquireCUIMapPreviewTypeInfo()
  {
    if (!gCUIMapPreviewTypeInfoConstructed) {
      new (gCUIMapPreviewTypeInfoStorage) CUIMapPreviewTypeInfo();
      gCUIMapPreviewTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CUIMapPreviewTypeInfo*>(gCUIMapPreviewTypeInfoStorage);
  }

  void cleanup_CUIMapPreviewTypeInfo()
  {
    if (!gCUIMapPreviewTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CUIMapPreviewTypeInfo*>(gCUIMapPreviewTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CUIMapPreviewTypeInfoBootstrap
  {
    CUIMapPreviewTypeInfoBootstrap() { moho::register_CUIMapPreviewTypeInfoStartup(); }
  };
  CUIMapPreviewTypeInfoBootstrap gCUIMapPreviewTypeInfoBootstrap;

  /**
   * Address: 0x008513D0 (FUN_008513D0, Moho::CUIMapPreviewTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CUIMapPreview's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CUIMapPreview standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CUIMapPreview fails its upcast.
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
 * Address: 0x00850620 (FUN_00850620, Moho::CUIMapPreviewTypeInfo::CUIMapPreviewTypeInfo)
 */
CUIMapPreviewTypeInfo::CUIMapPreviewTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CUIMapPreview), this);
}

/**
 * Address: 0x008506C0 (FUN_008506C0, Moho::CUIMapPreviewTypeInfo::dtr)
 */
CUIMapPreviewTypeInfo::~CUIMapPreviewTypeInfo() = default;

/**
 * Address: 0x008506B0 (FUN_008506B0, Moho::CUIMapPreviewTypeInfo::GetName)
 */
const char* CUIMapPreviewTypeInfo::GetName() const
{
  return "CUIMapPreview";
}

/**
 * Address: 0x00850680 (FUN_00850680, Moho::CUIMapPreviewTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CUIMapPreviewTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 292 (0x124 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CUIMapPreviewTypeInfo::Init()
{
  size_ = 0x124;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CUIMapPreviewTypeInfoStartup()
{
  (void)AcquireCUIMapPreviewTypeInfo();
  (void)std::atexit(&cleanup_CUIMapPreviewTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUIMapPreviewTypeInfoStartup_850620, moho::register_CUIMapPreviewTypeInfoStartup)
