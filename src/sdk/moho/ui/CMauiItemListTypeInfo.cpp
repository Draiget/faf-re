#include "moho/ui/CMauiItemListTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiItemListTypeInfo) unsigned char gCMauiItemListTypeInfoStorage[sizeof(CMauiItemListTypeInfo)];
  bool gCMauiItemListTypeInfoConstructed = false;

  [[nodiscard]] CMauiItemListTypeInfo& AcquireCMauiItemListTypeInfo()
  {
    if (!gCMauiItemListTypeInfoConstructed) {
      new (gCMauiItemListTypeInfoStorage) CMauiItemListTypeInfo();
      gCMauiItemListTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiItemListTypeInfo*>(gCMauiItemListTypeInfoStorage);
  }

  void cleanup_CMauiItemListTypeInfo()
  {
    if (!gCMauiItemListTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiItemListTypeInfo*>(gCMauiItemListTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiItemListTypeInfoBootstrap
  {
    CMauiItemListTypeInfoBootstrap() { moho::register_CMauiItemListTypeInfoStartup(); }
  };
  CMauiItemListTypeInfoBootstrap gCMauiItemListTypeInfoBootstrap;

  /**
   * Address: 0x0079C940 (FUN_0079C940, Moho::CMauiItemListTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiItemList's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiItemList standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiItemList fails its upcast.
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
 * Address: 0x007991F0 (FUN_007991F0, Moho::CMauiItemListTypeInfo::CMauiItemListTypeInfo)
 */
CMauiItemListTypeInfo::CMauiItemListTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiItemList), this);
}

/**
 * Address: 0x00799290 (FUN_00799290, Moho::CMauiItemListTypeInfo::dtr)
 */
CMauiItemListTypeInfo::~CMauiItemListTypeInfo() = default;

/**
 * Address: 0x00799280 (FUN_00799280, Moho::CMauiItemListTypeInfo::GetName)
 */
const char* CMauiItemListTypeInfo::GetName() const
{
  return "CMauiItemList";
}

/**
 * Address: 0x00799250 (FUN_00799250, Moho::CMauiItemListTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiItemListTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 344 (0x158 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiItemListTypeInfo::Init()
{
  size_ = 0x158;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiItemListTypeInfoStartup()
{
  (void)AcquireCMauiItemListTypeInfo();
  (void)std::atexit(&cleanup_CMauiItemListTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiItemListTypeInfoStartup_7991f0, moho::register_CMauiItemListTypeInfoStartup)
