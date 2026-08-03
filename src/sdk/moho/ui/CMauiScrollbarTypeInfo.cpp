#include "moho/ui/CMauiScrollbarTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiScrollbarTypeInfo) unsigned char gCMauiScrollbarTypeInfoStorage[sizeof(CMauiScrollbarTypeInfo)];
  bool gCMauiScrollbarTypeInfoConstructed = false;

  [[nodiscard]] CMauiScrollbarTypeInfo& AcquireCMauiScrollbarTypeInfo()
  {
    if (!gCMauiScrollbarTypeInfoConstructed) {
      new (gCMauiScrollbarTypeInfoStorage) CMauiScrollbarTypeInfo();
      gCMauiScrollbarTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiScrollbarTypeInfo*>(gCMauiScrollbarTypeInfoStorage);
  }

  void cleanup_CMauiScrollbarTypeInfo()
  {
    if (!gCMauiScrollbarTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiScrollbarTypeInfo*>(gCMauiScrollbarTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiScrollbarTypeInfoBootstrap
  {
    CMauiScrollbarTypeInfoBootstrap() { moho::register_CMauiScrollbarTypeInfoStartup(); }
  };
  CMauiScrollbarTypeInfoBootstrap gCMauiScrollbarTypeInfoBootstrap;

  /**
   * Address: 0x007A2700 (FUN_007A2700, Moho::CMauiScrollbarTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiScrollbar's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiScrollbar standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiScrollbar fails its upcast.
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
 * Address: 0x007A0360 (FUN_007A0360, Moho::CMauiScrollbarTypeInfo::CMauiScrollbarTypeInfo)
 */
CMauiScrollbarTypeInfo::CMauiScrollbarTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiScrollbar), this);
}

/**
 * Address: 0x007A0400 (FUN_007A0400, Moho::CMauiScrollbarTypeInfo::dtr)
 */
CMauiScrollbarTypeInfo::~CMauiScrollbarTypeInfo() = default;

/**
 * Address: 0x007A03F0 (FUN_007A03F0, Moho::CMauiScrollbarTypeInfo::GetName)
 */
const char* CMauiScrollbarTypeInfo::GetName() const
{
  return "CMauiScrollbar";
}

/**
 * Address: 0x007A03C0 (FUN_007A03C0, Moho::CMauiScrollbarTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiScrollbarTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 344 (0x158 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiScrollbarTypeInfo::Init()
{
  size_ = 0x158;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiScrollbarTypeInfoStartup()
{
  (void)AcquireCMauiScrollbarTypeInfo();
  (void)std::atexit(&cleanup_CMauiScrollbarTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiScrollbarTypeInfoStartup_7a0360, moho::register_CMauiScrollbarTypeInfoStartup)
