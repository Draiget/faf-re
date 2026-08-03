#include "moho/ui/CMauiGroupTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiGroupTypeInfo) unsigned char gCMauiGroupTypeInfoStorage[sizeof(CMauiGroupTypeInfo)];
  bool gCMauiGroupTypeInfoConstructed = false;

  [[nodiscard]] CMauiGroupTypeInfo& AcquireCMauiGroupTypeInfo()
  {
    if (!gCMauiGroupTypeInfoConstructed) {
      new (gCMauiGroupTypeInfoStorage) CMauiGroupTypeInfo();
      gCMauiGroupTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiGroupTypeInfo*>(gCMauiGroupTypeInfoStorage);
  }

  void cleanup_CMauiGroupTypeInfo()
  {
    if (!gCMauiGroupTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiGroupTypeInfo*>(gCMauiGroupTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiGroupTypeInfoBootstrap
  {
    CMauiGroupTypeInfoBootstrap() { moho::register_CMauiGroupTypeInfoStartup(); }
  };
  CMauiGroupTypeInfoBootstrap gCMauiGroupTypeInfoBootstrap;

  /**
   * Address: 0x00797540 (FUN_00797540, Moho::CMauiGroupTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiGroup's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiGroup standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiGroup fails its upcast.
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
 * Address: 0x00797130 (FUN_00797130, Moho::CMauiGroupTypeInfo::CMauiGroupTypeInfo)
 */
CMauiGroupTypeInfo::CMauiGroupTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiGroup), this);
}

/**
 * Address: 0x007971D0 (FUN_007971D0, Moho::CMauiGroupTypeInfo::dtr)
 */
CMauiGroupTypeInfo::~CMauiGroupTypeInfo() = default;

/**
 * Address: 0x007971C0 (FUN_007971C0, Moho::CMauiGroupTypeInfo::GetName)
 */
const char* CMauiGroupTypeInfo::GetName() const
{
  return "CMauiGroup";
}

/**
 * Address: 0x00797190 (FUN_00797190, Moho::CMauiGroupTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiGroupTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 284 (0x11C - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiGroupTypeInfo::Init()
{
  size_ = 0x11C;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiGroupTypeInfoStartup()
{
  (void)AcquireCMauiGroupTypeInfo();
  (void)std::atexit(&cleanup_CMauiGroupTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiGroupTypeInfoStartup_797130, moho::register_CMauiGroupTypeInfoStartup)
