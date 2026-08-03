#include "moho/ui/CMauiEditTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiEditTypeInfo) unsigned char gCMauiEditTypeInfoStorage[sizeof(CMauiEditTypeInfo)];
  bool gCMauiEditTypeInfoConstructed = false;

  [[nodiscard]] CMauiEditTypeInfo& AcquireCMauiEditTypeInfo()
  {
    if (!gCMauiEditTypeInfoConstructed) {
      new (gCMauiEditTypeInfoStorage) CMauiEditTypeInfo();
      gCMauiEditTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiEditTypeInfo*>(gCMauiEditTypeInfoStorage);
  }

  void cleanup_CMauiEditTypeInfo()
  {
    if (!gCMauiEditTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiEditTypeInfo*>(gCMauiEditTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiEditTypeInfoBootstrap
  {
    CMauiEditTypeInfoBootstrap() { moho::register_CMauiEditTypeInfoStartup(); }
  };
  CMauiEditTypeInfoBootstrap gCMauiEditTypeInfoBootstrap;

  /**
   * Address: 0x00794EC0 (FUN_00794EC0, Moho::CMauiEditTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiEdit's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiEdit standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiEdit fails its upcast.
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
 * Address: 0x0078EE90 (FUN_0078EE90, Moho::CMauiEditTypeInfo::CMauiEditTypeInfo)
 */
CMauiEditTypeInfo::CMauiEditTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiEdit), this);
}

/**
 * Address: 0x0078EF30 (FUN_0078EF30, Moho::CMauiEditTypeInfo::dtr)
 */
CMauiEditTypeInfo::~CMauiEditTypeInfo() = default;

/**
 * Address: 0x0078EF20 (FUN_0078EF20, Moho::CMauiEditTypeInfo::GetName)
 */
const char* CMauiEditTypeInfo::GetName() const
{
  return "CMauiEdit";
}

/**
 * Address: 0x0078EEF0 (FUN_0078EEF0, Moho::CMauiEditTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiEditTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 408 (0x198 - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiEditTypeInfo::Init()
{
  size_ = 0x198;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiEditTypeInfoStartup()
{
  (void)AcquireCMauiEditTypeInfo();
  (void)std::atexit(&cleanup_CMauiEditTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiEditTypeInfoStartup_78ee90, moho::register_CMauiEditTypeInfoStartup)
