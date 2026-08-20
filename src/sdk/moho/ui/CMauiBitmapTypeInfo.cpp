#include "moho/ui/CMauiBitmapTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiBitmapTypeInfo) unsigned char gCMauiBitmapTypeInfoStorage[sizeof(CMauiBitmapTypeInfo)];
  bool gCMauiBitmapTypeInfoConstructed = false;

  [[nodiscard]] CMauiBitmapTypeInfo& AcquireCMauiBitmapTypeInfo()
  {
    if (!gCMauiBitmapTypeInfoConstructed) {
      new (gCMauiBitmapTypeInfoStorage) CMauiBitmapTypeInfo();
      gCMauiBitmapTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiBitmapTypeInfo*>(gCMauiBitmapTypeInfoStorage);
  }

  void cleanup_CMauiBitmapTypeInfo()
  {
    if (!gCMauiBitmapTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiBitmapTypeInfo*>(gCMauiBitmapTypeInfoStorage);
    typeInfo.~CMauiBitmapTypeInfo();
    gCMauiBitmapTypeInfoConstructed = false;
  }

  struct CMauiBitmapTypeInfoBootstrap
  {
    CMauiBitmapTypeInfoBootstrap() { moho::register_CMauiBitmapTypeInfoStartup(); }
  };
  CMauiBitmapTypeInfoBootstrap gCMauiBitmapTypeInfoBootstrap;

  /**
   * Address: 0x00783B00 (FUN_00783B00, Moho::CMauiBitmapTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CMauiBitmap's reflected base, at offset 0, resolving it
   * through the cached `CMauiControl::sType` slot exactly as the binary does.
   *
   * Without the base edge the reflection graph has CMauiBitmap standing alone, so
   * `RType::IsDerivedFrom` cannot walk from it to CScriptObject and every
   * reflected reference built from a CMauiBitmap fails its upcast.
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
 * Address: 0x0077F800 (FUN_0077F800, Moho::CMauiBitmapTypeInfo::CMauiBitmapTypeInfo)
 */
CMauiBitmapTypeInfo::CMauiBitmapTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiBitmap), this);
}

/**
 * Address: 0x0077F8A0 (FUN_0077F8A0, Moho::CMauiBitmapTypeInfo::dtr)
 */
CMauiBitmapTypeInfo::~CMauiBitmapTypeInfo() = default;

/**
 * Address: 0x0077F890 (FUN_0077F890, Moho::CMauiBitmapTypeInfo::GetName)
 */
const char* CMauiBitmapTypeInfo::GetName() const
{
  return "CMauiBitmap";
}

/**
 * Address: 0x0077F860 (FUN_0077F860, Moho::CMauiBitmapTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiBitmapTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 396 (0x18C - the size the binary hands to
 * `operator new` at the matching construction site), declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiBitmapTypeInfo::Init()
{
  size_ = 0x18C;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiBitmapTypeInfoStartup()
{
  if (gCMauiBitmapTypeInfoConstructed) {
    return;
  }

  (void)AcquireCMauiBitmapTypeInfo();
  (void)std::atexit(&cleanup_CMauiBitmapTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(CMauiBitmapTypeInfoStartupPreregister, moho::register_CMauiBitmapTypeInfoStartup)
