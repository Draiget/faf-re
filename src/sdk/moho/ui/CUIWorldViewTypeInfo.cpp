#include "moho/ui/CUIWorldViewTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/ui/UiRuntimeTypes.h"

using namespace moho;

namespace
{
  alignas(CUIWorldViewTypeInfo) unsigned char gCUIWorldViewTypeInfoStorage[sizeof(CUIWorldViewTypeInfo)];
  bool gCUIWorldViewTypeInfoConstructed = false;

  [[nodiscard]] CUIWorldViewTypeInfo& AcquireCUIWorldViewTypeInfo()
  {
    if (!gCUIWorldViewTypeInfoConstructed) {
      new (gCUIWorldViewTypeInfoStorage) CUIWorldViewTypeInfo();
      gCUIWorldViewTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CUIWorldViewTypeInfo*>(gCUIWorldViewTypeInfoStorage);
  }

  /**
   * Address: 0x00C07990 (atexit lane registered by FUN_00BE6920)
   */
  void cleanup_CUIWorldViewTypeInfo()
  {
    if (!gCUIWorldViewTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CUIWorldViewTypeInfo*>(gCUIWorldViewTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CUIWorldViewTypeInfoBootstrap
  {
    CUIWorldViewTypeInfoBootstrap() { moho::register_CUIWorldViewTypeInfoStartup(); }
  };
  CUIWorldViewTypeInfoBootstrap gCUIWorldViewTypeInfoBootstrap;

  /**
   * Address: 0x00873950 (FUN_00873950, Moho::CUIWorldViewTypeInfo::AddBase_CMauiControl)
   *
   * What it does:
   * Declares CMauiControl as CUIWorldView's reflected base at offset 0,
   * resolving it through the cached `CMauiControl::sType` slot exactly as the
   * binary does. The lineage is what lets `REF_UpcastPtr` walk a control
   * reference down to this class.
   */
  void AddCMauiControlBase(gpg::RType& typeInfo)
  {
    gpg::RType* baseType = moho::CMauiControl::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::CMauiControl));
      moho::CMauiControl::sType = baseType;
    }

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
 * Address: 0x0086DCA0 (FUN_0086DCA0, sub_86DCA0)
 *
 * What it does:
 * Runs the `gpg::RType` base constructor over the static descriptor storage,
 * installs the `CUIWorldViewTypeInfo` vtable, and pre-registers the descriptor
 * against `CUIWorldView`'s RTTI type descriptor.
 */
CUIWorldViewTypeInfo::CUIWorldViewTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CUIWorldView), this);
}

/**
 * Address: 0x0086DD40 (FUN_0086DD40, Moho::CUIWorldViewTypeInfo::dtr)
 */
CUIWorldViewTypeInfo::~CUIWorldViewTypeInfo() = default;

/**
 * Address: 0x0086DD30 (FUN_0086DD30, Moho::CUIWorldViewTypeInfo::GetName)
 */
const char* CUIWorldViewTypeInfo::GetName() const
{
  return "CUIWorldView";
}

/**
 * Address: 0x0086DD00 (FUN_0086DD00, Moho::CUIWorldViewTypeInfo::Init)
 *
 * What it does:
 * Sets the reflected size to 0x2A8 - the size the binary hands to
 * `operator new` at the `CUIWorldView:__init` site - declares the CMauiControl
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CUIWorldViewTypeInfo::Init()
{
  size_ = 0x2A8;
  AddCMauiControlBase(*this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BE6920 (FUN_00BE6920, sub_BE6920)
 *
 * What it does:
 * Constructs the static descriptor and registers its teardown, exactly as the
 * binary's static-initialiser entry does.
 */
void moho::register_CUIWorldViewTypeInfoStartup()
{
  (void)AcquireCUIWorldViewTypeInfo();
  (void)std::atexit(&cleanup_CUIWorldViewTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUIWorldViewTypeInfoStartup_086dca0, moho::register_CUIWorldViewTypeInfoStartup)
