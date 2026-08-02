#include "moho/ui/CMauiControlTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiControlTypeInfo) unsigned char gCMauiControlTypeInfoStorage[sizeof(CMauiControlTypeInfo)];
  bool gCMauiControlTypeInfoConstructed = false;

  [[nodiscard]] CMauiControlTypeInfo& AcquireCMauiControlTypeInfo()
  {
    if (!gCMauiControlTypeInfoConstructed) {
      new (gCMauiControlTypeInfoStorage) CMauiControlTypeInfo();
      gCMauiControlTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiControlTypeInfo*>(gCMauiControlTypeInfoStorage);
  }

  void cleanup_CMauiControlTypeInfo()
  {
    if (!gCMauiControlTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<CMauiControlTypeInfo*>(gCMauiControlTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiControlTypeInfoBootstrap
  {
    CMauiControlTypeInfoBootstrap() { moho::register_CMauiControlTypeInfoStartup(); }
  };
  CMauiControlTypeInfoBootstrap gCMauiControlTypeInfoBootstrap;
  /**
   * Address: 0x0078A680 (FUN_0078A680, sub_78A680)
   *
   * What it does:
   * Declares CScriptObject as CMauiControl's reflected base, at offset 0.
   *
   * IDA gives this one no AddBase_ symbol - CMauiControlTypeInfo::Init just
   * calls sub_78A680 - so a search for `<TypeInfo>::AddBase_*` does not find
   * it. It is the link that lets IsDerivedFrom walk CMauiFrame ->
   * CMauiControl -> CScriptObject; without it every Maui control handed to
   * gpg::RRef_CScriptObject trips the binary's "isDer" assertion.
   */
  void AddCScriptObjectBase(gpg::RType& typeInfo)
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CScriptObject));
    }

    gpg::RField baseField{};
    baseField.mName = cached->GetName();
    baseField.mType = cached;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x00786660 (Moho::CMauiControlTypeInfo::CMauiControlTypeInfo)
 */
CMauiControlTypeInfo::CMauiControlTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiControl), this);
}

/**
 * Address: 0x00786700
 */
CMauiControlTypeInfo::~CMauiControlTypeInfo() = default;

/**
 * Address: 0x007866F0
 */
const char* CMauiControlTypeInfo::GetName() const
{
  return "CMauiControl";
}

/**
 * Address: 0x007866C0
 */
void CMauiControlTypeInfo::Init()
{
  size_ = 0x11C;
  AddCScriptObjectBase(*this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDDD60
 */
void moho::register_CMauiControlTypeInfoStartup()
{
  (void)AcquireCMauiControlTypeInfo();
  (void)std::atexit(&cleanup_CMauiControlTypeInfo);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiControlTypeInfoStartup_6e4932, moho::register_CMauiControlTypeInfoStartup)
