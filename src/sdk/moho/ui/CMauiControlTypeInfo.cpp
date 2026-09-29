#include "moho/ui/CMauiControlTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C02BC0 (FUN_00C02BC0, atexit destructor of the CMauiControlTypeInfo object)
   */
  [[nodiscard]] CMauiControlTypeInfo& AcquireCMauiControlTypeInfo()
  {
    static CMauiControlTypeInfo sInstance;
    return sInstance;
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
  static_assert(sizeof(moho::CMauiControl) == 0x11C, "moho::CMauiControl is 0x11C bytes on x86");
  size_ = sizeof(moho::CMauiControl);
  AddCScriptObjectBase(*this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDDD60 (FUN_00BDDD60, register_CMauiControlTypeInfoStartup)
 *
 * What it does:
 * Constructs the `CMauiControl` type-info object.
 */
void moho::register_CMauiControlTypeInfoStartup()
{
  (void)AcquireCMauiControlTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiControlTypeInfoStartup_6e4932, moho::register_CMauiControlTypeInfoStartup)
