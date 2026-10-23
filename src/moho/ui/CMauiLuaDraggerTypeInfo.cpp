#include "moho/ui/CMauiLuaDraggerTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/script/CScriptObject.h"
#include "moho/ui/UiRuntimeTypes.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C02CF0 (FUN_00C02CF0, atexit destructor of the CMauiLuaDraggerTypeInfo object)
   */
  [[nodiscard]] CMauiLuaDraggerTypeInfo& AcquireCMauiLuaDraggerTypeInfo()
  {
    static CMauiLuaDraggerTypeInfo sInstance;
    return sInstance;
  }

  struct CMauiLuaDraggerTypeInfoBootstrap
  {
    CMauiLuaDraggerTypeInfoBootstrap() { moho::register_CMauiLuaDraggerTypeInfoStartup(); }
  };
  CMauiLuaDraggerTypeInfoBootstrap gCMauiLuaDraggerTypeInfoBootstrap;

  /**
   * Address: 0x0078E690 (FUN_0078E690, sub_78E690)
   *
   * What it does:
   * Declares CScriptObject as CMauiLuaDragger's reflected base, at offset 0,
   * resolving it through the cached `CScriptObject::sType` slot exactly as the
   * binary does. The lineage is what lets `REF_UpcastPtr` walk from the
   * `CScriptObject` reference `SCR_MakeScriptObjectRef` builds down to this
   * class.
   */
  void AddCScriptObjectBase(gpg::RType& typeInfo)
  {
    gpg::RType* baseType = moho::CScriptObject::sType;
    if (baseType == nullptr) {
      baseType = gpg::LookupRType(typeid(moho::CScriptObject));
      moho::CScriptObject::sType = baseType;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x0078DC70 (FUN_0078DC70, sub_78DC70)
 *
 * IDA signature:
 * gpg::RType *sub_78DC70();
 *
 * What it does:
 * Runs the `gpg::RType` base constructor over the static descriptor storage,
 * installs the `CMauiLuaDraggerTypeInfo` vtable, and pre-registers the
 * descriptor against `CMauiLuaDragger`'s RTTI type descriptor.
 */
CMauiLuaDraggerTypeInfo::CMauiLuaDraggerTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiLuaDragger), this);
}

/**
 * Address: 0x0078DD10 (FUN_0078DD10, Moho::CMauiLuaDraggerTypeInfo::dtr)
 */
CMauiLuaDraggerTypeInfo::~CMauiLuaDraggerTypeInfo() = default;

/**
 * Address: 0x0078DD00 (FUN_0078DD00, Moho::CMauiLuaDraggerTypeInfo::GetName)
 */
const char* CMauiLuaDraggerTypeInfo::GetName() const
{
  return "CMauiLuaDragger";
}

/**
 * Address: 0x0078DCD0 (FUN_0078DCD0, Moho::CMauiLuaDraggerTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiLuaDraggerTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 60 (0x3C - the size the binary hands to
 * `operator new` at the `InternalCreateDragger` site), declares the
 * CScriptObject base, then runs the base initialiser and finishes the
 * descriptor.
 */
void CMauiLuaDraggerTypeInfo::Init()
{
  static_assert(sizeof(moho::CMauiLuaDragger) == 0x3C, "moho::CMauiLuaDragger is 0x3C bytes on x86");
  size_ = sizeof(moho::CMauiLuaDragger);
  AddCScriptObjectBase(*this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDE120 (FUN_00BDE120, sub_BDE120)
 *
 * What it does:
 * Constructs the static `CMauiLuaDragger` type-info object.
 */
void moho::register_CMauiLuaDraggerTypeInfoStartup()
{
  (void)AcquireCMauiLuaDraggerTypeInfo();
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiLuaDraggerTypeInfoStartup_078dc70, moho::register_CMauiLuaDraggerTypeInfoStartup)
