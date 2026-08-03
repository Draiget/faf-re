#include "moho/ui/CMauiCursorTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/script/CScriptObject.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CMauiCursorTypeInfo) unsigned char gCMauiCursorTypeInfoStorage[sizeof(CMauiCursorTypeInfo)];
  bool gCMauiCursorTypeInfoConstructed = false;

  [[nodiscard]] CMauiCursorTypeInfo& AcquireCMauiCursorTypeInfo()
  {
    if (!gCMauiCursorTypeInfoConstructed) {
      new (gCMauiCursorTypeInfoStorage) CMauiCursorTypeInfo();
      gCMauiCursorTypeInfoConstructed = true;
    }
    return *reinterpret_cast<CMauiCursorTypeInfo*>(gCMauiCursorTypeInfoStorage);
  }

  void cleanup_CMauiCursorTypeInfo()
  {
    if (!gCMauiCursorTypeInfoConstructed) {
      return;
    }
    auto& typeInfo = *reinterpret_cast<CMauiCursorTypeInfo*>(gCMauiCursorTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CMauiCursorTypeInfoBootstrap
  {
    CMauiCursorTypeInfoBootstrap() { moho::register_CMauiCursorTypeInfoStartup(); }
  };
  CMauiCursorTypeInfoBootstrap gCMauiCursorTypeInfoBootstrap;

  /**
   * Address: 0x0078D970 (FUN_0078D970, sub_78D970)
   *
   * What it does:
   * Declares CScriptObject as CMauiCursor's reflected base, at offset 0,
   * resolving it through the cached `CScriptObject::sType` slot exactly as the
   * binary does.
   *
   * Without a descriptor for CMauiCursor at all, `LookupRType` throws for the
   * type, and the throw escapes `ResolveCursorFromLuaObjectOrError` before it
   * can reach any of its own `luaL_error` branches - which killed
   * `Cursor.__init`, then `UIUtil.CreateCursor()`, so `SetCursor` never ran and
   * the UI manager kept a null cursor.
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
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }
} // namespace

/**
 * Address: 0x0078CA00 (FUN_0078CA00, Moho::CMauiCursorTypeInfo::CMauiCursorTypeInfo)
 */
CMauiCursorTypeInfo::CMauiCursorTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CMauiCursor), this);
}

/**
 * Address: 0x0078CAA0 (FUN_0078CAA0, Moho::CMauiCursorTypeInfo::dtr)
 */
CMauiCursorTypeInfo::~CMauiCursorTypeInfo() = default;

/**
 * Address: 0x0078CA90 (FUN_0078CA90, Moho::CMauiCursorTypeInfo::GetName)
 */
const char* CMauiCursorTypeInfo::GetName() const
{
  return "CMauiCursor";
}

/**
 * Address: 0x0078CA60 (FUN_0078CA60, Moho::CMauiCursorTypeInfo::Init)
 *
 * IDA signature:
 * int __thiscall Moho::CMauiCursorTypeInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Sets the reflected size to 88 (0x58 - the size the binary hands to
 * `operator new` at the `_c_CreateCursor` site), declares the CScriptObject
 * base, then runs the base initialiser and finishes the descriptor.
 */
void CMauiCursorTypeInfo::Init()
{
  size_ = 0x58;
  AddCScriptObjectBase(*this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CMauiCursorTypeInfoStartup()
{
  (void)AcquireCMauiCursorTypeInfo();
  (void)std::atexit(&cleanup_CMauiCursorTypeInfo);
}

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CMauiCursorTypeInfoStartup_078ca00, moho::register_CMauiCursorTypeInfoStartup)
