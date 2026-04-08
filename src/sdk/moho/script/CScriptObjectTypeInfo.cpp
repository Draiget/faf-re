#include "moho/script/CScriptObjectTypeInfo.h"

#include <typeinfo>

#include "moho/script/CScriptObject.h"

namespace
{
  [[nodiscard]] moho::CScriptObjectTypeInfo& ScriptObjectTypeInfoSingleton()
  {
    static moho::CScriptObjectTypeInfo sTypeInfo{};
    return sTypeInfo;
  }

  /**
   * Address: 0x004C8150 (FUN_004C8150, Moho::CScriptObjectTypeInfo::AddBase_RObject)
   *
   * What it does:
   * Adds gpg::RObject as a reflected base with zero subobject offset.
   */
  void AddBase_RObject(gpg::RType* const typeInfo)
  {
    static gpg::RType* rObjectType = nullptr;
    if (rObjectType == nullptr) {
      rObjectType = gpg::LookupRType(typeid(gpg::RObject));
    }

    gpg::RField baseField{};
    baseField.mName = rObjectType->GetName();
    baseField.mType = rObjectType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  struct CScriptObjectTypeInfoBootstrap
  {
    CScriptObjectTypeInfoBootstrap()
    {
      moho::register_CScriptObjectTypeInfo();
    }
  };

  CScriptObjectTypeInfoBootstrap gCScriptObjectTypeInfoBootstrap{};
} // namespace

namespace moho
{
  /**
   * Address: 0x004C6E20 (FUN_004C6E20, Moho::CScriptObjectTypeInfo::CScriptObjectTypeInfo)
   */
  CScriptObjectTypeInfo::CScriptObjectTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CScriptObject), this);
  }

  /**
   * Address: 0x004C6EC0 (FUN_004C6EC0, Moho::CScriptObjectTypeInfo::dtr)
   */
  CScriptObjectTypeInfo::~CScriptObjectTypeInfo() = default;

  /**
   * Address: 0x004C6EB0 (FUN_004C6EB0, Moho::CScriptObjectTypeInfo::GetName)
   *
   * IDA signature:
   * const char *Moho::CScriptObjectTypeInfo::GetName();
   */
  const char* CScriptObjectTypeInfo::GetName() const
  {
    return "CScriptObject";
  }

  /**
   * Address: 0x004C6E80 (FUN_004C6E80, Moho::CScriptObjectTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CScriptObjectTypeInfo::Init(gpg::RType *this);
   */
  void CScriptObjectTypeInfo::Init()
  {
    size_ = sizeof(CScriptObject);
    AddBase_RObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC6060 (FUN_00BC6060, register_CScriptObjectTypeInfo)
   */
  void register_CScriptObjectTypeInfo()
  {
    (void)ScriptObjectTypeInfoSingleton();
  }
} // namespace moho
