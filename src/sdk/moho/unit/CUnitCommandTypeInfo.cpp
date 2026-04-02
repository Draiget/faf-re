#include "moho/unit/CUnitCommandTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/script/CScriptObject.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/ECommandEvent.h"

namespace
{
  using TypeInfo = moho::CUnitCommandTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitCommandTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCommandTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCUnitCommandTypeInfo() noexcept
  {
    if (!gCUnitCommandTypeInfoConstructed) {
      new (gCUnitCommandTypeInfoStorage) TypeInfo();
      gCUnitCommandTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCommandTypeInfoStorage);
  }

  /**
   * Address: 0x00BFEB80 (FUN_00BFEB80, ??1CUnitCommandTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Tears down recovered `CUnitCommand` type-info storage at process exit.
   */
  void cleanup_CUnitCommandTypeInfo()
  {
    if (!gCUnitCommandTypeInfoConstructed) {
      return;
    }

    GetCUnitCommandTypeInfo().~CUnitCommandTypeInfo();
    gCUnitCommandTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitCommand::sType = nullptr;

  gpg::RType* CUnitCommand::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CUnitCommand));
    }
    return sType;
  }

  /**
   * Address: 0x006E7E90 (FUN_006E7E90, ??0CUnitCommandTypeInfo@Moho@@QAE@@Z)
   */
  CUnitCommandTypeInfo::CUnitCommandTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCommand), this);
  }

  /**
   * Address: 0x006E7F30 (FUN_006E7F30, Moho::CUnitCommandTypeInfo::dtr)
   */
  CUnitCommandTypeInfo::~CUnitCommandTypeInfo() = default;

  /**
   * Address: 0x006E7F20 (FUN_006E7F20, Moho::CUnitCommandTypeInfo::GetName)
   */
  const char* CUnitCommandTypeInfo::GetName() const
  {
    return "CUnitCommand";
  }

  /**
   * Address: 0x006E7FD0 (FUN_006E7FD0, sub_6E7FD0)
   */
  void CUnitCommandTypeInfo::ApplyLegacyBaseVersionLane(gpg::RType* const typeInfo)
  {
    AddBase_CScriptObject(typeInfo);
    AddBase_Broadcaster_ECommandEvent(typeInfo);
    typeInfo->version_ = 2;
  }

  /**
   * Address: 0x006E7EF0 (FUN_006E7EF0, Moho::CUnitCommandTypeInfo::Init)
   */
  void CUnitCommandTypeInfo::Init()
  {
    size_ = sizeof(CUnitCommand);
    gpg::RType::Init();
    ApplyLegacyBaseVersionLane(this);
    Finish();
  }

  /**
   * Address: 0x006EB600 (FUN_006EB600, Moho::CUnitCommandTypeInfo::AddBase_CScriptObject)
   */
  void CUnitCommandTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CScriptObject::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CScriptObject));
      CScriptObject::sType = baseType;
    }

    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006EB660 (FUN_006EB660, Moho::CUnitCommandTypeInfo::AddBase_Broadcaster_ECommandEvent)
   */
  void CUnitCommandTypeInfo::AddBase_Broadcaster_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = register_Broadcaster_ECommandEvent_RType();
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(BroadcasterEventTag<ECommandEvent>));
    }

    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x34;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD8F30 (FUN_00BD8F30, register_CUnitCommandTypeInfo)
   */
  int register_CUnitCommandTypeInfo()
  {
    (void)GetCUnitCommandTypeInfo();
    return std::atexit(&cleanup_CUnitCommandTypeInfo);
  }
} // namespace moho

namespace
{
  struct CUnitCommandTypeInfoBootstrap
  {
    CUnitCommandTypeInfoBootstrap()
    {
      (void)moho::register_CUnitCommandTypeInfo();
    }
  };

  CUnitCommandTypeInfoBootstrap gCUnitCommandTypeInfoBootstrap;
} // namespace
