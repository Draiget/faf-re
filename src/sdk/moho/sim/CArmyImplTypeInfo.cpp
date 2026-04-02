#include "moho/sim/CArmyImplTypeInfo.h"

#include <new>
#include <type_traits>
#include <typeinfo>

#include "moho/sim/CArmyImpl.h"
#include "moho/sim/SimArmy.h"

namespace
{
  [[nodiscard]] gpg::RRef MakeCArmyImplRef(moho::CArmyImpl* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CArmyImpl::StaticGetClass();
    return out;
  }

  moho::CArmyImplTypeInfo gCArmyImplTypeInfo;
} // namespace

namespace moho
{
  /**
   * Address: 0x006FE3D0 (FUN_006FE3D0, Moho::CArmyImplTypeInfo::CArmyImplTypeInfo)
   *
   * IDA signature:
   * gpg::RType *Moho::CArmyImplTypeInfo::CArmyImplTypeInfo();
   */
  CArmyImplTypeInfo::CArmyImplTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CArmyImpl), this);
  }

  /**
   * Address: 0x006FE480 (FUN_006FE480, Moho::CArmyImplTypeInfo::dtr)
   */
  CArmyImplTypeInfo::~CArmyImplTypeInfo() = default;

  /**
   * Address: 0x006FE470 (FUN_006FE470, Moho::CArmyImplTypeInfo::GetName)
   */
  const char* CArmyImplTypeInfo::GetName() const
  {
    return "CArmyImpl";
  }

  /**
   * Address: 0x006FE430 (FUN_006FE430, Moho::CArmyImplTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall register_CArmyImplRType(gpg::RType *this);
   */
  void CArmyImplTypeInfo::Init()
  {
    size_ = sizeof(CArmyImpl);
    newRefFunc_ = &CArmyImplTypeInfo::NewRef;
    ctorRefFunc_ = &CArmyImplTypeInfo::CtrRef;
    deleteFunc_ = &CArmyImplTypeInfo::Delete;
    dtrFunc_ = &CArmyImplTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_SimArmy(this);
    Finish();
  }

  /**
   * Address: 0x007034D0 (FUN_007034D0, sub_7034D0)
   */
  gpg::RRef CArmyImplTypeInfo::NewRef()
  {
    return MakeCArmyImplRef(nullptr);
  }

  /**
   * Address: 0x00703570 (FUN_00703570, sub_703570)
   */
  gpg::RRef CArmyImplTypeInfo::CtrRef(void* const objectStorage)
  {
    return MakeCArmyImplRef(static_cast<CArmyImpl*>(objectStorage));
  }

  /**
   * Address: 0x00703550 (FUN_00703550, sub_703550)
   */
  void CArmyImplTypeInfo::Delete(void* const objectStorage)
  {
    (void)objectStorage;
  }

  /**
   * Address: 0x007035E0 (FUN_007035E0, sub_7035E0)
   */
  void CArmyImplTypeInfo::Destruct(void* const objectStorage)
  {
    (void)objectStorage;
  }

  /**
   * Address: 0x00703F40 (FUN_00703F40, Moho::CArmyImplTypeInfo::AddBase_SimArmy)
   */
  void CArmyImplTypeInfo::AddBase_SimArmy(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = SimArmy::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(SimArmy));
      SimArmy::sType = baseType;
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
   * Address: 0x00BD9C00 (FUN_00BD9C00, register_CArmyImplTypeInfo)
   *
   * What it does:
   * Forces CArmyImpl RTTI preregistration bootstrap.
   */
  void register_CArmyImplTypeInfo()
  {
    (void)gCArmyImplTypeInfo;
  }
} // namespace moho

namespace
{
  struct CArmyImplTypeInfoBootstrap
  {
    CArmyImplTypeInfoBootstrap()
    {
      moho::register_CArmyImplTypeInfo();
    }
  };

  CArmyImplTypeInfoBootstrap gCArmyImplTypeInfoBootstrap;
} // namespace
