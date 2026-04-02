#include "moho/entity/PropTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/entity/Prop.h"

namespace
{
  moho::SPropPriorityInfoTypeInfo gSPropPriorityInfoTypeInfo;
  moho::PropTypeInfo gPropTypeInfo;

  template <typename TTypeInfo>
  void ResetTypeInfoVectors(TTypeInfo& typeInfo) noexcept
  {
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006F9AA0 (FUN_006F9AA0, sub_6F9AA0)
   */
  SPropPriorityInfoTypeInfo::SPropPriorityInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPropPriorityInfo), this);
  }

  /**
   * Address: 0x006F9B30 (FUN_006F9B30, Moho::SPropPriorityInfoTypeInfo::dtr)
   */
  SPropPriorityInfoTypeInfo::~SPropPriorityInfoTypeInfo() = default;

  /**
   * Address: 0x006F9B20 (FUN_006F9B20, Moho::SPropPriorityInfoTypeInfo::GetName)
   */
  const char* SPropPriorityInfoTypeInfo::GetName() const
  {
    return "SPropPriorityInfo";
  }

  /**
   * Address: 0x006F9B00 (FUN_006F9B00, Moho::SPropPriorityInfoTypeInfo::Init)
   */
  void SPropPriorityInfoTypeInfo::Init()
  {
    size_ = sizeof(SPropPriorityInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006FA380 (FUN_006FA380, Moho::PropTypeInfo::PropTypeInfo)
   */
  PropTypeInfo::PropTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Prop), this);
  }

  /**
   * Address: 0x006FA420 (FUN_006FA420, Moho::PropTypeInfo::dtr)
   */
  PropTypeInfo::~PropTypeInfo() = default;

  /**
   * Address: 0x006FA410 (FUN_006FA410, Moho::PropTypeInfo::GetName)
   */
  const char* PropTypeInfo::GetName() const
  {
    return "Prop";
  }

  /**
   * Address: 0x006FA3E0 (FUN_006FA3E0, Moho::PropTypeInfo::Init)
   */
  void PropTypeInfo::Init()
  {
    size_ = sizeof(Prop);
    AddBase_Entity(this);
    gpg::RType::Init();
    Version(1);
    Finish();
  }

  /**
   * Address: 0x006FAD70 (FUN_006FAD70, Moho::PropTypeInfo::AddBase_Entity)
   */
  void PropTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(Entity));

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BFF0E0 (FUN_00BFF0E0, sub_BFF0E0)
   */
  void cleanup_SPropPriorityInfoTypeInfo()
  {
    ResetTypeInfoVectors(gSPropPriorityInfoTypeInfo);
  }

  /**
   * Address: 0x00BD9820 (FUN_00BD9820, sub_BD9820)
   */
  void register_SPropPriorityInfoTypeInfo()
  {
    (void)gSPropPriorityInfoTypeInfo;
    (void)std::atexit(&cleanup_SPropPriorityInfoTypeInfo);
  }

  /**
   * Address: 0x00BFF170 (FUN_00BFF170, sub_BFF170)
   */
  void cleanup_PropTypeInfo()
  {
    ResetTypeInfoVectors(gPropTypeInfo);
  }

  /**
   * Address: 0x00BD9880 (FUN_00BD9880, register_PropTypeInfo)
   */
  void register_PropTypeInfo()
  {
    (void)gPropTypeInfo;
    (void)std::atexit(&cleanup_PropTypeInfo);
  }
} // namespace moho

namespace
{
  struct PropTypeInfoBootstrap
  {
    PropTypeInfoBootstrap()
    {
      moho::register_SPropPriorityInfoTypeInfo();
      moho::register_PropTypeInfo();
    }
  };

  PropTypeInfoBootstrap gPropTypeInfoBootstrap;
} // namespace
