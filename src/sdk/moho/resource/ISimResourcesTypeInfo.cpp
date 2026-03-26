#include "moho/resource/ISimResourcesTypeInfo.h"

#include "moho/resource/ResourceReflectionHelpers.h"

namespace moho
{
  /**
   * Address: 0x00546F80 (FUN_00546F80, Moho::ISimResourcesTypeInfo::dtr)
   */
  ISimResourcesTypeInfo::~ISimResourcesTypeInfo() = default;

  /**
   * Address: 0x00546F70 (FUN_00546F70, Moho::ISimResourcesTypeInfo::GetName)
   */
  const char* ISimResourcesTypeInfo::GetName() const
  {
    return "ISimResources";
  }

  /**
   * Address: 0x00546F50 (FUN_00546F50, Moho::ISimResourcesTypeInfo::Init)
   */
  void ISimResourcesTypeInfo::Init()
  {
    size_ = 0x04;
    gpg::RType::Init();
    AddBase_IResources(this);
    Finish();
  }

  /**
   * Address: 0x005488F0 (FUN_005488F0, Moho::ISimResourcesTypeInfo::AddBase_IResources)
   */
  void ISimResourcesTypeInfo::AddBase_IResources(gpg::RType* const typeInfo)
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveIResourcesType());
  }
} // namespace moho
