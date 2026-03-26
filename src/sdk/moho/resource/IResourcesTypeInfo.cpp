#include "moho/resource/IResourcesTypeInfo.h"

#include "moho/resource/IResources.h"

namespace moho
{
  /**
   * Address: 0x00546DC0 (FUN_00546DC0, Moho::IResourcesTypeInfo::dtr)
   */
  IResourcesTypeInfo::~IResourcesTypeInfo() = default;

  /**
   * Address: 0x00546DB0 (FUN_00546DB0, Moho::IResourcesTypeInfo::GetName)
   */
  const char* IResourcesTypeInfo::GetName() const
  {
    return "IResources";
  }

  /**
   * Address: 0x00546D90 (FUN_00546D90, Moho::IResourcesTypeInfo::Init)
   */
  void IResourcesTypeInfo::Init()
  {
    size_ = sizeof(IResources);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
