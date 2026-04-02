#include "moho/resource/ISimResourcesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/ISimResources.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  alignas(moho::ISimResourcesTypeInfo) unsigned char gISimResourcesTypeInfoStorage[sizeof(moho::ISimResourcesTypeInfo)];
  bool gISimResourcesTypeInfoConstructed = false;

  [[nodiscard]] moho::ISimResourcesTypeInfo& AcquireISimResourcesTypeInfo()
  {
    if (!gISimResourcesTypeInfoConstructed) {
      new (gISimResourcesTypeInfoStorage) moho::ISimResourcesTypeInfo();
      gISimResourcesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::ISimResourcesTypeInfo*>(gISimResourcesTypeInfoStorage);
  }

  void cleanup_ISimResourcesTypeInfo()
  {
    if (!gISimResourcesTypeInfoConstructed) {
      return;
    }

    AcquireISimResourcesTypeInfo().~ISimResourcesTypeInfo();
    gISimResourcesTypeInfoConstructed = false;
  }

  struct ISimResourcesTypeInfoStartup
  {
    ISimResourcesTypeInfoStartup()
    {
      moho::register_ISimResourcesTypeInfo();
    }
  };

  [[maybe_unused]] ISimResourcesTypeInfoStartup gISimResourcesTypeInfoStartup;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546EF0 (FUN_00546EF0, Moho::ISimResourcesTypeInfo::ISimResourcesTypeInfo)
   */
  ISimResourcesTypeInfo::ISimResourcesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(ISimResources), this);
  }

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

  /**
   * Address: 0x00BC97D0 (FUN_00BC97D0, register_ISimResourcesTypeInfo)
   */
  void register_ISimResourcesTypeInfo()
  {
    (void)AcquireISimResourcesTypeInfo();
    (void)std::atexit(&cleanup_ISimResourcesTypeInfo);
  }
} // namespace moho
