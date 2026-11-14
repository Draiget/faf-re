#include "moho/resource/ISimResourcesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/ISimResources.h"
#include "moho/resource/ResourceReflectionHelpers.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  [[nodiscard]] moho::ISimResourcesTypeInfo& AcquireISimResourcesTypeInfo()
  {
    static moho::ISimResourcesTypeInfo sInstance;
    return sInstance;
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
    static_assert(sizeof(moho::ISimResources) == 0x04, "moho::ISimResources is 0x04 bytes on x86");
    size_ = sizeof(moho::ISimResources);
    gpg::RType::Init();
    AddBase_IResources(this);
    Finish();
  }

  /**
   * Address: 0x005488F0 (FUN_005488F0, Moho::ISimResourcesTypeInfo::AddBase_IResources)
   */
  void ISimResourcesTypeInfo::AddBase_IResources(
    gpg::RType* const typeInfo
  )
  {
    moho::resource_reflection::AddBase(typeInfo, moho::resource_reflection::ResolveIResourcesType());
  }

  /**
   * Address: 0x00BC97D0 (FUN_00BC97D0, register_ISimResourcesTypeInfo)
   */
  void register_ISimResourcesTypeInfo()
  {
    (void)AcquireISimResourcesTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  register_ISimResourcesTypeInfo_415ee2,
  moho::register_ISimResourcesTypeInfo
)
