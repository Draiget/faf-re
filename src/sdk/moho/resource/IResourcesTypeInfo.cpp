#include "moho/resource/IResourcesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/IResources.h"

namespace
{
  alignas(moho::IResourcesTypeInfo) unsigned char gIResourcesTypeInfoStorage[sizeof(moho::IResourcesTypeInfo)];
  bool gIResourcesTypeInfoConstructed = false;

  [[nodiscard]] moho::IResourcesTypeInfo& AcquireIResourcesTypeInfo()
  {
    if (!gIResourcesTypeInfoConstructed) {
      new (gIResourcesTypeInfoStorage) moho::IResourcesTypeInfo();
      gIResourcesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::IResourcesTypeInfo*>(gIResourcesTypeInfoStorage);
  }

  void cleanup_IResourcesTypeInfo()
  {
    if (!gIResourcesTypeInfoConstructed) {
      return;
    }

    AcquireIResourcesTypeInfo().~IResourcesTypeInfo();
    gIResourcesTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00546E20 (FUN_00546E20)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `IResourcesTypeInfo`.
   */
  [[maybe_unused]] void cleanup_IResourcesTypeInfoRTypeBase(moho::IResourcesTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct IResourcesTypeInfoStartup
  {
    IResourcesTypeInfoStartup()
    {
      moho::register_IResourcesTypeInfo();
    }
  };

  [[maybe_unused]] IResourcesTypeInfoStartup gIResourcesTypeInfoStartup;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546D30 (FUN_00546D30, Moho::IResourcesTypeInfo::IResourcesTypeInfo)
   */
  IResourcesTypeInfo::IResourcesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(IResources), this);
  }

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

  /**
   * Address: 0x00BC97B0 (FUN_00BC97B0, register_IResourcesTypeInfo)
   */
  void register_IResourcesTypeInfo()
  {
    (void)AcquireIResourcesTypeInfo();
    (void)std::atexit(&cleanup_IResourcesTypeInfo);
  }
} // namespace moho
