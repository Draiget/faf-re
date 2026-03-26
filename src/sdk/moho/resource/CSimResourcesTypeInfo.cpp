#include "moho/resource/CSimResourcesTypeInfo.h"

#include <new>

#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  [[nodiscard]] gpg::RRef MakeCSimResourcesRef(moho::CSimResources* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::resource_reflection::ResolveCSimResourcesType();
    return out;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00546AD0 (FUN_00546AD0, Moho::CSimResourcesTypeInfo::dtr)
   */
  CSimResourcesTypeInfo::~CSimResourcesTypeInfo() = default;

  /**
   * Address: 0x00546AC0 (FUN_00546AC0, Moho::CSimResourcesTypeInfo::GetName)
   */
  const char* CSimResourcesTypeInfo::GetName() const
  {
    return "CSimResources";
  }

  /**
   * Address: 0x00546A80 (FUN_00546A80, Moho::CSimResourcesTypeInfo::Init)
   */
  void CSimResourcesTypeInfo::Init()
  {
    size_ = sizeof(CSimResources);
    newRefFunc_ = &CSimResourcesTypeInfo::NewRef;
    ctorRefFunc_ = &CSimResourcesTypeInfo::CtrRef;
    deleteFunc_ = &CSimResourcesTypeInfo::Delete;
    dtrFunc_ = &CSimResourcesTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_ISimResources(this);
    Finish();
  }

  /**
   * Address: 0x005487E0 (FUN_005487E0, Moho::CSimResourcesTypeInfo::AddBase_ISimResources)
   */
  void CSimResourcesTypeInfo::AddBase_ISimResources(gpg::RType* const typeInfo)
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveISimResourcesType());
  }

  /**
   * Address: 0x005484A0 (FUN_005484A0, Moho::CSimResourcesTypeInfo::NewRef)
   */
  gpg::RRef CSimResourcesTypeInfo::NewRef()
  {
    CSimResources* const object = new (std::nothrow) CSimResources();
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548530 (FUN_00548530, Moho::CSimResourcesTypeInfo::CtrRef)
   */
  gpg::RRef CSimResourcesTypeInfo::CtrRef(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      new (object) CSimResources();
    }
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548510 (FUN_00548510, Moho::CSimResourcesTypeInfo::Delete)
   */
  void CSimResourcesTypeInfo::Delete(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      delete object;
    }
  }

  /**
   * Address: 0x005485A0 (FUN_005485A0, Moho::CSimResourcesTypeInfo::Destruct)
   */
  void CSimResourcesTypeInfo::Destruct(void* const objectPtr)
  {
    auto* const object = reinterpret_cast<CSimResources*>(objectPtr);
    object->~CSimResources();
  }
} // namespace moho
