#include "moho/resource/CSimResourcesTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceReflectionHelpers.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  [[nodiscard]] moho::CSimResourcesTypeInfo& AcquireCSimResourcesTypeInfo()
  {
    static moho::CSimResourcesTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00547820 (FUN_00547820)
   *
   * What it does:
   * Writes one `gpg::RType` callback lane set for `CSimResources`
   * allocate/construct/delete/destruct behavior.
   */
  [[nodiscard]] moho::CSimResourcesTypeInfo* BindCSimResourcesTypeInfoCallbackLanes(
    moho::CSimResourcesTypeInfo* const typeInfo,
    const gpg::RType::new_ref_func_t newRefFunc,
    const gpg::RType::ctor_ref_func_t ctorRefFunc,
    const gpg::RType::delete_func_t deleteFunc,
    const gpg::RType::dtr_func_t dtrFunc
  ) noexcept
  {
    if (typeInfo == nullptr) {
      return nullptr;
    }

    (void)gpg::BindRTypeLifecycleCallbacks(typeInfo, newRefFunc, ctorRefFunc, deleteFunc, dtrFunc);
    return typeInfo;
  }

  [[nodiscard]] gpg::RRef MakeCSimResourcesRef(
    moho::CSimResources* const object
  )
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::resource_reflection::ResolveCSimResourcesType();
    return out;
  }

  struct CSimResourcesTypeInfoStartup
  {
    CSimResourcesTypeInfoStartup()
    {
      moho::register_CSimResourcesTypeInfo();
    }
  };

  [[maybe_unused]] CSimResourcesTypeInfoStartup gCSimResourcesTypeInfoStartup;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546A20 (FUN_00546A20, Moho::CSimResourcesTypeInfo::CSimResourcesTypeInfo)
   */
  CSimResourcesTypeInfo::CSimResourcesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CSimResources), this);
  }

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
    (void)BindCSimResourcesTypeInfoCallbackLanes(
      this,
      &CSimResourcesTypeInfo::NewRef,
      &CSimResourcesTypeInfo::CtrRef,
      &CSimResourcesTypeInfo::Delete,
      &CSimResourcesTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_ISimResources(this);
    Finish();
  }

  /**
   * Address: 0x005487E0 (FUN_005487E0, Moho::CSimResourcesTypeInfo::AddBase_ISimResources)
   */
  void CSimResourcesTypeInfo::AddBase_ISimResources(
    gpg::RType* const typeInfo
  )
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveISimResourcesType());
  }

  /**
   * Address: 0x005484A0 (FUN_005484A0, Moho::CSimResourcesTypeInfo::NewRef)
   */
  gpg::RRef CSimResourcesTypeInfo::NewRef()
  {
    CSimResources* const object = CSimResources::Create();
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548530 (FUN_00548530, Moho::CSimResourcesTypeInfo::CtrRef)
   */
  gpg::RRef CSimResourcesTypeInfo::CtrRef(
    void* const objectPtr
  )
  {
    auto* const object = static_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      new (object) CSimResources();
    }
    return MakeCSimResourcesRef(object);
  }

  /**
   * Address: 0x00548510 (FUN_00548510, Moho::CSimResourcesTypeInfo::Delete)
   */
  void CSimResourcesTypeInfo::Delete(
    void* const objectPtr
  )
  {
    auto* const object = static_cast<CSimResources*>(objectPtr);
    if (object != nullptr) {
      delete object;
    }
  }

  /**
   * Address: 0x005485A0 (FUN_005485A0, Moho::CSimResourcesTypeInfo::Destruct)
   */
  void CSimResourcesTypeInfo::Destruct(
    void* const objectPtr
  )
  {
    auto* const object = static_cast<CSimResources*>(objectPtr);
    object->~CSimResources();
  }

  /**
   * Address: 0x00BC96B0 (FUN_00BC96B0, register_CSimResourcesTypeInfo)
   */
  void register_CSimResourcesTypeInfo()
  {
    (void)AcquireCSimResourcesTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  register_CSimResourcesTypeInfo_f091f7,
  moho::register_CSimResourcesTypeInfo
)
