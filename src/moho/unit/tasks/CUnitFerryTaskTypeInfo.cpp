#include "moho/unit/tasks/CUnitFerryTaskTypeInfo.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitFerryTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitFerryTaskTypeInfo;

  /**
   * Address: 0x00BF9D40 (FUN_00BF9D40, atexit destructor of the CUnitFerryTaskTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RRef MakeCUnitFerryTaskRef(moho::CUnitFerryTask* const object)
  {
    return gpg::RRef{object, gpg::RTypeOf<moho::CUnitFerryTask>()};
  }

  /**
   * Address: 0x0060FFB0 (FUN_0060FFB0)
   *
   * What it does:
   * Binds lifecycle callback lanes (`new/ctor/delete/destruct`) for one
   * `CUnitFerryTaskTypeInfo` descriptor.
   */
  [[maybe_unused]] gpg::RType* BindCUnitFerryTaskTypeLifecycleCallbacks(gpg::RType* const typeInfo) noexcept
  {
    typeInfo->newRefFunc_ = &moho::CUnitFerryTaskTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &moho::CUnitFerryTaskTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &moho::CUnitFerryTaskTypeInfo::Delete;
    typeInfo->dtrFunc_ = &moho::CUnitFerryTaskTypeInfo::Destruct;
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060DB00 (FUN_0060DB00)
   */
  CUnitFerryTaskTypeInfo::CUnitFerryTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitFerryTask), this);
  }

  /**
   * Address: 0x0060DBB0 (FUN_0060DBB0, scalar deleting thunk)
   */
  CUnitFerryTaskTypeInfo::~CUnitFerryTaskTypeInfo() = default;

  /**
   * Address: 0x0060DBA0 (FUN_0060DBA0, Moho::CUnitFerryTaskTypeInfo::GetName)
   */
  const char* CUnitFerryTaskTypeInfo::GetName() const
  {
    return "CUnitFerryTask";
  }

  /**
   * Address: 0x0060DB60 (FUN_0060DB60, Moho::CUnitFerryTaskTypeInfo::Init)
   */
  void CUnitFerryTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitFerryTask);
    (void)BindCUnitFerryTaskTypeLifecycleCallbacks(this);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x006104B0 (FUN_006104B0, Moho::CUnitFerryTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitFerryTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
  }

  /**
   * Address: 0x006101B0 (FUN_006101B0, Moho::CUnitFerryTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitFerryTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitFerryTask();
    return MakeCUnitFerryTaskRef(object);
  }

  /**
   * Address: 0x00610280 (FUN_00610280, Moho::CUnitFerryTaskTypeInfo::CtrRef)
   */
  gpg::RRef CUnitFerryTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = gpg::ConstructInStorage<CUnitFerryTask>(objectStorage);
    return MakeCUnitFerryTaskRef(object);
  }

  /**
   * Address: 0x00610260 (FUN_00610260, Moho::CUnitFerryTaskTypeInfo::Delete)
   */
  void CUnitFerryTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitFerryTask*>(objectStorage);
  }

  /**
   * Address: 0x00610330 (FUN_00610330, Moho::CUnitFerryTaskTypeInfo::Destruct)
   */
  void CUnitFerryTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitFerryTask*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitFerryTask();
  }

  /**
   * Address: 0x00BD08E0 (FUN_00BD08E0, register_CUnitFerryTaskTypeInfo)
   */
  void register_CUnitFerryTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitFerryTaskTypeInfo_71ac00, moho::register_CUnitFerryTaskTypeInfo)
