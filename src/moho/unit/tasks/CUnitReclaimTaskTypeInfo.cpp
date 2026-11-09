#include "moho/unit/tasks/CUnitReclaimTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitReclaimTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BFA2B0 (FUN_00BFA2B0, atexit destructor of the CUnitReclaimTaskTypeInfo object; registered by 0x00BD17C0)
   */
  [[nodiscard]] moho::CUnitReclaimTaskTypeInfo* AcquireCUnitReclaimTaskTypeInfo()
  {
    static moho::CUnitReclaimTaskTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(moho::CUnitReclaimTask), &sInstance);
    return &sInstance;
  }

  /**
   * Address: 0x0061ED40 (FUN_0061ED40, sub_61ED40)
   *
   * What it does:
   * Constructs and preregisters static RTTI descriptor storage for
   * `moho::CUnitReclaimTask`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* construct_CUnitReclaimTaskTypeInfo()
  {
    return AcquireCUnitReclaimTaskTypeInfo();
  }

  [[nodiscard]] gpg::RRef MakeCUnitReclaimTaskRef(moho::CUnitReclaimTask* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = gpg::RTypeOf<moho::CUnitReclaimTask>();
    gpg::RRef_CUnitReclaimTask(&out, object);
    return out;
  }
} // namespace

namespace moho
{
  const char* CUnitReclaimTaskTypeInfo::GetName() const
  {
    return "CUnitReclaimTask";
  }

  /**
   * Address: 0x0061EDA0 (FUN_0061EDA0, Moho::CUnitReclaimTaskTypeInfo::Init)
   *
   * What it does:
   * Sets reclaim-task reflected size/callback lanes, registers reflected base
   * slices, and finalizes type-info initialization.
   */
  void CUnitReclaimTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitReclaimTask);
    AssignAllLifecycleCallbacks(this);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00620460 (FUN_00620460, callback shard)
   *
   * What it does:
   * Assigns all lifecycle callbacks (`NewRef`, `CtrRef`, delete, destruct)
   * to one reclaim-task type descriptor.
   */
  gpg::RType* CUnitReclaimTaskTypeInfo::AssignAllLifecycleCallbacks(gpg::RType* const typeInfo)
  {
    AssignCtorCallbacks(typeInfo);
    AssignDtorCallbacks(typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00620520 (FUN_00620520, callback shard)
   *
   * What it does:
   * Assigns constructor-lane callbacks (`NewRef`, `CtrRef`) to one reclaim-task
   * type descriptor.
   */
  gpg::RType* CUnitReclaimTaskTypeInfo::AssignCtorCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->newRefFunc_ = &CUnitReclaimTaskTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &CUnitReclaimTaskTypeInfo::CtrRef;
    return typeInfo;
  }

  /**
   * Address: 0x00620530 (FUN_00620530, callback shard)
   *
   * What it does:
   * Assigns destructor-lane callbacks (delete + in-place destruct) to one
   * reclaim-task type descriptor.
   */
  gpg::RType* CUnitReclaimTaskTypeInfo::AssignDtorCallbacks(gpg::RType* const typeInfo)
  {
    typeInfo->deleteFunc_ = &CUnitReclaimTaskTypeInfo::Delete;
    typeInfo->dtrFunc_ = &CUnitReclaimTaskTypeInfo::Destruct;
    return typeInfo;
  }

  /**
   * Address: 0x00620680 (FUN_00620680, Moho::CUnitReclaimTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitReclaimTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
  }

  /**
   * Address: 0x006206E0 (FUN_006206E0, Moho::CUnitReclaimTaskTypeInfo::AddBase_Listener_ECommandEvent)
   */
  void __stdcall CUnitReclaimTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::Listener<moho::ECommandEvent>>(typeInfo, gpg::BaseSubobjectOffset<CUnitReclaimTask, Listener<ECommandEvent>>());
  }

  /**
   * Address: 0x00620560 (FUN_00620560, Moho::CUnitReclaimTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitReclaimTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitReclaimTask();
    return MakeCUnitReclaimTaskRef(static_cast<CUnitReclaimTask*>(object));
  }

  /**
   * Address: 0x00620600 (FUN_00620600, Moho::CUnitReclaimTaskTypeInfo::CtrRef)
   */
  gpg::RRef CUnitReclaimTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = gpg::ConstructInStorage<moho::CUnitReclaimTask>(objectStorage);

    return MakeCUnitReclaimTaskRef(reinterpret_cast<CUnitReclaimTask*>(object));
  }

  /**
   * Address: 0x006205E0 (FUN_006205E0, Moho::CUnitReclaimTaskTypeInfo::Delete)
   */
  void CUnitReclaimTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitReclaimTask*>(objectStorage);
  }

  /**
   * Address: 0x00620670 (FUN_00620670, Moho::CUnitReclaimTaskTypeInfo::Destruct)
   */
  void CUnitReclaimTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitReclaimTask*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitReclaimTask();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(AcquireCUnitReclaimTaskTypeInfo_13dd41, AcquireCUnitReclaimTaskTypeInfo)
