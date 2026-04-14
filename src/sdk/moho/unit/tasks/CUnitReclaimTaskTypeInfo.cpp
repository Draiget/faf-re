#include "moho/unit/tasks/CUnitReclaimTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitReclaimTask.h"

namespace
{
  alignas(moho::CUnitReclaimTaskTypeInfo)
  unsigned char gCUnitReclaimTaskTypeInfoStorage[sizeof(moho::CUnitReclaimTaskTypeInfo)]{};
  bool gCUnitReclaimTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitReclaimTaskTypeInfo* AcquireCUnitReclaimTaskTypeInfo()
  {
    if (!gCUnitReclaimTaskTypeInfoConstructed) {
      auto* const typeInfo = new (gCUnitReclaimTaskTypeInfoStorage) moho::CUnitReclaimTaskTypeInfo();
      gpg::PreRegisterRType(typeid(moho::CUnitReclaimTask), typeInfo);
      gCUnitReclaimTaskTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CUnitReclaimTaskTypeInfo*>(gCUnitReclaimTaskTypeInfoStorage);
  }

  /**
   * Address: 0x0061ED40 (FUN_0061ED40, sub_61ED40)
   *
   * What it does:
   * Constructs and preregisters static RTTI descriptor storage for
   * `moho::CUnitReclaimTask`.
   */
  [[nodiscard]] gpg::RType* construct_CUnitReclaimTaskTypeInfo()
  {
    return AcquireCUnitReclaimTaskTypeInfo();
  }

  [[nodiscard]] gpg::RType* CachedCUnitReclaimTaskType()
  {
    gpg::RType* type = moho::CUnitReclaimTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitReclaimTask));
      moho::CUnitReclaimTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
    }
    return cached;
  }

  class CUnitReclaimTaskReflectionView final : public moho::CUnitReclaimTask
  {
  public:
    CUnitReclaimTaskReflectionView()
      : CUnitReclaimTask()
    {
    }

    ~CUnitReclaimTaskReflectionView() override = default;

    int Execute() override
    {
      return -1;
    }

    void OnEvent(moho::ECommandEvent) override {}
  };

  static_assert(
    sizeof(CUnitReclaimTaskReflectionView) == sizeof(moho::CUnitReclaimTask),
    "CUnitReclaimTaskReflectionView size must match CUnitReclaimTask"
  );

  [[nodiscard]] gpg::RRef MakeCUnitReclaimTaskRef(moho::CUnitReclaimTask* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedCUnitReclaimTaskType();
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
    gpg::RType* const baseType = CachedCCommandTaskType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006206E0 (FUN_006206E0, Moho::CUnitReclaimTaskTypeInfo::AddBase_Listener_ECommandEvent)
   */
  void __stdcall CUnitReclaimTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedListenerECommandEventType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x34;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00620560 (FUN_00620560, Moho::CUnitReclaimTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitReclaimTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitReclaimTaskReflectionView();
    return MakeCUnitReclaimTaskRef(static_cast<CUnitReclaimTask*>(object));
  }

  /**
   * Address: 0x00620600 (FUN_00620600, Moho::CUnitReclaimTaskTypeInfo::CtrRef)
   */
  gpg::RRef CUnitReclaimTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitReclaimTaskReflectionView*>(objectStorage);
    if (object) {
      new (object) CUnitReclaimTaskReflectionView();
    }

    return MakeCUnitReclaimTaskRef(reinterpret_cast<CUnitReclaimTask*>(object));
  }

  /**
   * Address: 0x006205E0 (FUN_006205E0, Moho::CUnitReclaimTaskTypeInfo::Delete)
   */
  void CUnitReclaimTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitReclaimTaskReflectionView*>(objectStorage);
  }

  /**
   * Address: 0x00620670 (FUN_00620670, Moho::CUnitReclaimTaskTypeInfo::Destruct)
   */
  void CUnitReclaimTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitReclaimTaskReflectionView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitReclaimTaskReflectionView();
  }
} // namespace moho
