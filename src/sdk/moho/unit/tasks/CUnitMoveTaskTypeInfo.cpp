#include "moho/unit/tasks/CUnitMoveTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace
{
  alignas(moho::CUnitMoveTaskTypeInfo)
    unsigned char gCUnitMoveTaskTypeInfoStorage[sizeof(moho::CUnitMoveTaskTypeInfo)];
  bool gCUnitMoveTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitMoveTaskTypeInfo& CUnitMoveTaskTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitMoveTaskTypeInfo*>(gCUnitMoveTaskTypeInfoStorage);
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

  [[nodiscard]] gpg::RType* CachedListenerEAiNavigatorEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiNavigatorEvent>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerEFormationdStatusType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::EFormationdStatus>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitMoveTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitMoveTask));
    }
    return cached;
  }

  void AddBaseField(gpg::RType* const typeInfo, gpg::RType* const baseType, const int offset)
  {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = offset;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void Delete_CUnitMoveTask(void* const objectStorage)
  {
    delete static_cast<moho::CUnitMoveTask*>(objectStorage);
  }

  void Destruct_CUnitMoveTask(void* const objectStorage)
  {
    auto* const task = static_cast<moho::CUnitMoveTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitMoveTask();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00618E60 (FUN_00618E60, preregister_CUnitMoveTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitMoveTaskTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CUnitMoveTaskTypeInfo()
  {
    if (!gCUnitMoveTaskTypeInfoConstructed) {
      new (gCUnitMoveTaskTypeInfoStorage) CUnitMoveTaskTypeInfo();
      gCUnitMoveTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CUnitMoveTask), &CUnitMoveTaskTypeInfoStorageRef());
    return &CUnitMoveTaskTypeInfoStorageRef();
  }

  const char* CUnitMoveTaskTypeInfo::GetName() const
  {
    return "CUnitMoveTask";
  }

  /**
   * Address: 0x00618EC0 (FUN_00618EC0, Moho::CUnitMoveTaskTypeInfo::Init)
   *
   * What it does:
   * Sets move-task reflected size/callback lanes, registers reflected base
   * slices, and finalizes type-info initialization.
   */
  void CUnitMoveTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitMoveTask);
    AssignAllLifecycleCallbacks(*this);
    gpg::RType::Init();
    AddBaseField(this, CachedCCommandTaskType(), 0);
    AddBaseField(this, CachedListenerEAiNavigatorEventType(), 0x34);
    AddBaseField(this, CachedListenerEFormationdStatusType(), 0x44);
    AddBaseField(this, CachedListenerECommandEventType(), 0x54);
    Finish();
  }

  /**
   * Address: 0x00619BD0 (FUN_00619BD0, callback shard)
   *
   * What it does:
   * Assigns all lifecycle callbacks (`NewRef`, `CtrRef`, delete, destruct)
   * onto one move-task type descriptor.
   */
  void CUnitMoveTaskTypeInfo::AssignAllLifecycleCallbacks(CUnitMoveTaskTypeInfo& typeInfo)
  {
    AssignCtorCallbacks(typeInfo);
    AssignDtorCallbacks(typeInfo);
  }

  /**
   * Address: 0x00619D50 (FUN_00619D50, callback shard)
   *
   * What it does:
   * Assigns constructor-lane callbacks (`NewRef`, `CtrRef`) to one move-task
   * type descriptor.
   */
  void CUnitMoveTaskTypeInfo::AssignCtorCallbacks(CUnitMoveTaskTypeInfo& typeInfo)
  {
    typeInfo.newRefFunc_ = &CUnitMoveTaskTypeInfo::NewRef;
    typeInfo.ctorRefFunc_ = &CUnitMoveTaskTypeInfo::CtrRef;
  }

  /**
   * Address: 0x00619D60 (FUN_00619D60, callback shard)
   *
   * What it does:
   * Assigns destructor-lane callbacks (delete + in-place destruct) to one
   * move-task type descriptor.
   */
  void CUnitMoveTaskTypeInfo::AssignDtorCallbacks(CUnitMoveTaskTypeInfo& typeInfo)
  {
    typeInfo.deleteFunc_ = &Delete_CUnitMoveTask;
    typeInfo.dtrFunc_ = &Destruct_CUnitMoveTask;
  }

  /**
   * Address: 0x00619DD0 (FUN_00619DD0, Moho::CUnitMoveTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitMoveTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitMoveTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitMoveTask();
    return gpg::RRef{task, CachedCUnitMoveTaskType()};
  }

  /**
   * Address: 0x00619E70 (FUN_00619E70, Moho::CUnitMoveTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitMoveTask` in caller storage and returns
   * a typed reflection ref.
   */
  gpg::RRef CUnitMoveTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitMoveTask*>(objectStorage);
    if (task) {
      new (task) CUnitMoveTask();
    }

    return gpg::RRef{task, CachedCUnitMoveTaskType()};
  }
} // namespace moho
