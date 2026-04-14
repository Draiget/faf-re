#include "moho/unit/tasks/CUnitFormAndMoveTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitFormAndMoveTask.h"

namespace
{
  using TypeInfo = moho::CUnitFormAndMoveTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      new (gTypeInfoStorage) TypeInfo();
      gTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gTypeInfoStorage);
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitFormAndMoveTaskTypeInfo();
    gTypeInfoConstructed = false;
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

  [[nodiscard]] gpg::RType* CachedCUnitFormAndMoveTaskType()
  {
    gpg::RType* type = moho::CUnitFormAndMoveTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFormAndMoveTask));
      moho::CUnitFormAndMoveTask::sType = type;
    }
    return type;
  }

  void AddBaseField(gpg::RType* const typeInfo, gpg::RType* const baseType, const std::int32_t offset)
  {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = offset;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RRef MakeFormAndMoveTaskRef(moho::CUnitFormAndMoveTask* const task)
  {
    return gpg::RRef{task, CachedCUnitFormAndMoveTaskType()};
  }

  /**
   * Address: 0x00619D70 (FUN_00619D70, callback shard)
   *
   * What it does:
   * Assigns allocator and placement-constructor callback lanes to this type
   * descriptor.
   */
  void AssignCtorCallbacks(TypeInfo& typeInfo)
  {
    typeInfo.newRefFunc_ = &moho::CUnitFormAndMoveTaskTypeInfo::NewRef;
    typeInfo.ctorRefFunc_ = &moho::CUnitFormAndMoveTaskTypeInfo::CtrRef;
  }

  /**
   * Address: 0x00619D80 (FUN_00619D80, callback shard)
   *
   * What it does:
   * Assigns delete and in-place-destruct callback lanes to this type
   * descriptor.
   */
  void AssignDtorCallbacks(TypeInfo& typeInfo)
  {
    typeInfo.deleteFunc_ = &moho::CUnitFormAndMoveTaskTypeInfo::Delete;
    typeInfo.dtrFunc_ = &moho::CUnitFormAndMoveTaskTypeInfo::Destruct;
  }

  /**
   * Address: 0x00619C90 (FUN_00619C90, callback shard)
   *
   * What it does:
   * Assigns all lifecycle callback lanes (`NewRef`, `CtrRef`, `Delete`,
   * `Destruct`) on this type descriptor.
   */
  void AssignAllLifecycleCallbacks(TypeInfo& typeInfo)
  {
    AssignCtorCallbacks(typeInfo);
    AssignDtorCallbacks(typeInfo);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00619850 (FUN_00619850, typeinfo ctor lane)
   *
   * What it does:
   * Constructs one type-info owner and preregisters
   * `CUnitFormAndMoveTask` RTTI binding.
   */
  CUnitFormAndMoveTaskTypeInfo::CUnitFormAndMoveTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitFormAndMoveTask), this);
  }

  /**
   * Address: 0x00619910 (FUN_00619910, scalar deleting thunk)
   */
  CUnitFormAndMoveTaskTypeInfo::~CUnitFormAndMoveTaskTypeInfo() = default;

  /**
   * Address: 0x00619900 (FUN_00619900, Moho::CUnitFormAndMoveTaskTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type-name literal for `CUnitFormAndMoveTask`.
   */
  const char* CUnitFormAndMoveTaskTypeInfo::GetName() const
  {
    return "CUnitFormAndMoveTask";
  }

  /**
   * Address: 0x006198B0 (FUN_006198B0, Moho::CUnitFormAndMoveTaskTypeInfo::Init)
   *
   * What it does:
   * Sets reflected size/callback lanes, registers reflected base slices, and
   * finalizes type-info initialization.
   */
  void CUnitFormAndMoveTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitFormAndMoveTask);
    AssignAllLifecycleCallbacks(*this);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_EAiNavigatorEvent(this);
    AddBase_Listener_EFormationdStatus(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x0061A1B0 (FUN_0061A1B0)
   *
   * What it does:
   * Registers `CCommandTask` as the reflected primary base.
   */
  void CUnitFormAndMoveTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    AddBaseField(typeInfo, CachedCCommandTaskType(), 0x00);
  }

  /**
   * Address: 0x0061A210 (FUN_0061A210)
   *
   * What it does:
   * Registers `Listener<EAiNavigatorEvent>` as reflected secondary base at
   * offset `0x34`.
   */
  void CUnitFormAndMoveTaskTypeInfo::AddBase_Listener_EAiNavigatorEvent(gpg::RType* const typeInfo)
  {
    AddBaseField(typeInfo, CachedListenerEAiNavigatorEventType(), 0x34);
  }

  /**
   * Address: 0x0061A270 (FUN_0061A270)
   *
   * What it does:
   * Registers `Listener<EFormationdStatus>` as reflected secondary base at
   * offset `0x44`.
   */
  void CUnitFormAndMoveTaskTypeInfo::AddBase_Listener_EFormationdStatus(gpg::RType* const typeInfo)
  {
    AddBaseField(typeInfo, CachedListenerEFormationdStatusType(), 0x44);
  }

  /**
   * Address: 0x0061A2D0 (FUN_0061A2D0)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as reflected secondary base at
   * offset `0x54`.
   */
  void CUnitFormAndMoveTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    AddBaseField(typeInfo, CachedListenerECommandEventType(), 0x54);
  }

  /**
   * Address: 0x00619EF0 (FUN_00619EF0, Moho::CUnitFormAndMoveTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitFormAndMoveTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitFormAndMoveTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitFormAndMoveTask();
    return MakeFormAndMoveTaskRef(task);
  }

  /**
   * Address: 0x00619F90 (FUN_00619F90, Moho::CUnitFormAndMoveTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitFormAndMoveTask` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef CUnitFormAndMoveTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitFormAndMoveTask*>(objectStorage);
    if (task) {
      new (task) CUnitFormAndMoveTask();
    }
    return MakeFormAndMoveTaskRef(task);
  }

  /**
   * Address: 0x00619F70 (FUN_00619F70, Moho::CUnitFormAndMoveTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitFormAndMoveTask`.
   */
  void CUnitFormAndMoveTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitFormAndMoveTask*>(objectStorage);
  }

  /**
   * Address: 0x0061A000 (FUN_0061A000, Moho::CUnitFormAndMoveTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs in-place destructor for one `CUnitFormAndMoveTask` without
   * deallocating storage.
   */
  void CUnitFormAndMoveTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitFormAndMoveTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitFormAndMoveTask();
  }

  /**
   * Address: 0x00BD1090 (FUN_00BD1090, register_CUnitFormAndMoveTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitFormAndMoveTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
