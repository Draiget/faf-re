#include "moho/unit/tasks/CUnitAttackTargetTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitAttackTargetTask.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/EAiAttackerEvent.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace
{
  using TypeInfo = moho::CUnitAttackTargetTaskTypeInfo;

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

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerEAiAttackerEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::EAiAttackerEvent>));
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

  [[nodiscard]] gpg::RType* CachedCUnitAttackTargetTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitAttackTargetTask));
    }
    return cached;
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitAttackTargetTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F2510 (FUN_005F2510, ??0CUnitAttackTargetTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitAttackTargetTask` RTTI into the reflection lookup table.
   */
  CUnitAttackTargetTaskTypeInfo::CUnitAttackTargetTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitAttackTargetTask), this);
  }

  /**
   * Address: 0x005F25D0 (FUN_005F25D0, scalar deleting thunk)
   */
  CUnitAttackTargetTaskTypeInfo::~CUnitAttackTargetTaskTypeInfo() = default;

  /**
   * Address: 0x005F25C0 (FUN_005F25C0)
   */
  const char* CUnitAttackTargetTaskTypeInfo::GetName() const
  {
    return "CUnitAttackTargetTask";
  }

  /**
   * Address: 0x005F2570 (FUN_005F2570)
   *
   * What it does:
   * Sets the reflected size (0x90) and wires base/allocator callbacks.
   */
  void CUnitAttackTargetTaskTypeInfo::Init()
  {
    size_ = 0x90;
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitAttackTargetTaskTypeInfo::NewRef,
      &CUnitAttackTargetTaskTypeInfo::CtrRef,
      &CUnitAttackTargetTaskTypeInfo::Delete,
      &CUnitAttackTargetTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_EAiAttackerEvent(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x005F4760 (FUN_005F4760, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base.
   */
  void CUnitAttackTargetTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005F47C0 (FUN_005F47C0, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent)
   *
   * What it does:
   * Registers `Listener<EAiAttackerEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void CUnitAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedListenerEAiAttackerEventType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x34;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x005F4820 (FUN_005F4820, Moho::CUnitAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x44`.
   */
  void CUnitAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedListenerECommandEventType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x44;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x005F4640 (FUN_005F4640, Moho::CUnitAttackTargetTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitAttackTargetTask` and returns typed reflection
   * reference for it.
   */
  gpg::RRef CUnitAttackTargetTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitAttackTargetTask();
    return gpg::RRef{task, CachedCUnitAttackTargetTaskType()};
  }

  /**
   * Address: 0x005F46E0 (FUN_005F46E0, Moho::CUnitAttackTargetTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitAttackTargetTask` in caller-provided
   * storage and returns typed reflection reference for it.
   */
  gpg::RRef CUnitAttackTargetTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitAttackTargetTask*>(objectStorage);
    if (task) {
      new (task) CUnitAttackTargetTask();
    }
    return gpg::RRef{task, CachedCUnitAttackTargetTaskType()};
  }

  /**
   * Address: 0x005F46C0 (FUN_005F46C0, Moho::CUnitAttackTargetTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitAttackTargetTask`.
   */
  void CUnitAttackTargetTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitAttackTargetTask*>(objectStorage);
  }

  /**
   * Address: 0x005F4750 (FUN_005F4750, Moho::CUnitAttackTargetTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs in-place destructor for one `CUnitAttackTargetTask` without
   * deallocating storage.
   */
  void CUnitAttackTargetTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitAttackTargetTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitAttackTargetTask();
  }

  /**
   * Address: 0x00BCF4A0 (FUN_00BCF4A0, register_CUnitAttackTargetTaskTypeInfo)
   */
  int register_CUnitAttackTargetTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
