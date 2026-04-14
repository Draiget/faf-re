#include "moho/unit/tasks/CUnitMeleeAttackTargetTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/ai/EAiAttackerEvent.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

namespace
{
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

  [[nodiscard]] gpg::RType* CachedCUnitMeleeAttackTargetTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitMeleeAttackTargetTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00615270 (FUN_00615270)
   *
   * What it does:
   * Preregisters `CUnitMeleeAttackTargetTask` RTTI into the reflection
   * lookup table.
   */
  CUnitMeleeAttackTargetTaskTypeInfo::CUnitMeleeAttackTargetTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitMeleeAttackTargetTask), this);
  }

  /**
   * Address: 0x00615330 (FUN_00615330, scalar deleting thunk)
   */
  CUnitMeleeAttackTargetTaskTypeInfo::~CUnitMeleeAttackTargetTaskTypeInfo() = default;

  /**
   * Address: 0x00615320 (FUN_00615320)
   *
   * What it does:
   * Returns the reflected type name literal for
   * `CUnitMeleeAttackTargetTask`.
   */
  const char* CUnitMeleeAttackTargetTaskTypeInfo::GetName() const
  {
    return "CUnitMeleeAttackTargetTask";
  }

  /**
   * Address: 0x006152D0 (FUN_006152D0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Init)
   *
   * What it does:
   * Sets reflected size (0x90), wires allocator callbacks, registers base
   * lanes, then finalizes reflection metadata.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::Init()
  {
    size_ = 0x90;
    newRefFunc_ = &CUnitMeleeAttackTargetTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitMeleeAttackTargetTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitMeleeAttackTargetTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitMeleeAttackTargetTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_EAiAttackerEvent(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x006179C0 (FUN_006179C0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00617A20 (FUN_00617A20, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent)
   *
   * What it does:
   * Registers `Listener<EAiAttackerEvent>` as a secondary base at offset
   * `0x34`.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent(gpg::RType* const typeInfo)
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
   * Address: 0x00617A80 (FUN_00617A80, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as a secondary base at offset
   * `0x44`.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
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
   * Address: 0x006178A0 (FUN_006178A0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitMeleeAttackTargetTask` and returns a typed reflection
   * ref.
   */
  gpg::RRef CUnitMeleeAttackTargetTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitMeleeAttackTargetTask();
    return gpg::RRef{task, CachedCUnitMeleeAttackTargetTaskType()};
  }

  /**
   * Address: 0x00617940 (FUN_00617940, Moho::CUnitMeleeAttackTargetTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitMeleeAttackTargetTask` in caller-provided
   * storage and returns typed reflection ref.
   */
  gpg::RRef CUnitMeleeAttackTargetTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitMeleeAttackTargetTask*>(objectStorage);
    if (task) {
      new (task) CUnitMeleeAttackTargetTask();
    }
    return gpg::RRef{task, CachedCUnitMeleeAttackTargetTaskType()};
  }

  /**
   * Address: 0x00617920 (FUN_00617920, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitMeleeAttackTargetTask`.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitMeleeAttackTargetTask*>(objectStorage);
  }

  /**
   * Address: 0x006179B0 (FUN_006179B0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs in-place destructor for one `CUnitMeleeAttackTargetTask` without
   * deallocating storage.
   */
  void CUnitMeleeAttackTargetTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitMeleeAttackTargetTask*>(objectStorage);
    task->~CUnitMeleeAttackTargetTask();
  }
} // namespace moho
