#include "moho/unit/tasks/CUnitGuardTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitGuardTask.h"

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

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitGuardTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitGuardTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00610F30 (FUN_00610F30, Moho::CUnitGuardTaskTypeInfo::Init)
   *
   * What it does:
   * Sets reflected object size/callback lanes, then registers
   * `CCommandTask` and `Listener<ECommandEvent>` base metadata.
   */
  void CUnitGuardTaskTypeInfo::Init()
  {
    size_ = 0xC0;
    newRefFunc_ = &CUnitGuardTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitGuardTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitGuardTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitGuardTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00614A70 (FUN_00614A70, Moho::CUnitGuardTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base.
   */
  void __stdcall CUnitGuardTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00614AD0 (FUN_00614AD0, Moho::CUnitGuardTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void __stdcall CUnitGuardTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
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
   * Address: 0x00614950 (FUN_00614950, Moho::CUnitGuardTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitGuardTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitGuardTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitGuardTask();
    return gpg::RRef{task, CachedCUnitGuardTaskType()};
  }

  /**
   * Address: 0x006149F0 (FUN_006149F0, Moho::CUnitGuardTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitGuardTask` in caller-provided storage and returns a
   * typed reflection ref.
   */
  gpg::RRef CUnitGuardTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    CUnitGuardTask* task = nullptr;
    if (objectStorage != nullptr) {
      task = new (objectStorage) CUnitGuardTask();
    }

    return gpg::RRef{task, CachedCUnitGuardTaskType()};
  }

  /**
   * Address: 0x006149D0 (FUN_006149D0, Moho::CUnitGuardTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitGuardTask`.
   */
  void CUnitGuardTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitGuardTask*>(objectStorage);
  }

  /**
   * Address: 0x00614A60 (FUN_00614A60, Moho::CUnitGuardTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the in-place `CUnitGuardTask` destructor body.
   */
  void CUnitGuardTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitGuardTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitGuardTask();
  }
} // namespace moho
