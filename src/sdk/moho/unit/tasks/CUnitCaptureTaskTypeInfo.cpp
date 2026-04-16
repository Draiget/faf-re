#include "moho/unit/tasks/CUnitCaptureTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitCaptureTask.h"

namespace
{
  alignas(moho::CUnitCaptureTaskTypeInfo)
    unsigned char gCUnitCaptureTaskTypeInfoStorage[sizeof(moho::CUnitCaptureTaskTypeInfo)];
  bool gCUnitCaptureTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitCaptureTaskTypeInfo& CUnitCaptureTaskTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitCaptureTaskTypeInfo*>(gCUnitCaptureTaskTypeInfoStorage);
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

  [[nodiscard]] gpg::RType* CachedCUnitCaptureTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCaptureTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00604140 (FUN_00604140, preregister_CUnitCaptureTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitCaptureTaskTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CUnitCaptureTaskTypeInfo()
  {
    if (!gCUnitCaptureTaskTypeInfoConstructed) {
      new (gCUnitCaptureTaskTypeInfoStorage) CUnitCaptureTaskTypeInfo();
      gCUnitCaptureTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CUnitCaptureTask), &CUnitCaptureTaskTypeInfoStorageRef());
    return &CUnitCaptureTaskTypeInfoStorageRef();
  }

  const char* CUnitCaptureTaskTypeInfo::GetName() const
  {
    return "CUnitCaptureTask";
  }

  /**
   * Address: 0x006041A0 (FUN_006041A0, Moho::CUnitCaptureTaskTypeInfo::Init)
   *
   * What it does:
   * Sets reflected object size/callback lanes, then registers
   * `CCommandTask` and `Listener<ECommandEvent>` base metadata.
   */
  void CUnitCaptureTaskTypeInfo::Init()
  {
    size_ = 0x64;
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCaptureTaskTypeInfo::NewRef,
      &CUnitCaptureTaskTypeInfo::CtrRef,
      &CUnitCaptureTaskTypeInfo::Delete,
      &CUnitCaptureTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00605520 (FUN_00605520, Moho::CUnitCaptureTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base.
   */
  void __stdcall CUnitCaptureTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00605580 (FUN_00605580, Moho::CUnitCaptureTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void __stdcall CUnitCaptureTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
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
   * Address: 0x00605400 (FUN_00605400, Moho::CUnitCaptureTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitCaptureTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitCaptureTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCaptureTask();
    return gpg::RRef{task, CachedCUnitCaptureTaskType()};
  }

  /**
   * Address: 0x006054A0 (FUN_006054A0, Moho::CUnitCaptureTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitCaptureTask` in caller-provided storage and returns a
   * typed reflection ref.
   */
  gpg::RRef CUnitCaptureTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    CUnitCaptureTask* task = nullptr;
    if (objectStorage != nullptr) {
      task = new (objectStorage) CUnitCaptureTask();
    }

    return gpg::RRef{task, CachedCUnitCaptureTaskType()};
  }

  /**
   * Address: 0x00605480 (FUN_00605480, Moho::CUnitCaptureTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitCaptureTask`.
   */
  void CUnitCaptureTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCaptureTask*>(objectStorage);
  }

  /**
   * Address: 0x00605510 (FUN_00605510, Moho::CUnitCaptureTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the in-place `CUnitCaptureTask` destructor body.
   */
  void CUnitCaptureTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCaptureTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitCaptureTask();
  }
} // namespace moho
