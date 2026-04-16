#include "moho/unit/tasks/CUnitSacrificeTaskTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitSacrificeTask.h"

namespace
{
  using TypeInfo = moho::CUnitSacrificeTaskTypeInfo;

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

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitSacrificeTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitSacrificeTask));
    }
    return cached;
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitSacrificeTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FAF60 (FUN_005FAF60, ??0CUnitSacrificeTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitSacrificeTask` RTTI into the reflection lookup table.
   */
  CUnitSacrificeTaskTypeInfo::CUnitSacrificeTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitSacrificeTask), this);
  }

  /**
   * Address: 0x005FB020 (FUN_005FB020, scalar deleting thunk)
   */
  CUnitSacrificeTaskTypeInfo::~CUnitSacrificeTaskTypeInfo() = default;

  /**
   * Address: 0x005FB010 (FUN_005FB010)
   */
  const char* CUnitSacrificeTaskTypeInfo::GetName() const
  {
    return "CUnitSacrificeTask";
  }

  /**
   * Address: 0x005FAFC0 (FUN_005FAFC0)
   *
   * What it does:
   * Sets the reflected size (0x4C) and wires base / allocator callbacks.
   */
  void CUnitSacrificeTaskTypeInfo::Init()
  {
    size_ = 0x4C;
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitSacrificeTaskTypeInfo::NewRef,
      &CUnitSacrificeTaskTypeInfo::CtrRef,
      &CUnitSacrificeTaskTypeInfo::Delete,
      &CUnitSacrificeTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x005FD4A0 (FUN_005FD4A0, Moho::CUnitSacrificeTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base for
   * `CUnitSacrificeTask`.
   */
  void __stdcall CUnitSacrificeTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005FD500 (FUN_005FD500, Moho::CUnitSacrificeTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base for
   * `CUnitSacrificeTask`.
   */
  void __stdcall CUnitSacrificeTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
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
   * Address: 0x005FC5A0 (FUN_005FC5A0, Moho::CUnitSacrificeTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates and initializes one `CUnitSacrificeTask` for reflection use,
   * then returns its typed reflection reference.
   */
  gpg::RRef CUnitSacrificeTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitSacrificeTask(nullptr, nullptr);
    if (!task) {
      return gpg::RRef{nullptr, CachedCUnitSacrificeTaskType()};
    }

    return gpg::RRef{task, CachedCUnitSacrificeTaskType()};
  }

  /**
   * Address: 0x005FC660 (FUN_005FC660, Moho::CUnitSacrificeTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitSacrificeTask` in caller-provided storage and
   * returns its typed reflection reference.
   */
  gpg::RRef CUnitSacrificeTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitSacrificeTask*>(objectStorage);
    if (task) {
      new (task) CUnitSacrificeTask(nullptr, nullptr);
    }

    return gpg::RRef{task, CachedCUnitSacrificeTaskType()};
  }

  /**
   * Address: 0x005FC640 (FUN_005FC640, Moho::CUnitSacrificeTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes a `CUnitSacrificeTask` through its deleting-destructor path.
   */
  void CUnitSacrificeTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitSacrificeTask*>(objectStorage);
  }

  /**
   * Address: 0x005FC700 (FUN_005FC700, Moho::CUnitSacrificeTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the non-deleting `CUnitSacrificeTask` destructor body on placement
   * storage.
   */
  void CUnitSacrificeTaskTypeInfo::Destruct(void* const objectStorage)
  {
    if (!objectStorage) {
      return;
    }

    static_cast<CUnitSacrificeTask*>(objectStorage)->~CUnitSacrificeTask();
  }

  /**
   * Address: 0x00BCF9F0 (FUN_00BCF9F0, register_CUnitSacrificeTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitSacrificeTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
