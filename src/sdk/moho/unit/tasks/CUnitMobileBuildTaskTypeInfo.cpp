#include "moho/unit/tasks/CUnitMobileBuildTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"

namespace
{
  using TypeInfo = moho::CUnitMobileBuildTaskTypeInfo;

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

  [[nodiscard]] gpg::RType* CachedCUnitMobileBuildTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitMobileBuildTask));
    }
    return cached;
  }

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitMobileBuildTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F68A0 (FUN_005F68A0, ??0CUnitMobileBuildTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitMobileBuildTask` RTTI into the reflection lookup table.
   */
  CUnitMobileBuildTaskTypeInfo::CUnitMobileBuildTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitMobileBuildTask), this);
  }

  /**
   * Address: 0x005F6960 (FUN_005F6960, scalar deleting thunk)
   */
  CUnitMobileBuildTaskTypeInfo::~CUnitMobileBuildTaskTypeInfo() = default;

  /**
   * Address: 0x005F6950 (FUN_005F6950)
   */
  const char* CUnitMobileBuildTaskTypeInfo::GetName() const
  {
    return "CUnitMobileBuildTask";
  }

  /**
   * Address: 0x005F6900 (FUN_005F6900)
   *
   * What it does:
   * Sets the reflected size (0xE8) and wires base/allocator callbacks.
   */
  void CUnitMobileBuildTaskTypeInfo::Init()
  {
    size_ = 0xE8;
    newRefFunc_ = &CUnitMobileBuildTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitMobileBuildTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitMobileBuildTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitMobileBuildTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x005FCF00 (FUN_005FCF00, Moho::CUnitMobileBuildTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base.
   */
  void __stdcall CUnitMobileBuildTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005FCF60 (FUN_005FCF60, Moho::CUnitMobileBuildTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void __stdcall CUnitMobileBuildTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
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
   * Address: 0x005FC120 (FUN_005FC120, Moho::CUnitMobileBuildTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitMobileBuildTask` and returns its typed reflection
   * reference.
   */
  gpg::RRef CUnitMobileBuildTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitMobileBuildTask();
    return gpg::RRef{task, CachedCUnitMobileBuildTaskType()};
  }

  /**
   * Address: 0x005FC1C0 (FUN_005FC1C0, Moho::CUnitMobileBuildTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitMobileBuildTask` in caller-provided storage and
   * returns its typed reflection reference.
   */
  gpg::RRef CUnitMobileBuildTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitMobileBuildTask*>(objectStorage);
    if (task) {
      new (task) CUnitMobileBuildTask();
    }
    return gpg::RRef{task, CachedCUnitMobileBuildTaskType()};
  }

  /**
   * Address: 0x005FC1A0 (FUN_005FC1A0, Moho::CUnitMobileBuildTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitMobileBuildTask`.
   */
  void CUnitMobileBuildTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitMobileBuildTask*>(objectStorage);
  }

  /**
   * Address: 0x005FC230 (FUN_005FC230, Moho::CUnitMobileBuildTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the non-deleting `CUnitMobileBuildTask` destructor body on placement
   * storage.
   */
  void CUnitMobileBuildTaskTypeInfo::Destruct(void* const objectStorage)
  {
    static_cast<CUnitMobileBuildTask*>(objectStorage)->~CUnitMobileBuildTask();
  }

  /**
   * Address: 0x00BCF870 (FUN_00BCF870, register_CUnitMobileBuildTaskTypeInfo)
   */
  int register_CUnitMobileBuildTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
