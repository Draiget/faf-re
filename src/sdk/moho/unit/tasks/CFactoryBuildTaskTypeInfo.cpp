#include "moho/unit/tasks/CFactoryBuildTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CFactoryBuildTask.h"

namespace
{
  alignas(moho::CFactoryBuildTaskTypeInfo)
    unsigned char gCFactoryBuildTaskTypeInfoStorage[sizeof(moho::CFactoryBuildTaskTypeInfo)];
  bool gCFactoryBuildTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CFactoryBuildTaskTypeInfo& CFactoryBuildTaskTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CFactoryBuildTaskTypeInfo*>(gCFactoryBuildTaskTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCFactoryBuildTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CFactoryBuildTask));
    }
    return cached;
  }

  /**
   * Address: 0x005FC500 (FUN_005FC500, Moho::CFactoryBuildTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CFactoryBuildTask` instance.
   */
  void DeleteCFactoryBuildTaskOwned(void* const objectStorage)
  {
    delete static_cast<moho::CFactoryBuildTask*>(objectStorage);
  }

  /**
   * Address: 0x005FC590 (FUN_005FC590, Moho::CFactoryBuildTaskTypeInfo::Destruct)
   *
   * What it does:
   * Executes one in-place `CFactoryBuildTask` destructor lane.
   */
  void DestroyCFactoryBuildTaskInPlace(void* const objectStorage)
  {
    auto* const task = static_cast<moho::CFactoryBuildTask*>(objectStorage);
    if (task != nullptr) {
      task->~CFactoryBuildTask();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FA130 (FUN_005FA130, preregister_CFactoryBuildTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CFactoryBuildTaskTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CFactoryBuildTaskTypeInfo()
  {
    if (!gCFactoryBuildTaskTypeInfoConstructed) {
      new (gCFactoryBuildTaskTypeInfoStorage) CFactoryBuildTaskTypeInfo();
      gCFactoryBuildTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CFactoryBuildTask), &CFactoryBuildTaskTypeInfoStorageRef());
    return &CFactoryBuildTaskTypeInfoStorageRef();
  }

  const char* CFactoryBuildTaskTypeInfo::GetName() const
  {
    return "CFactoryBuildTask";
  }

  void CFactoryBuildTaskTypeInfo::Init()
  {
    size_ = sizeof(CFactoryBuildTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CFactoryBuildTaskTypeInfo::NewRef,
      &CFactoryBuildTaskTypeInfo::CtrRef,
      &DeleteCFactoryBuildTaskOwned,
      &DestroyCFactoryBuildTaskInPlace
    );
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x005FC480 (FUN_005FC480, Moho::CFactoryBuildTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CFactoryBuildTask` and returns a typed reflection ref.
   */
  gpg::RRef CFactoryBuildTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CFactoryBuildTask();
    return gpg::RRef{task, CachedCFactoryBuildTaskType()};
  }

  /**
   * Address: 0x005FC520 (FUN_005FC520, Moho::CFactoryBuildTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CFactoryBuildTask` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef CFactoryBuildTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CFactoryBuildTask*>(objectStorage);
    if (task) {
      new (task) CFactoryBuildTask();
    }

    return gpg::RRef{task, CachedCFactoryBuildTaskType()};
  }
} // namespace moho
