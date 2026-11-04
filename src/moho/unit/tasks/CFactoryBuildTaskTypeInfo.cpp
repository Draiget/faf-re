#include "moho/unit/tasks/CFactoryBuildTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CFactoryBuildTask.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
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

  /**
   * Address: 0x005FD420 (FUN_005FD420, func_RTypeAddBaseCCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the zero-offset reflected base, looking its type up once into
   * `CCommandTask::sType` (0x010C6FF4). `Init` (0x005FA190) is its only caller.
   */
  void AddBaseCCommandTask(gpg::RType* const typeInfo)
  {
    if (moho::CCommandTask::sType == nullptr) {
      moho::CCommandTask::sType = gpg::LookupRType(typeid(moho::CCommandTask));
    }

    gpg::RType* const baseType = moho::CCommandTask::sType;
    typeInfo->AddBase(gpg::RField{baseType->GetName(), baseType, 0, 0, nullptr});
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FA130 (FUN_005FA130, preregister_CFactoryBuildTaskTypeInfo)
   * Address: 0x00BF9480 (FUN_00BF9480, atexit destructor of the CFactoryBuildTaskTypeInfo object)
   *
   * What it does:
   * Constructs/preregisters the startup `CFactoryBuildTaskTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CFactoryBuildTaskTypeInfo()
  {
    static CFactoryBuildTaskTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(CFactoryBuildTask), &sInstance);
    return &sInstance;
  }

  const char* CFactoryBuildTaskTypeInfo::GetName() const
  {
    return "CFactoryBuildTask";
  }

  /**
   * Address: 0x005FA190 (FUN_005FA190, Moho::CFactoryBuildTaskTypeInfo::Init)
   *
   * What it does:
   * Size and lifecycle callbacks, base init, the `CCommandTask` base (0x005FA1BC), then
   * `Finish`. Without the base, saving a factory's build task failed `isDer` (it is written
   * through `CTask*`).
   */
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
    AddBaseCCommandTask(this);
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
    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CFactoryBuildTask>(task);
    return ref;
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

    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CFactoryBuildTask>(task);
    return ref;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CFactoryBuildTaskTypeInfo_c07ac7, moho::preregister_CFactoryBuildTaskTypeInfo)
