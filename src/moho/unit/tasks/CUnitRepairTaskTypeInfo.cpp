#include "moho/unit/tasks/CUnitRepairTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitRepairTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitRepairTaskTypeInfo;

  /**
   * Address: 0x00BF93F0 (FUN_00BF93F0, atexit destructor of the CUnitRepairTaskTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x005F9000 (FUN_005F9000, ??0CUnitRepairTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitRepairTask` RTTI into the reflection lookup table.
   */
  CUnitRepairTaskTypeInfo::CUnitRepairTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitRepairTask), this);
  }

  /**
   * Address: 0x005F90C0 (FUN_005F90C0, scalar deleting thunk)
   */
  CUnitRepairTaskTypeInfo::~CUnitRepairTaskTypeInfo() = default;

  /**
   * Address: 0x005F90B0 (FUN_005F90B0)
   */
  const char* CUnitRepairTaskTypeInfo::GetName() const
  {
    return "CUnitRepairTask";
  }

  /**
   * Address: 0x005F9060 (FUN_005F9060)
   *
   * What it does:
   * Sets the reflected size (0x9C) and wires base / allocator callbacks.
   */
  void CUnitRepairTaskTypeInfo::Init()
  {
    static_assert(sizeof(moho::CUnitRepairTask) == 0x9C, "moho::CUnitRepairTask is 0x9C bytes on x86");
    size_ = sizeof(moho::CUnitRepairTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitRepairTaskTypeInfo::NewRef,
      &CUnitRepairTaskTypeInfo::CtrRef,
      &CUnitRepairTaskTypeInfo::Delete,
      &CUnitRepairTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x005FD340 (FUN_005FD340, Moho::CUnitRepairTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base at offset 0.
   */
  void __stdcall CUnitRepairTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
  }

  /**
   * Address: 0x005FD3A0 (FUN_005FD3A0, Moho::CUnitRepairTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void __stdcall CUnitRepairTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::Listener<moho::ECommandEvent>>(typeInfo, gpg::BaseSubobjectOffset<CUnitRepairTask, Listener<ECommandEvent>>());
  }

  /**
   * Address: 0x005FC360 (FUN_005FC360, Moho::CUnitRepairTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one repair-task reflection object and returns its typed
   * reflection reference.
   */
  gpg::RRef CUnitRepairTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitRepairTask();

    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CUnitRepairTask>(task);
    return ref;
  }

  /**
   * Address: 0x005FC400 (FUN_005FC400, Moho::CUnitRepairTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one repair-task reflection object in caller-provided
   * storage and returns its typed reflection reference.
   */
  gpg::RRef CUnitRepairTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = gpg::ConstructInStorage<CUnitRepairTask>(objectStorage);

    gpg::RRef ref{};
    ref = gpg::MakeRRef<moho::CUnitRepairTask>(task);
    return ref;
  }

  /**
   * Address: 0x005FC3E0 (FUN_005FC3E0, Moho::CUnitRepairTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned repair-task reflection object through the deleting
   * destructor lane.
   */
  void CUnitRepairTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitRepairTask*>(objectStorage);
  }

  /**
   * Address: 0x005FC470 (FUN_005FC470, Moho::CUnitRepairTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the non-deleting destructor lane for one repair-task reflection
   * object.
   */
  void CUnitRepairTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitRepairTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitRepairTask();
  }

  /**
   * Address: 0x00BCF930 (FUN_00BCF930, register_CUnitRepairTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner.
   */
  void register_CUnitRepairTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitRepairTaskTypeInfo_348fbb, moho::register_CUnitRepairTaskTypeInfo)
