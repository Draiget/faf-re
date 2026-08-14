#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCarrierLaunchTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitCarrierLaunch.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::CUnitCarrierLaunchTypeInfo)
    unsigned char gCUnitCarrierLaunchTypeInfoStorage[sizeof(moho::CUnitCarrierLaunchTypeInfo)];
  bool gCUnitCarrierLaunchTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitCarrierLaunchTypeInfo& CUnitCarrierLaunchTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitCarrierLaunchTypeInfo*>(gCUnitCarrierLaunchTypeInfoStorage);
  }

  /**
   * Address: 0x00607D80 (FUN_00607D80, Moho::CUnitCarrierLaunchTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitCarrierLaunch` instance.
   */
  void DeleteCUnitCarrierLaunchOwned(void* const objectStorage)
  {
    delete static_cast<moho::CUnitCarrierLaunch*>(objectStorage);
  }

  /**
   * Address: 0x00607E10 (FUN_00607E10, Moho::CUnitCarrierLaunchTypeInfo::Destruct)
   *
   * What it does:
   * Executes one in-place `CUnitCarrierLaunch` destructor lane.
   */
  void DestroyCUnitCarrierLaunchInPlace(void* const objectStorage)
  {
    auto* const task = static_cast<moho::CUnitCarrierLaunch*>(objectStorage);
    if (task != nullptr) {
      task->~CUnitCarrierLaunch();
    }
  }
} // namespace

namespace moho
{
    /**
   * Address: 0x00607F20 (FUN_00607F20, Moho::CUnitCarrierLaunchTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as this type's reflected base at offset 0.
   */
  void CUnitCarrierLaunchTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(CCommandTask));
    }
    gpg::AddBaseIfPresent(typeInfo, sType, 0);
  }

/**
   * Address: 0x00607470 (FUN_00607470, preregister_CUnitCarrierLaunchTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitCarrierLaunchTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CUnitCarrierLaunchTypeInfo()
  {
    if (!gCUnitCarrierLaunchTypeInfoConstructed) {
      new (gCUnitCarrierLaunchTypeInfoStorage) CUnitCarrierLaunchTypeInfo();
      gCUnitCarrierLaunchTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CUnitCarrierLaunch), &CUnitCarrierLaunchTypeInfoStorageRef());
    return &CUnitCarrierLaunchTypeInfoStorageRef();
  }

  const char* CUnitCarrierLaunchTypeInfo::GetName() const
  {
    return "CUnitCarrierLaunch";
  }

  void CUnitCarrierLaunchTypeInfo::Init()
  {
    size_ = sizeof(CUnitCarrierLaunch);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCarrierLaunchTypeInfo::NewRef,
      &CUnitCarrierLaunchTypeInfo::CtrRef,
      &DeleteCUnitCarrierLaunchOwned,
      &DestroyCUnitCarrierLaunchInPlace
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00607D00 (FUN_00607D00, Moho::CUnitCarrierLaunchTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitCarrierLaunch` and returns a typed reflection ref.
   */
  gpg::RRef CUnitCarrierLaunchTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCarrierLaunch();
    gpg::RRef ref{};
    (void)gpg::RRef_CUnitCarrierLaunch(&ref, task);
    return ref;
  }

  /**
   * Address: 0x00607DA0 (FUN_00607DA0, Moho::CUnitCarrierLaunchTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitCarrierLaunch` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef CUnitCarrierLaunchTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCarrierLaunch*>(objectStorage);
    if (task) {
      new (task) CUnitCarrierLaunch();
    }

    gpg::RRef ref{};
    (void)gpg::RRef_CUnitCarrierLaunch(&ref, task);
    return ref;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CUnitCarrierLaunchTypeInfo_413aa3, moho::preregister_CUnitCarrierLaunchTypeInfo)
