#include "moho/unit/tasks/CUnitCarrierLaunchTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitCarrierLaunch.h"

namespace
{
  alignas(moho::CUnitCarrierLaunchTypeInfo)
    unsigned char gCUnitCarrierLaunchTypeInfoStorage[sizeof(moho::CUnitCarrierLaunchTypeInfo)];
  bool gCUnitCarrierLaunchTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitCarrierLaunchTypeInfo& CUnitCarrierLaunchTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitCarrierLaunchTypeInfo*>(gCUnitCarrierLaunchTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCUnitCarrierLaunchType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCarrierLaunch));
    }
    return cached;
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
    return gpg::RRef{task, CachedCUnitCarrierLaunchType()};
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

    return gpg::RRef{task, CachedCUnitCarrierLaunchType()};
  }
} // namespace moho
