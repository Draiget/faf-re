#include "moho/unit/tasks/CUnitUnloadUnitsTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitUnloadUnits.h"

namespace
{
  alignas(moho::CUnitUnloadUnitsTypeInfo)
    unsigned char gCUnitUnloadUnitsTypeInfoStorage[sizeof(moho::CUnitUnloadUnitsTypeInfo)];
  bool gCUnitUnloadUnitsTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitUnloadUnitsTypeInfo& CUnitUnloadUnitsTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitUnloadUnitsTypeInfo*>(gCUnitUnloadUnitsTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCUnitUnloadUnitsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitUnloadUnits));
    }
    return cached;
  }

  /**
   * Address: 0x00627DC0 (FUN_00627DC0, Moho::CUnitUnloadUnitsTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitUnloadUnits` instance.
   */
  void DeleteCUnitUnloadUnitsOwned(void* const objectStorage)
  {
    delete static_cast<moho::CUnitUnloadUnits*>(objectStorage);
  }

  /**
   * Address: 0x00627E50 (FUN_00627E50, Moho::CUnitUnloadUnitsTypeInfo::Dtr)
   *
   * What it does:
   * Executes one in-place `CUnitUnloadUnits` destructor lane.
   */
  void DestroyCUnitUnloadUnitsInPlace(void* const objectStorage)
  {
    auto* const task = static_cast<moho::CUnitUnloadUnits*>(objectStorage);
    if (task != nullptr) {
      task->~CUnitUnloadUnits();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00626120 (FUN_00626120, preregister_CUnitUnloadUnitsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitUnloadUnitsTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CUnitUnloadUnitsTypeInfo()
  {
    if (!gCUnitUnloadUnitsTypeInfoConstructed) {
      new (gCUnitUnloadUnitsTypeInfoStorage) CUnitUnloadUnitsTypeInfo();
      gCUnitUnloadUnitsTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CUnitUnloadUnits), &CUnitUnloadUnitsTypeInfoStorageRef());
    return &CUnitUnloadUnitsTypeInfoStorageRef();
  }

  const char* CUnitUnloadUnitsTypeInfo::GetName() const
  {
    return "CUnitUnloadUnits";
  }

  void CUnitUnloadUnitsTypeInfo::Init()
  {
    size_ = sizeof(CUnitUnloadUnits);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitUnloadUnitsTypeInfo::NewRef,
      &CUnitUnloadUnitsTypeInfo::CtrRef,
      &DeleteCUnitUnloadUnitsOwned,
      &DestroyCUnitUnloadUnitsInPlace
    );
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00627D40 (FUN_00627D40, Moho::CUnitUnloadUnitsTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitUnloadUnits` and returns a typed reflection ref.
   */
  gpg::RRef CUnitUnloadUnitsTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitUnloadUnits();
    return gpg::RRef{task, CachedCUnitUnloadUnitsType()};
  }

  /**
   * Address: 0x00627DE0 (FUN_00627DE0, Moho::CUnitUnloadUnitsTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitUnloadUnits` in caller-provided storage and returns a
   * typed reflection ref.
   */
  gpg::RRef CUnitUnloadUnitsTypeInfo::CtrRef(void* const objectStorage)
  {
    CUnitUnloadUnits* task = nullptr;
    if (objectStorage != nullptr) {
      task = new (objectStorage) CUnitUnloadUnits();
    }

    return gpg::RRef{task, CachedCUnitUnloadUnitsType()};
  }
} // namespace moho
