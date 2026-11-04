#include "moho/unit/tasks/CUnitWaitForFerryTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitWaitForFerryTaskTypeInfo;

  /**
   * Address: 0x00BF9DD0 (FUN_00BF9DD0, atexit destructor of the CUnitWaitForFerryTaskTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RRef MakeCUnitWaitForFerryTaskRef(moho::CUnitWaitForFerryTask* const object)
  {
    return gpg::RRef{object, gpg::RTypeOf<moho::CUnitWaitForFerryTask>()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060F830 (FUN_0060F830)
   */
  CUnitWaitForFerryTaskTypeInfo::CUnitWaitForFerryTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(moho::CUnitWaitForFerryTask), this);
  }

  /**
   * Address: 0x0060F8E0 (FUN_0060F8E0, scalar deleting thunk)
   */
  CUnitWaitForFerryTaskTypeInfo::~CUnitWaitForFerryTaskTypeInfo() = default;

  /**
   * Address: 0x0060F8D0 (FUN_0060F8D0)
   */
  const char* CUnitWaitForFerryTaskTypeInfo::GetName() const
  {
    return "moho::CUnitWaitForFerryTask";
  }

  /**
   * Address: 0x0060F890 (FUN_0060F890)
   */
  void CUnitWaitForFerryTaskTypeInfo::Init()
  {
    size_ = sizeof(moho::CUnitWaitForFerryTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitWaitForFerryTaskTypeInfo::NewRef,
      &CUnitWaitForFerryTaskTypeInfo::CtrRef,
      &CUnitWaitForFerryTaskTypeInfo::Delete,
      &CUnitWaitForFerryTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00610530 (FUN_00610530, Moho::CUnitWaitForFerryTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitWaitForFerryTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
  }

  /**
   * Address: 0x00610340 (FUN_00610340, Moho::CUnitWaitForFerryTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitWaitForFerryTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitWaitForFerryTask();
    return MakeCUnitWaitForFerryTaskRef(object);
  }

  /**
   * Address: 0x00610400 (FUN_00610400, Moho::CUnitWaitForFerryTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one wait-for-ferry task runtime lane in caller
   * storage and returns typed reflection reference.
   */
  gpg::RRef CUnitWaitForFerryTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = gpg::ConstructInStorage<moho::CUnitWaitForFerryTask>(objectStorage);
    return MakeCUnitWaitForFerryTaskRef(object);
  }

  /**
   * Address: 0x006103E0 (FUN_006103E0, Moho::CUnitWaitForFerryTaskTypeInfo::Delete)
   */
  void CUnitWaitForFerryTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitWaitForFerryTask*>(objectStorage);
  }

  /**
   * Address: 0x006104A0 (FUN_006104A0, Moho::CUnitWaitForFerryTaskTypeInfo::Destruct)
   */
  void CUnitWaitForFerryTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitWaitForFerryTask*>(objectStorage);
    if (!object) {
      return;
    }

    std::destroy_at(object);
  }

  /**
   * Address: 0x00BD0940 (FUN_00BD0940, register_CUnitWaitForFerryTaskTypeInfo)
   */
  void register_CUnitWaitForFerryTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitWaitForFerryTaskTypeInfo_a0b296, moho::register_CUnitWaitForFerryTaskTypeInfo)
