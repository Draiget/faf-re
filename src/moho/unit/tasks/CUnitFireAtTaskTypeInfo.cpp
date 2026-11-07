#include "moho/unit/tasks/CUnitFireAtTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitFireAtTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitFireAtTaskTypeInfo;

  /**
   * Address: 0x00BF9C90 (FUN_00BF9C90, atexit destructor of the CUnitFireAtTaskTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  [[nodiscard]] gpg::RRef MakeCUnitFireAtTaskRef(moho::CUnitFireAtTask* const object)
  {
    return gpg::RRef{object, gpg::RTypeOf<moho::CUnitFireAtTask>()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060AFA0 (FUN_0060AFA0)
   */
  CUnitFireAtTaskTypeInfo::CUnitFireAtTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(moho::CUnitFireAtTask), this);
  }

  /**
   * Address: 0x0060B050 (FUN_0060B050, scalar deleting thunk)
   */
  CUnitFireAtTaskTypeInfo::~CUnitFireAtTaskTypeInfo() = default;

  /**
   * Address: 0x0060B040 (FUN_0060B040)
   */
  const char* CUnitFireAtTaskTypeInfo::GetName() const
  {
    return "moho::CUnitFireAtTask";
  }

  /**
   * Address: 0x0060B000 (FUN_0060B000)
   */
  void CUnitFireAtTaskTypeInfo::Init()
  {
    size_ = sizeof(moho::CUnitFireAtTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitFireAtTaskTypeInfo::NewRef,
      &CUnitFireAtTaskTypeInfo::CtrRef,
      &CUnitFireAtTaskTypeInfo::Delete,
      &CUnitFireAtTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060C720 (FUN_0060C720, Moho::CUnitFireAtTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitFireAtTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::AddReflectedBase<moho::CCommandTask>(typeInfo);
  }

  /**
   * Address: 0x0060C0B0 (FUN_0060C0B0, Moho::CUnitFireAtTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitFireAtTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitFireAtTask();
    return MakeCUnitFireAtTaskRef(object);
  }

  /**
   * Address: 0x0060C170 (FUN_0060C170, Moho::CUnitFireAtTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one fire-at-task runtime lane in caller storage and
   * returns typed reflection reference.
   */
  gpg::RRef CUnitFireAtTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = gpg::ConstructInStorage<moho::CUnitFireAtTask>(objectStorage);
    return MakeCUnitFireAtTaskRef(object);
  }

  /**
   * Address: 0x0060C150 (FUN_0060C150, Moho::CUnitFireAtTaskTypeInfo::Delete)
   */
  void CUnitFireAtTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitFireAtTask*>(objectStorage);
  }

  /**
   * Address: 0x0060C200 (FUN_0060C200, Moho::CUnitFireAtTaskTypeInfo::Destruct)
   */
  void CUnitFireAtTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitFireAtTask*>(objectStorage);
    if (!object) {
      return;
    }

    std::destroy_at(object);
  }

  /**
   * Address: 0x00BD0690 (FUN_00BD0690, register_CUnitFireAtTaskTypeInfo)
   */
  void register_CUnitFireAtTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitFireAtTaskTypeInfo_3917a7, moho::register_CUnitFireAtTaskTypeInfo)
