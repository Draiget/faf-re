#include "moho/unit/tasks/CUnitFireAtTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitFireAtTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitFireAtTaskTypeInfo;

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

  void cleanup()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitFireAtTaskTypeInfo();
    gTypeInfoConstructed = false;
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

  [[nodiscard]] gpg::RType* CachedCUnitFireAtTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitFireAtTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitFireAtTaskRef(moho::CUnitFireAtTask* const object)
  {
    return gpg::RRef{object, CachedCUnitFireAtTaskType()};
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
    auto* const object = static_cast<moho::CUnitFireAtTask*>(objectStorage);
    if (object) {
      new (object) moho::CUnitFireAtTask();
    }
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

  int register_CUnitFireAtTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitFireAtTaskTypeInfo_3917a7, moho::register_CUnitFireAtTaskTypeInfo)
