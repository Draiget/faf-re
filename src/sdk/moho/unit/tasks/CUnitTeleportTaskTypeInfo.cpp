#include "moho/unit/tasks/CUnitTeleportTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitTeleportTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitTeleportTaskTypeInfo();
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

  [[nodiscard]] gpg::RRef MakeCUnitTeleportTaskRef(moho::CUnitTeleportTask* const object)
  {
    gpg::RRef ref{};
    (void)gpg::RRef_CUnitTeleportTask(&ref, object);
    return ref;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060A8B0 (FUN_0060A8B0)
   */
  CUnitTeleportTaskTypeInfo::CUnitTeleportTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(moho::CUnitTeleportTask), this);
  }

  /**
   * Address: 0x0060A960 (FUN_0060A960, scalar deleting thunk)
   */
  CUnitTeleportTaskTypeInfo::~CUnitTeleportTaskTypeInfo() = default;

  /**
   * Address: 0x0060A950 (FUN_0060A950)
   */
  const char* CUnitTeleportTaskTypeInfo::GetName() const
  {
    return "moho::CUnitTeleportTask";
  }

  /**
   * Address: 0x0060A910 (FUN_0060A910)
   */
  void CUnitTeleportTaskTypeInfo::Init()
  {
    size_ = sizeof(moho::CUnitTeleportTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitTeleportTaskTypeInfo::NewRef,
      &CUnitTeleportTaskTypeInfo::CtrRef,
      &CUnitTeleportTaskTypeInfo::Delete,
      &CUnitTeleportTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060C510 (FUN_0060C510, Moho::CUnitTeleportTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitTeleportTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x0060BF50 (FUN_0060BF50, Moho::CUnitTeleportTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitTeleportTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) moho::CUnitTeleportTask();
    return MakeCUnitTeleportTaskRef(object);
  }

  /**
   * Address: 0x0060C010 (FUN_0060C010, Moho::CUnitTeleportTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one teleport-task runtime lane in caller storage and
   * returns typed reflection reference.
   */
  gpg::RRef CUnitTeleportTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitTeleportTask*>(objectStorage);
    if (object) {
      new (object) moho::CUnitTeleportTask();
    }
    return MakeCUnitTeleportTaskRef(object);
  }

  /**
   * Address: 0x0060BFF0 (FUN_0060BFF0, Moho::CUnitTeleportTaskTypeInfo::Delete)
   */
  void CUnitTeleportTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<moho::CUnitTeleportTask*>(objectStorage);
  }

  /**
   * Address: 0x0060C0A0 (FUN_0060C0A0, Moho::CUnitTeleportTaskTypeInfo::Destruct)
   */
  void CUnitTeleportTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CUnitTeleportTask*>(objectStorage);
    if (!object) {
      return;
    }

    std::destroy_at(object);
  }

  int register_CUnitTeleportTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitTeleportTaskTypeInfo_1b405b, moho::register_CUnitTeleportTaskTypeInfo)
