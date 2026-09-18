#include "moho/unit/tasks/CUnitWaitForFerryTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitWaitForFerryTask.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitWaitForFerryTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitWaitForFerryTaskTypeInfo();
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

  [[nodiscard]] gpg::RType* CachedCUnitWaitForFerryTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitWaitForFerryTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitWaitForFerryTaskRef(moho::CUnitWaitForFerryTask* const object)
  {
    return gpg::RRef{object, CachedCUnitWaitForFerryTaskType()};
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
    auto* const object = static_cast<moho::CUnitWaitForFerryTask*>(objectStorage);
    if (object) {
      new (object) moho::CUnitWaitForFerryTask();
    }
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

  int register_CUnitWaitForFerryTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitWaitForFerryTaskTypeInfo_a0b296, moho::register_CUnitWaitForFerryTaskTypeInfo)
