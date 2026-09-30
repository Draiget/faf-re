#include "moho/unit/tasks/CUnitCallTeleportTypeInfo.h"

#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CUnitCallTeleportTypeInfo;

  /**
   * Address: 0x00BF96E0 (FUN_00BF96E0, atexit destructor of the CUnitCallTeleportTypeInfo object)
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  void InitializeTeleportRuntimeState(moho::CUnitCallTeleport* const task)
  {
    task->mTargetTransportUnit.ownerLinkSlot = nullptr;
    task->mTargetTransportUnit.nextInOwner = nullptr;
    task->mCompletedSuccessfully = false;
    task->mIsOccupying = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00601090 (FUN_00601090)
   */
  CUnitCallTeleportTypeInfo::CUnitCallTeleportTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCallTeleport), this);
  }

  /**
   * Address: 0x00601140 (FUN_00601140, scalar deleting destructor thunk)
   */
  CUnitCallTeleportTypeInfo::~CUnitCallTeleportTypeInfo() = default;

  /**
   * Address: 0x00601130 (FUN_00601130)
   */
  const char* CUnitCallTeleportTypeInfo::GetName() const
  {
    return "CUnitCallTeleport";
  }

  /**
   * Address: 0x006010F0 (FUN_006010F0)
   */
  void CUnitCallTeleportTypeInfo::Init()
  {
    size_ = sizeof(CUnitCallTeleport);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCallTeleportTypeInfo::NewRef,
      &CUnitCallTeleportTypeInfo::CtrRef,
      &CUnitCallTeleportTypeInfo::Delete,
      &CUnitCallTeleportTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00602EA0 (FUN_00602EA0, AddBase_CCommandTask)
   */
  void __stdcall CUnitCallTeleportTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CCommandTask::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = baseType;
    }

    GPG_ASSERT(baseType != nullptr);
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006029A0 (FUN_006029A0)
   */
  gpg::RRef CUnitCallTeleportTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCallTeleport();
    if (task) {
      InitializeTeleportRuntimeState(task);
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallTeleport))};
  }

  /**
   * Address: 0x00602A50 (FUN_00602A50)
   */
  gpg::RRef CUnitCallTeleportTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallTeleport*>(objectStorage);
    if (task) {
      new (task) CUnitCallTeleport();
      InitializeTeleportRuntimeState(task);
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallTeleport))};
  }

  /**
   * Address: 0x00602A30 (FUN_00602A30)
   */
  void CUnitCallTeleportTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCallTeleport*>(objectStorage);
  }

  /**
   * Address: 0x00602AD0 (FUN_00602AD0)
   */
  void CUnitCallTeleportTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallTeleport*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitCallTeleport();
  }

  /**
   * Address: 0x00BCFD00 (FUN_00BCFD00, register_CUnitCallTeleportTypeInfo)
   */
  void register_CUnitCallTeleportTypeInfo()
  {
    (void)AcquireTypeInfo();
  }
} // namespace moho



// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUnitCallTeleportTypeInfo_9cf7f9, moho::register_CUnitCallTeleportTypeInfo)
