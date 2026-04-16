#include "moho/unit/tasks/CUnitCallTeleportTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"

namespace
{
  using TypeInfo = moho::CUnitCallTeleportTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitCallTeleportTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCallTeleportTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCUnitCallTeleportTypeInfoConstructed) {
      new (gCUnitCallTeleportTypeInfoStorage) TypeInfo();
      gCUnitCallTeleportTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCallTeleportTypeInfoStorage);
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
    baseField.v4 = 0;
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
   * Address: 0x00BF96E0 (FUN_00BF96E0, cleanup_CUnitCallTeleportTypeInfo)
   */
  void cleanup_CUnitCallTeleportTypeInfo()
  {
    if (!gCUnitCallTeleportTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCUnitCallTeleportTypeInfoStorage);
    typeInfo.fields_.clear();
    typeInfo.bases_.clear();
  }

  /**
   * Address: 0x00BCFD00 (FUN_00BCFD00, register_CUnitCallTeleportTypeInfo)
   */
  int register_CUnitCallTeleportTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitCallTeleportTypeInfo);
  }
} // namespace moho

