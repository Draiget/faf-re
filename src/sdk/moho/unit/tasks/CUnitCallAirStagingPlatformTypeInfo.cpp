#include "moho/unit/tasks/CUnitCallAirStagingPlatformTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallAirStagingPlatform.h"

namespace
{
  using TypeInfo = moho::CUnitCallAirStagingPlatformTypeInfo;

  alignas(TypeInfo) unsigned char gCUnitCallAirStagingPlatformTypeInfoStorage[sizeof(TypeInfo)];
  bool gCUnitCallAirStagingPlatformTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCUnitCallAirStagingPlatformTypeInfoConstructed) {
      new (gCUnitCallAirStagingPlatformTypeInfoStorage) TypeInfo();
      gCUnitCallAirStagingPlatformTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCUnitCallAirStagingPlatformTypeInfoStorage);
  }

  void InitializeAirStagingRuntimeState(moho::CUnitCallAirStagingPlatform* const task)
  {
    task->mPlatform.ownerLinkSlot = nullptr;
    task->mPlatform.nextInOwner = nullptr;
    task->mDone = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00601AC0 (FUN_00601AC0)
   */
  CUnitCallAirStagingPlatformTypeInfo::CUnitCallAirStagingPlatformTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitCallAirStagingPlatform), this);
  }

  /**
   * Address: 0x00601B70 (FUN_00601B70, scalar deleting destructor thunk)
   */
  CUnitCallAirStagingPlatformTypeInfo::~CUnitCallAirStagingPlatformTypeInfo() = default;

  /**
   * Address: 0x00601B60 (FUN_00601B60)
   */
  const char* CUnitCallAirStagingPlatformTypeInfo::GetName() const
  {
    return "CUnitCallAirStagingPlatform";
  }

  /**
   * Address: 0x00601B20 (FUN_00601B20)
   */
  void CUnitCallAirStagingPlatformTypeInfo::Init()
  {
    size_ = sizeof(CUnitCallAirStagingPlatform);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitCallAirStagingPlatformTypeInfo::NewRef,
      &CUnitCallAirStagingPlatformTypeInfo::CtrRef,
      &CUnitCallAirStagingPlatformTypeInfo::Delete,
      &CUnitCallAirStagingPlatformTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00602F20 (FUN_00602F20, AddBase_CCommandTask)
   */
  void __stdcall CUnitCallAirStagingPlatformTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x00602AE0 (FUN_00602AE0)
   */
  gpg::RRef CUnitCallAirStagingPlatformTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCallAirStagingPlatform();
    if (task) {
      InitializeAirStagingRuntimeState(task);
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallAirStagingPlatform))};
  }

  /**
   * Address: 0x00602B90 (FUN_00602B90)
   */
  gpg::RRef CUnitCallAirStagingPlatformTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallAirStagingPlatform*>(objectStorage);
    if (task) {
      new (task) CUnitCallAirStagingPlatform();
      InitializeAirStagingRuntimeState(task);
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CUnitCallAirStagingPlatform))};
  }

  /**
   * Address: 0x00602B70 (FUN_00602B70)
   */
  void CUnitCallAirStagingPlatformTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitCallAirStagingPlatform*>(objectStorage);
  }

  /**
   * Address: 0x00602C10 (FUN_00602C10)
   */
  void CUnitCallAirStagingPlatformTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCallAirStagingPlatform*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitCallAirStagingPlatform();
  }

  /**
   * Address: 0x00BF9770 (FUN_00BF9770, cleanup_CUnitCallAirStagingPlatformTypeInfo)
   */
  void cleanup_CUnitCallAirStagingPlatformTypeInfo()
  {
    if (!gCUnitCallAirStagingPlatformTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCUnitCallAirStagingPlatformTypeInfoStorage);
    typeInfo.fields_.clear();
    typeInfo.bases_.clear();
  }

  /**
   * Address: 0x00BCFD60 (FUN_00BCFD60, register_CUnitCallAirStagingPlatformTypeInfo)
   */
  int register_CUnitCallAirStagingPlatformTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitCallAirStagingPlatformTypeInfo);
  }
} // namespace moho

