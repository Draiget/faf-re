#include "moho/unit/tasks/CUnitUpgradeTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitUpgradeTask.h"

namespace
{
  using TypeInfo = moho::CUnitUpgradeTaskTypeInfo;

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

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitUpgradeTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitUpgradeTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitUpgradeTaskRef(moho::CUnitUpgradeTask* const task)
  {
    return gpg::RRef{task, CachedCUnitUpgradeTaskType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F8680 (FUN_005F8680, sub_5F8680)
   */
  CUnitUpgradeTaskTypeInfo::CUnitUpgradeTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitUpgradeTask), this);
  }

  /**
   * Address: 0x005F8730 (FUN_005F8730, Moho::CUnitUpgradeTaskTypeInfo::dtr)
   */
  CUnitUpgradeTaskTypeInfo::~CUnitUpgradeTaskTypeInfo() = default;

  /**
   * Address: 0x005F8720 (FUN_005F8720, Moho::CUnitUpgradeTaskTypeInfo::GetName)
   */
  const char* CUnitUpgradeTaskTypeInfo::GetName() const
  {
    return "CUnitUpgradeTask";
  }

  /**
   * Address: 0x005F86E0 (FUN_005F86E0, Moho::CUnitUpgradeTaskTypeInfo::Init)
   */
  void CUnitUpgradeTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitUpgradeTask);
    newRefFunc_ = &CUnitUpgradeTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitUpgradeTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitUpgradeTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitUpgradeTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x005FD140 (FUN_005FD140, Moho::CUnitUpgradeTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitUpgradeTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005FC240 (FUN_005FC240, Moho::CUnitUpgradeTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitUpgradeTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitUpgradeTask();
    return MakeCUnitUpgradeTaskRef(task);
  }

  /**
   * Address: 0x005FC2E0 (FUN_005FC2E0, Moho::CUnitUpgradeTaskTypeInfo::CtrRef)
   */
  gpg::RRef CUnitUpgradeTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitUpgradeTask*>(objectStorage);
    if (task) {
      new (task) CUnitUpgradeTask();
    }
    return MakeCUnitUpgradeTaskRef(task);
  }

  /**
   * Address: 0x005FC2C0 (FUN_005FC2C0, Moho::CUnitUpgradeTaskTypeInfo::Delete)
   */
  void CUnitUpgradeTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitUpgradeTask*>(objectStorage);
  }

  /**
   * Address: 0x005FC350 (FUN_005FC350, Moho::CUnitUpgradeTaskTypeInfo::Destruct)
   */
  void CUnitUpgradeTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitUpgradeTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CUnitUpgradeTask();
  }

  /**
   * Address: 0x00BF9360 (FUN_00BF9360)
   */
  void cleanup_CUnitUpgradeTaskTypeInfo()
  {
    if (!gTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CUnitUpgradeTaskTypeInfo();
    gTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BCF8D0 (FUN_00BCF8D0, sub_BCF8D0)
   */
  int register_CUnitUpgradeTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CUnitUpgradeTaskTypeInfo);
  }
} // namespace moho

