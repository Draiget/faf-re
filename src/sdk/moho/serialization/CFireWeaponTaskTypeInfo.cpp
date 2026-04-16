#include "moho/serialization/CFireWeaponTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/task/CTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"

namespace
{
  using TypeInfo = moho::CFireWeaponTaskTypeInfo;

  alignas(TypeInfo) unsigned char gCFireWeaponTaskTypeInfoStorage[sizeof(TypeInfo)];
  bool gCFireWeaponTaskTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCFireWeaponTaskTypeInfoConstructed) {
      new (gCFireWeaponTaskTypeInfoStorage) TypeInfo();
      gCFireWeaponTaskTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCFireWeaponTaskTypeInfoStorage);
  }

  void cleanup_CFireWeaponTaskTypeInfo_00BFE6B0_Impl()
  {
    if (!gCFireWeaponTaskTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<TypeInfo*>(gCFireWeaponTaskTypeInfoStorage);
    typeInfo.fields_.clear();
    typeInfo.bases_.clear();
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x006D3AF0 (FUN_006D3AF0, Moho::CFireWeaponTaskTypeInfo::CFireWeaponTaskTypeInfo)
   */
  CFireWeaponTaskTypeInfo::CFireWeaponTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CFireWeaponTask), this);
  }

  /**
   * Address: 0x006D3BA0 (FUN_006D3BA0, scalar deleting destructor thunk)
   */
  CFireWeaponTaskTypeInfo::~CFireWeaponTaskTypeInfo() = default;

  /**
   * Address: 0x006D3B90 (FUN_006D3B90, ?GetName@CFireWeaponTaskTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* CFireWeaponTaskTypeInfo::GetName() const
  {
    return "CFireWeaponTask";
  }

  /**
   * Address: 0x006D3B50 (FUN_006D3B50, ?Init@CFireWeaponTaskTypeInfo@Moho@@UAEXXZ)
   */
  void CFireWeaponTaskTypeInfo::Init()
  {
    size_ = sizeof(CFireWeaponTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CFireWeaponTaskTypeInfo::NewRef,
      &CFireWeaponTaskTypeInfo::CtrRef,
      &CFireWeaponTaskTypeInfo::Delete,
      &CFireWeaponTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CTask(this);
    Finish();
  }

  /**
   * Address: 0x006DD350 (FUN_006DD350, Moho::CFireWeaponTaskTypeInfo::AddBase_CTask)
   */
  void __stdcall CFireWeaponTaskTypeInfo::AddBase_CTask(gpg::RType* const typeInfo)
  {
    gpg::RType* taskType = CTask::sType;
    if (!taskType) {
      taskType = gpg::LookupRType(typeid(CTask));
      CTask::sType = taskType;
    }

    GPG_ASSERT(taskType != nullptr);
    gpg::RField baseField{};
    baseField.mName = taskType->GetName();
    baseField.mType = taskType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x006DD000 (FUN_006DD000, Moho::CFireWeaponTaskTypeInfo::NewRef)
   */
  gpg::RRef CFireWeaponTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CFireWeaponTask();
    return gpg::RRef{task, gpg::LookupRType(typeid(CFireWeaponTask))};
  }

  /**
   * Address: 0x006DD090 (FUN_006DD090, Moho::CFireWeaponTaskTypeInfo::CtrRef)
   */
  gpg::RRef CFireWeaponTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CFireWeaponTask*>(objectStorage);
    if (task) {
      new (task) CFireWeaponTask();
    }
    return gpg::RRef{task, gpg::LookupRType(typeid(CFireWeaponTask))};
  }

  /**
   * Address: 0x006DD070 (FUN_006DD070, Moho::CFireWeaponTaskTypeInfo::Delete)
   */
  void CFireWeaponTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CFireWeaponTask*>(objectStorage);
  }

  /**
   * Address: 0x006DD100 (FUN_006DD100, Moho::CFireWeaponTaskTypeInfo::Destruct)
   */
  void CFireWeaponTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CFireWeaponTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CFireWeaponTask();
  }

  /**
   * Address: 0x00BFE6B0 (FUN_00BFE6B0, cleanup)
   */
  void cleanup_CFireWeaponTaskTypeInfo()
  {
    cleanup_CFireWeaponTaskTypeInfo_00BFE6B0_Impl();
  }

  /**
   * Address: 0x00BD8870 (FUN_00BD8870, register_CFireWeaponTaskTypeInfo)
   */
  void register_CFireWeaponTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    (void)std::atexit(&cleanup_CFireWeaponTaskTypeInfo);
  }
} // namespace moho
