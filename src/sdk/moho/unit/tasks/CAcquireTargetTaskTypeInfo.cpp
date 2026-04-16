#include "moho/unit/tasks/CAcquireTargetTaskTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CAcquireTargetTask.h"

namespace
{
  using TypeInfo = moho::CAcquireTargetTaskTypeInfo;

  alignas(TypeInfo) unsigned char gCAcquireTargetTaskTypeInfoStorage[sizeof(TypeInfo)];
  bool gCAcquireTargetTaskTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCAcquireTargetTaskTypeInfoConstructed) {
      new (gCAcquireTargetTaskTypeInfoStorage) TypeInfo();
      gCAcquireTargetTaskTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCAcquireTargetTaskTypeInfoStorage);
  }

  void cleanup_CAcquireTargetTaskTypeInfo()
  {
    if (!gCAcquireTargetTaskTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~CAcquireTargetTaskTypeInfo();
    gCAcquireTargetTaskTypeInfoConstructed = false;
  }

  /**
   * Address: 0x005D8820 (FUN_005D8820)
   *
   * What it does:
   * Runs the in-place default construction path for one
   * `CAcquireTargetTask` instance used by type-info `NewRef`/`CtrRef`.
   */
  [[nodiscard]] moho::CAcquireTargetTask* ConstructAcquireTargetTaskInPlace(void* const objectStorage)
  {
    if (objectStorage == nullptr) {
      return nullptr;
    }

    return ::new (objectStorage) moho::CAcquireTargetTask(nullptr, nullptr);
  }

  /**
   * Address: 0x005DC140 (FUN_005DC140)
   *
   * What it does:
   * Assigns all lifecycle callback slots (`NewRef`, `CtrRef`, `Delete`,
   * `Destruct`) on one `CAcquireTargetTaskTypeInfo` descriptor.
   */
  [[maybe_unused]] [[nodiscard]] moho::CAcquireTargetTaskTypeInfo* AssignAcquireTargetTaskLifecycleCallbacks(
    moho::CAcquireTargetTaskTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->newRefFunc_ = &moho::CAcquireTargetTaskTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &moho::CAcquireTargetTaskTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &moho::CAcquireTargetTaskTypeInfo::Delete;
    typeInfo->dtrFunc_ = &moho::CAcquireTargetTaskTypeInfo::Destruct;
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005D86A0 (FUN_005D86A0, ??0CAcquireTargetTaskTypeInfo@Moho@@QAE@@Z)
   */
  CAcquireTargetTaskTypeInfo::CAcquireTargetTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CAcquireTargetTask), this);
  }

  /**
   * Address: 0x005D8760 (FUN_005D8760, scalar deleting thunk)
   */
  CAcquireTargetTaskTypeInfo::~CAcquireTargetTaskTypeInfo() = default;

  /**
   * Address: 0x005D8750 (FUN_005D8750)
   */
  const char* CAcquireTargetTaskTypeInfo::GetName() const
  {
    return "CAcquireTargetTask";
  }

  /**
   * Address: 0x005D8700 (FUN_005D8700)
   */
  void CAcquireTargetTaskTypeInfo::Init()
  {
    size_ = sizeof(CAcquireTargetTask);
    (void)AssignAcquireTargetTaskLifecycleCallbacks(this);
    gpg::RType::Init();
    AddBase_CTask(this);
    AddBase_ManyToOneListener_EProjectileImpactEvent(this);
    AddBase_ManyToOneListener_ECollisionBeamEvent(this);
    Finish();
  }

  /**
   * Address: 0x005DEE50 (FUN_005DEE50, AddBase_CTask)
   */
  void CAcquireTargetTaskTypeInfo::AddBase_CTask(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = CTask::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(CTask));
      CTask::sType = baseType;
    }

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x005DEEB0 (FUN_005DEEB0, AddBase_ManyToOneListener_EProjectileImpactEvent)
   */
  void CAcquireTargetTaskTypeInfo::AddBase_ManyToOneListener_EProjectileImpactEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = ManyToOneListener_EProjectileImpactEvent::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(ManyToOneListener_EProjectileImpactEvent));
      ManyToOneListener_EProjectileImpactEvent::sType = baseType;
    }

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0x18;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x005DEF10 (FUN_005DEF10, AddBase_ManyToOneListener_ECollisionBeamEvent)
   */
  void CAcquireTargetTaskTypeInfo::AddBase_ManyToOneListener_ECollisionBeamEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* baseType = ManyToOneListener_ECollisionBeamEvent::sType;
    if (!baseType) {
      baseType = gpg::LookupRType(typeid(ManyToOneListener_ECollisionBeamEvent));
      ManyToOneListener_ECollisionBeamEvent::sType = baseType;
    }

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0x20;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x005DD990 (FUN_005DD990, NewRef)
   */
  gpg::RRef CAcquireTargetTaskTypeInfo::NewRef()
  {
    void* const storage = ::operator new(sizeof(CAcquireTargetTask), std::nothrow);
    auto* const task = ConstructAcquireTargetTaskInPlace(storage);
    return gpg::RRef{task, gpg::LookupRType(typeid(CAcquireTargetTask))};
  }

  /**
   * Address: 0x005DDA20 (FUN_005DDA20, CtrRef)
   */
  gpg::RRef CAcquireTargetTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = ConstructAcquireTargetTaskInPlace(objectStorage);
    return gpg::RRef{task, gpg::LookupRType(typeid(CAcquireTargetTask))};
  }

  /**
   * Address: 0x005DDA00 (FUN_005DDA00, Delete)
   */
  void CAcquireTargetTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CAcquireTargetTask*>(objectStorage);
  }

  /**
   * Address: 0x005DDA90 (FUN_005DDA90, Destruct)
   */
  void CAcquireTargetTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CAcquireTargetTask*>(objectStorage);
    if (!task) {
      return;
    }

    task->~CAcquireTargetTask();
  }

  /**
   * Address: 0x00BCE910 (FUN_00BCE910, register_CAcquireTargetTaskTypeInfo)
   */
  int register_CAcquireTargetTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CAcquireTargetTaskTypeInfo);
  }
} // namespace moho
