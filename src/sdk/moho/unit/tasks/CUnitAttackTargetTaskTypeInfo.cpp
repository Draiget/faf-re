#include "moho/unit/tasks/CUnitAttackTargetTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitAttackTargetTask.h"

#include <cstdlib>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CUnitAttackTargetTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitAttackTargetTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F2510 (FUN_005F2510, ??0CUnitAttackTargetTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitAttackTargetTask` RTTI into the reflection lookup table.
   */
  CUnitAttackTargetTaskTypeInfo::CUnitAttackTargetTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitAttackTargetTask), this);
  }

  /**
   * Address: 0x005F25D0 (FUN_005F25D0, scalar deleting thunk)
   */
  CUnitAttackTargetTaskTypeInfo::~CUnitAttackTargetTaskTypeInfo() = default;

  /**
   * Address: 0x005F25C0 (FUN_005F25C0)
   */
  const char* CUnitAttackTargetTaskTypeInfo::GetName() const
  {
    return "CUnitAttackTargetTask";
  }

  /**
   * Address: 0x005F2570 (FUN_005F2570)
   *
   * What it does:
   * Sets the reflected size (0x90) and wires base/allocator callbacks.
   */
  void CUnitAttackTargetTaskTypeInfo::Init()
  {
    size_ = 0x90;
    newRefFunc_ = &CUnitAttackTargetTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitAttackTargetTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitAttackTargetTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitAttackTargetTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_EAiAttackerEvent(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00BCF4A0 (FUN_00BCF4A0, register_CUnitAttackTargetTaskTypeInfo)
   */
  int register_CUnitAttackTargetTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
