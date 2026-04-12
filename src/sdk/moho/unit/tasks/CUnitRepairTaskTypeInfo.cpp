#include "moho/unit/tasks/CUnitRepairTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitRepairTask.h"

#include <cstdlib>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CUnitRepairTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitRepairTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F9000 (FUN_005F9000, ??0CUnitRepairTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitRepairTask` RTTI into the reflection lookup table.
   */
  CUnitRepairTaskTypeInfo::CUnitRepairTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitRepairTask), this);
  }

  /**
   * Address: 0x005F90C0 (FUN_005F90C0, scalar deleting thunk)
   */
  CUnitRepairTaskTypeInfo::~CUnitRepairTaskTypeInfo() = default;

  /**
   * Address: 0x005F90B0 (FUN_005F90B0)
   */
  const char* CUnitRepairTaskTypeInfo::GetName() const
  {
    return "CUnitRepairTask";
  }

  /**
   * Address: 0x005F9060 (FUN_005F9060)
   *
   * What it does:
   * Sets the reflected size (0x9C) and wires base/allocator callbacks.
   */
  void CUnitRepairTaskTypeInfo::Init()
  {
    size_ = 0x9C;
    newRefFunc_ = &CUnitRepairTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitRepairTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitRepairTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitRepairTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00BCF930 (FUN_00BCF930, register_CUnitRepairTaskTypeInfo)
   */
  int register_CUnitRepairTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
