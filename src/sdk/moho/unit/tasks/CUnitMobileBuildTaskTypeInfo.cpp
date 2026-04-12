#include "moho/unit/tasks/CUnitMobileBuildTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitMobileBuildTask.h"

#include <cstdlib>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CUnitMobileBuildTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitMobileBuildTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F68A0 (FUN_005F68A0, ??0CUnitMobileBuildTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitMobileBuildTask` RTTI into the reflection lookup table.
   */
  CUnitMobileBuildTaskTypeInfo::CUnitMobileBuildTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitMobileBuildTask), this);
  }

  /**
   * Address: 0x005F6960 (FUN_005F6960, scalar deleting thunk)
   */
  CUnitMobileBuildTaskTypeInfo::~CUnitMobileBuildTaskTypeInfo() = default;

  /**
   * Address: 0x005F6950 (FUN_005F6950)
   */
  const char* CUnitMobileBuildTaskTypeInfo::GetName() const
  {
    return "CUnitMobileBuildTask";
  }

  /**
   * Address: 0x005F6900 (FUN_005F6900)
   *
   * What it does:
   * Sets the reflected size (0xE8) and wires base/allocator callbacks.
   */
  void CUnitMobileBuildTaskTypeInfo::Init()
  {
    size_ = 0xE8;
    newRefFunc_ = &CUnitMobileBuildTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitMobileBuildTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitMobileBuildTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitMobileBuildTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00BCF870 (FUN_00BCF870, register_CUnitMobileBuildTaskTypeInfo)
   */
  int register_CUnitMobileBuildTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
