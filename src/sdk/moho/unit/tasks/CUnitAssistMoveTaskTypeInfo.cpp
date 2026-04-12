#include "moho/unit/tasks/CUnitAssistMoveTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitAssistMoveTask.h"

#include <cstdlib>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CUnitAssistMoveTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitAssistMoveTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F09A0 (FUN_005F09A0, ??0CUnitAssistMoveTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitAssistMoveTask` RTTI into the reflection lookup table.
   */
  CUnitAssistMoveTaskTypeInfo::CUnitAssistMoveTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitAssistMoveTask), this);
  }

  /**
   * Address: 0x005F0A50 (FUN_005F0A50, scalar deleting thunk)
   */
  CUnitAssistMoveTaskTypeInfo::~CUnitAssistMoveTaskTypeInfo() = default;

  /**
   * Address: 0x005F0A40 (FUN_005F0A40)
   */
  const char* CUnitAssistMoveTaskTypeInfo::GetName() const
  {
    return "CUnitAssistMoveTask";
  }

  /**
   * Address: 0x005F0A00 (FUN_005F0A00)
   *
   * What it does:
   * Sets the reflected size (0x68) and wires base/allocator callbacks.
   */
  void CUnitAssistMoveTaskTypeInfo::Init()
  {
    size_ = 0x68;
    newRefFunc_ = &CUnitAssistMoveTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitAssistMoveTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitAssistMoveTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitAssistMoveTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x00BCF250 (FUN_00BCF250, register_CUnitAssistMoveTaskTypeInfo)
   */
  int register_CUnitAssistMoveTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
