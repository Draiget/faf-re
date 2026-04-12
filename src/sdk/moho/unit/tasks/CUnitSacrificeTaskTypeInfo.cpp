#include "moho/unit/tasks/CUnitSacrificeTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitSacrificeTask.h"

#include <cstdlib>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CUnitSacrificeTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitSacrificeTaskTypeInfo();
    gTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FAF60 (FUN_005FAF60, ??0CUnitSacrificeTaskTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Preregisters `CUnitSacrificeTask` RTTI into the reflection lookup table.
   */
  CUnitSacrificeTaskTypeInfo::CUnitSacrificeTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitSacrificeTask), this);
  }

  /**
   * Address: 0x005FB020 (FUN_005FB020, scalar deleting thunk)
   */
  CUnitSacrificeTaskTypeInfo::~CUnitSacrificeTaskTypeInfo() = default;

  /**
   * Address: 0x005FB010 (FUN_005FB010)
   */
  const char* CUnitSacrificeTaskTypeInfo::GetName() const
  {
    return "CUnitSacrificeTask";
  }

  /**
   * Address: 0x005FAFC0 (FUN_005FAFC0)
   *
   * What it does:
   * Sets the reflected size (0x4C) and wires base/allocator callbacks.
   */
  void CUnitSacrificeTaskTypeInfo::Init()
  {
    size_ = 0x4C;
    newRefFunc_ = &CUnitSacrificeTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitSacrificeTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitSacrificeTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitSacrificeTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x00BCF9F0 (FUN_00BCF9F0, register_CUnitSacrificeTaskTypeInfo)
   */
  int register_CUnitSacrificeTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
