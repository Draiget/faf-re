#include "moho/unit/tasks/CUnitGetBuiltTaskTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/unit/tasks/CUnitGetBuiltTask.h"

namespace
{
  using TypeInfo = moho::CUnitGetBuiltTaskTypeInfo;

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

    AcquireTypeInfo().~CUnitGetBuiltTaskTypeInfo();
    gTypeInfoConstructed = false;
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
} // namespace

namespace moho
{
  /**
   * Address: 0x0060A5A0 (FUN_0060A5A0)
   * Mangled: ?0CUnitGetBuiltTaskTypeInfo@Moho@@QAE@@Z
   *
   * What it does:
   * Preregisters `CUnitGetBuiltTask` RTTI into the reflection lookup table.
   */
  CUnitGetBuiltTaskTypeInfo::CUnitGetBuiltTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitGetBuiltTask), this);
  }

  /**
   * Address: 0x0060A650 (FUN_0060A650, scalar deleting thunk)
   */
  CUnitGetBuiltTaskTypeInfo::~CUnitGetBuiltTaskTypeInfo() = default;

  /**
   * Address: 0x0060A640 (FUN_0060A640)
   */
  const char* CUnitGetBuiltTaskTypeInfo::GetName() const
  {
    return "CUnitGetBuiltTask";
  }

  /**
   * Address: 0x0060A600 (FUN_0060A600)
   *
   * What it does:
   * Sets the reflected size (0x30) and wires base/allocator callbacks.
   */
  void CUnitGetBuiltTaskTypeInfo::Init()
  {
    size_ = 0x30;
    newRefFunc_ = &CUnitGetBuiltTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitGetBuiltTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitGetBuiltTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitGetBuiltTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060A600 (FUN_0060A600, AddBase_CCommandTask lane)
   *
   * What it does:
   * Registers `CCommandTask` as reflection base for `CUnitGetBuiltTask`.
   */
  void CUnitGetBuiltTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCCommandTaskType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD05D0 (FUN_00BD05D0, register_CUnitGetBuiltTaskTypeInfo)
   */
  int register_CUnitGetBuiltTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
