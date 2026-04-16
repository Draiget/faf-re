#include "moho/unit/tasks/CUnitGetBuiltTaskTypeInfo.h"

#include <cstdlib>
#include <new>
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

  [[nodiscard]] gpg::RType* CachedCUnitGetBuiltTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitGetBuiltTask));
    }
    return cached;
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
    size_ = sizeof(CUnitGetBuiltTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitGetBuiltTaskTypeInfo::NewRef,
      &CUnitGetBuiltTaskTypeInfo::CtrRef,
      &CUnitGetBuiltTaskTypeInfo::Delete,
      &CUnitGetBuiltTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060C430 (FUN_0060C430, Moho::CUnitGetBuiltTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as reflection base for `CUnitGetBuiltTask`.
   */
  void __stdcall CUnitGetBuiltTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x0060BE20 (FUN_0060BE20, Moho::CUnitGetBuiltTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitGetBuiltTask` and tags it with the reflected runtime
   * type descriptor.
   */
  gpg::RRef CUnitGetBuiltTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitGetBuiltTask();
    return gpg::RRef{task, CachedCUnitGetBuiltTaskType()};
  }

  /**
   * Address: 0x0060BEC0 (FUN_0060BEC0, Moho::CUnitGetBuiltTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitGetBuiltTask` in caller-provided storage and tags it
   * with the reflected runtime type descriptor.
   */
  gpg::RRef CUnitGetBuiltTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitGetBuiltTask*>(objectStorage);
    if (task) {
      new (task) CUnitGetBuiltTask();
    }
    return gpg::RRef{task, CachedCUnitGetBuiltTaskType()};
  }

  /**
   * Address: 0x0060BEA0 (FUN_0060BEA0, Moho::CUnitGetBuiltTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes a `CUnitGetBuiltTask` through its deleting-destructor path.
   */
  void CUnitGetBuiltTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitGetBuiltTask*>(objectStorage);
  }

  /**
   * Address: 0x0060BF40 (FUN_0060BF40, Moho::CUnitGetBuiltTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the non-deleting `CUnitGetBuiltTask` destructor body on placement
   * storage.
   */
  void CUnitGetBuiltTaskTypeInfo::Destruct(void* const objectStorage)
  {
    static_cast<CUnitGetBuiltTask*>(objectStorage)->~CUnitGetBuiltTask();
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
