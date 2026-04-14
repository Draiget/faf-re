#include "moho/unit/tasks/CUnitFireAtTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitFireAtTask.h"

namespace
{
  using TypeInfo = moho::CUnitFireAtTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitFireAtTaskRuntimeView final : moho::CCommandTask
  {
    moho::CCommandTask* mDispatchTask = nullptr;                       // +0x30
    moho::EAiTargetType mTargetType = static_cast<moho::EAiTargetType>(0); // +0x34
    moho::WeakPtr<moho::Entity> mTargetEntity{};                       // +0x38
    std::uint8_t mTargetPositionBytes[0x0C];                           // +0x40 (left as-is by binary CtrRef lane)
    std::int32_t mTargetPoint = -1;                                    // +0x4C
    bool mTargetIsMobile = false;                                      // +0x50
    std::uint8_t mTargetPad51_53[3] = {0, 0, 0};
    moho::UnitWeapon* mWeapon = nullptr; // +0x54
    std::int32_t mIsNuclear = 0;         // +0x58

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitFireAtTaskRuntimeView) == sizeof(moho::CUnitFireAtTask),
    "CUnitFireAtTaskRuntimeView size must match CUnitFireAtTask"
  );
  static_assert(
    offsetof(CUnitFireAtTaskRuntimeView, mDispatchTask) == offsetof(moho::CUnitFireAtTask, mDispatch),
    "CUnitFireAtTaskRuntimeView::mDispatchTask offset must match CUnitFireAtTask"
  );
  static_assert(offsetof(CUnitFireAtTaskRuntimeView, mTargetType) == 0x34, "CUnitFireAtTaskRuntimeView::mTargetType offset must be 0x34");
  static_assert(offsetof(CUnitFireAtTaskRuntimeView, mTargetPoint) == 0x4C, "CUnitFireAtTaskRuntimeView::mTargetPoint offset must be 0x4C");
  static_assert(
    offsetof(CUnitFireAtTaskRuntimeView, mWeapon) == offsetof(moho::CUnitFireAtTask, mWeapon),
    "CUnitFireAtTaskRuntimeView::mWeapon offset must match CUnitFireAtTask"
  );
  static_assert(
    offsetof(CUnitFireAtTaskRuntimeView, mIsNuclear) == offsetof(moho::CUnitFireAtTask, mIsNuclear),
    "CUnitFireAtTaskRuntimeView::mIsNuclear offset must match CUnitFireAtTask"
  );

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

    AcquireTypeInfo().~CUnitFireAtTaskTypeInfo();
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

  [[nodiscard]] gpg::RType* CachedCUnitFireAtTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitFireAtTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitFireAtTaskRef(CUnitFireAtTaskRuntimeView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitFireAtTask*>(object), CachedCUnitFireAtTaskType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060AFA0 (FUN_0060AFA0)
   */
  CUnitFireAtTaskTypeInfo::CUnitFireAtTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitFireAtTask), this);
  }

  /**
   * Address: 0x0060B050 (FUN_0060B050, scalar deleting thunk)
   */
  CUnitFireAtTaskTypeInfo::~CUnitFireAtTaskTypeInfo() = default;

  /**
   * Address: 0x0060B040 (FUN_0060B040)
   */
  const char* CUnitFireAtTaskTypeInfo::GetName() const
  {
    return "CUnitFireAtTask";
  }

  /**
   * Address: 0x0060B000 (FUN_0060B000)
   */
  void CUnitFireAtTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitFireAtTask);
    newRefFunc_ = &CUnitFireAtTaskTypeInfo::NewRef;
    ctorRefFunc_ = &CUnitFireAtTaskTypeInfo::CtrRef;
    deleteFunc_ = &CUnitFireAtTaskTypeInfo::Delete;
    dtrFunc_ = &CUnitFireAtTaskTypeInfo::Destruct;
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060C720 (FUN_0060C720, Moho::CUnitFireAtTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitFireAtTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x0060C0B0 (FUN_0060C0B0, Moho::CUnitFireAtTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitFireAtTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitFireAtTaskRuntimeView();
    return MakeCUnitFireAtTaskRef(object);
  }

  /**
   * Address: 0x0060C170 (FUN_0060C170, Moho::CUnitFireAtTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one fire-at-task runtime lane in caller storage and
   * returns typed reflection reference.
   */
  gpg::RRef CUnitFireAtTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitFireAtTaskRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitFireAtTaskRuntimeView();
    }
    return MakeCUnitFireAtTaskRef(object);
  }

  /**
   * Address: 0x0060C150 (FUN_0060C150, Moho::CUnitFireAtTaskTypeInfo::Delete)
   */
  void CUnitFireAtTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitFireAtTaskRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x0060C200 (FUN_0060C200, Moho::CUnitFireAtTaskTypeInfo::Destruct)
   */
  void CUnitFireAtTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitFireAtTaskRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitFireAtTaskRuntimeView();
  }

  int register_CUnitFireAtTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho

