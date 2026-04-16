#include "moho/unit/tasks/CUnitTeleportTaskTypeInfo.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"
#include "moho/unit/tasks/CUnitCallTeleport.h"

namespace
{
  using TypeInfo = moho::CUnitTeleportTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitTeleportTaskTypeInfoStartupHelperLinks
  {
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
  };

  CUnitTeleportTaskTypeInfoStartupHelperLinks gCUnitTeleportTaskTypeInfoStartupHelperLinks{};

  [[nodiscard]] gpg::SerHelperBase* CUnitTeleportTaskTypeInfoStartupSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gCUnitTeleportTaskTypeInfoStartupHelperLinks.mNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitTeleportTaskTypeInfoStartupHelperNode() noexcept
  {
    if (
      gCUnitTeleportTaskTypeInfoStartupHelperLinks.mNext != nullptr
      && gCUnitTeleportTaskTypeInfoStartupHelperLinks.mPrev != nullptr
    ) {
      gCUnitTeleportTaskTypeInfoStartupHelperLinks.mNext->mPrev = gCUnitTeleportTaskTypeInfoStartupHelperLinks.mPrev;
      gCUnitTeleportTaskTypeInfoStartupHelperLinks.mPrev->mNext = gCUnitTeleportTaskTypeInfoStartupHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = CUnitTeleportTaskTypeInfoStartupSelfNode();
    gCUnitTeleportTaskTypeInfoStartupHelperLinks.mPrev = self;
    gCUnitTeleportTaskTypeInfoStartupHelperLinks.mNext = self;
    return self;
  }

  struct CUnitTeleportTaskRuntimeView final : moho::CCommandTask
  {
    moho::EAiTargetType mTargetType = static_cast<moho::EAiTargetType>(0); // +0x30
    moho::WeakPtr<moho::Entity> mTargetEntity{};                            // +0x34
    std::uint8_t mTargetPositionBytes[0x0C];                                // +0x3C (left as-is by binary CtrRef lane)
    std::int32_t mTargetPoint = -1;                                          // +0x48
    bool mTargetIsMobile = false;                                            // +0x4C
    std::uint8_t mTargetPad4D_4F[3] = {0, 0, 0};
    moho::WeakPtr<moho::Unit> mTeleportBeaconUnit{}; // +0x50
    Wm3::Quaternionf mOrientation;                    // +0x58

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitTeleportTaskRuntimeView) == sizeof(moho::CUnitTeleportTask),
    "CUnitTeleportTaskRuntimeView size must match CUnitTeleportTask"
  );
  static_assert(
    offsetof(CUnitTeleportTaskRuntimeView, mTargetType) == 0x30,
    "CUnitTeleportTaskRuntimeView::mTargetType offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitTeleportTaskRuntimeView, mTargetPoint) == 0x48,
    "CUnitTeleportTaskRuntimeView::mTargetPoint offset must be 0x48"
  );
  static_assert(
    offsetof(CUnitTeleportTaskRuntimeView, mTeleportBeaconUnit) == offsetof(moho::CUnitTeleportTask, mTeleportBeaconUnit),
    "CUnitTeleportTaskRuntimeView::mTeleportBeaconUnit offset must match CUnitTeleportTask"
  );
  static_assert(
    offsetof(CUnitTeleportTaskRuntimeView, mOrientation) == offsetof(moho::CUnitTeleportTask, mOrientation),
    "CUnitTeleportTaskRuntimeView::mOrientation offset must match CUnitTeleportTask"
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

    AcquireTypeInfo().~CUnitTeleportTaskTypeInfo();
    gTypeInfoConstructed = false;
  }

  /**
   * Address: 0x0060AA60 (FUN_0060AA60)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks one static helper-link node used by
   * `CUnitTeleportTaskTypeInfo` bootstrap storage and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CUnitTeleportTaskTypeInfoStartupThunkA() noexcept
  {
    return UnlinkCUnitTeleportTaskTypeInfoStartupHelperNode();
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

  [[nodiscard]] gpg::RType* CachedCUnitTeleportTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitTeleportTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeCUnitTeleportTaskRef(CUnitTeleportTaskRuntimeView* const object)
  {
    return gpg::RRef{reinterpret_cast<moho::CUnitTeleportTask*>(object), CachedCUnitTeleportTaskType()};
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060A8B0 (FUN_0060A8B0)
   */
  CUnitTeleportTaskTypeInfo::CUnitTeleportTaskTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CUnitTeleportTask), this);
  }

  /**
   * Address: 0x0060A960 (FUN_0060A960, scalar deleting thunk)
   */
  CUnitTeleportTaskTypeInfo::~CUnitTeleportTaskTypeInfo() = default;

  /**
   * Address: 0x0060A950 (FUN_0060A950)
   */
  const char* CUnitTeleportTaskTypeInfo::GetName() const
  {
    return "CUnitTeleportTask";
  }

  /**
   * Address: 0x0060A910 (FUN_0060A910)
   */
  void CUnitTeleportTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitTeleportTask);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitTeleportTaskTypeInfo::NewRef,
      &CUnitTeleportTaskTypeInfo::CtrRef,
      &CUnitTeleportTaskTypeInfo::Delete,
      &CUnitTeleportTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x0060C510 (FUN_0060C510, Moho::CUnitTeleportTaskTypeInfo::AddBase_CCommandTask)
   */
  void __stdcall CUnitTeleportTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x0060BF50 (FUN_0060BF50, Moho::CUnitTeleportTaskTypeInfo::NewRef)
   */
  gpg::RRef CUnitTeleportTaskTypeInfo::NewRef()
  {
    auto* const object = new (std::nothrow) CUnitTeleportTaskRuntimeView();
    return MakeCUnitTeleportTaskRef(object);
  }

  /**
   * Address: 0x0060C010 (FUN_0060C010, Moho::CUnitTeleportTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one teleport-task runtime lane in caller storage and
   * returns typed reflection reference.
   */
  gpg::RRef CUnitTeleportTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitTeleportTaskRuntimeView*>(objectStorage);
    if (object) {
      new (object) CUnitTeleportTaskRuntimeView();
    }
    return MakeCUnitTeleportTaskRef(object);
  }

  /**
   * Address: 0x0060BFF0 (FUN_0060BFF0, Moho::CUnitTeleportTaskTypeInfo::Delete)
   */
  void CUnitTeleportTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitTeleportTaskRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x0060C0A0 (FUN_0060C0A0, Moho::CUnitTeleportTaskTypeInfo::Destruct)
   */
  void CUnitTeleportTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<CUnitTeleportTaskRuntimeView*>(objectStorage);
    if (!object) {
      return;
    }

    object->~CUnitTeleportTaskRuntimeView();
  }

  int register_CUnitTeleportTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
