#include "moho/unit/tasks/CUnitAssistMoveTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitAssistMoveTask.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/task/CCommandTask.h"

namespace
{
  using TypeInfo = moho::CUnitAssistMoveTaskTypeInfo;

  alignas(TypeInfo) unsigned char gTypeInfoStorage[sizeof(TypeInfo)];
  bool gTypeInfoConstructed = false;

  struct CUnitAssistMoveTaskTypeInfoStartupHelperLinks
  {
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
  };

  CUnitAssistMoveTaskTypeInfoStartupHelperLinks gCUnitAssistMoveTaskTypeInfoStartupHelperLinks{};

  [[nodiscard]] gpg::SerHelperBase* CUnitAssistMoveTaskTypeInfoStartupSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitAssistMoveTaskTypeInfoStartupHelperNode() noexcept
  {
    if (
      gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mNext != nullptr
      && gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mPrev != nullptr
    ) {
      gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mNext->mPrev = gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mPrev;
      gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mPrev->mNext = gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = CUnitAssistMoveTaskTypeInfoStartupSelfNode();
    gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mPrev = self;
    gCUnitAssistMoveTaskTypeInfoStartupHelperLinks.mNext = self;
    return self;
  }

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

  /**
   * Address: 0x005F0B60 (FUN_005F0B60)
   *
   * What it does:
   * Alias startup-lane thunk that unlinks one static helper-link node used by
   * `CUnitAssistMoveTaskTypeInfo` bootstrap storage and restores self-links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CUnitAssistMoveTaskTypeInfoStartupThunkA() noexcept
  {
    return UnlinkCUnitAssistMoveTaskTypeInfoStartupHelperNode();
  }

  /**
   * Address: 0x005F0B90 (FUN_005F0B90)
   *
   * What it does:
   * Secondary alias startup-lane thunk for the same
   * `CUnitAssistMoveTaskTypeInfo` helper-link unlink/reset path.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* cleanup_CUnitAssistMoveTaskTypeInfoStartupThunkB() noexcept
  {
    return UnlinkCUnitAssistMoveTaskTypeInfoStartupHelperNode();
  }

  struct CUnitAssistMoveTaskRuntimeView final : moho::CCommandTask
  {
    std::uint32_t mUnknown30 = 0;
    std::uint32_t mUnknown34 = 0;
    std::uint32_t mUnknown38 = 0;
    std::uint32_t mUnknown3C = 0;
    std::uint32_t mUnknown40 = 0;
    std::uint32_t mUnknown44 = 0;
    std::uint32_t mUnknown48 = 0;
    std::uint32_t mUnknown4C = 0;
    std::uint32_t mUnknown50 = 0;
    std::uint32_t mUnknown54 = 0;
    float mUnknown58 = 0.0f;
    float mUnknown5C = 0.0f;
    float mUnknown60 = 0.0f;
    std::uint8_t mUnknown64 = 0;
    std::uint8_t mPadding65_67[3] = {0, 0, 0};

    int Execute() override
    {
      return -1;
    }
  };

  static_assert(
    sizeof(CUnitAssistMoveTaskRuntimeView) == sizeof(moho::CUnitAssistMoveTask),
    "CUnitAssistMoveTaskRuntimeView size must match CUnitAssistMoveTask"
  );

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCUnitAssistMoveTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitAssistMoveTask));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeAssistMoveTaskRef(moho::CUnitAssistMoveTask* const task)
  {
    return gpg::RRef{task, CachedCUnitAssistMoveTaskType()};
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
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitAssistMoveTaskTypeInfo::NewRef,
      &CUnitAssistMoveTaskTypeInfo::CtrRef,
      &CUnitAssistMoveTaskTypeInfo::Delete,
      &CUnitAssistMoveTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    Finish();
  }

  /**
   * Address: 0x005F1CB0 (FUN_005F1CB0, Moho::CUnitAssistMoveTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as reflection base for `CUnitAssistMoveTask`.
   */
  void CUnitAssistMoveTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005F1B20 (FUN_005F1B20, Moho::CUnitAssistMoveTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitAssistMoveTask` and returns a typed reflection
   * reference to it.
   */
  gpg::RRef CUnitAssistMoveTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitAssistMoveTaskRuntimeView();
    return MakeAssistMoveTaskRef(reinterpret_cast<CUnitAssistMoveTask*>(task));
  }

  /**
   * Address: 0x005F1BF0 (FUN_005F1BF0, Moho::CUnitAssistMoveTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitAssistMoveTask` in caller storage and
   * returns a typed reflection reference to it.
   */
  gpg::RRef CUnitAssistMoveTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitAssistMoveTaskRuntimeView*>(objectStorage);
    if (task) {
      new (task) CUnitAssistMoveTaskRuntimeView();
    }
    return MakeAssistMoveTaskRef(reinterpret_cast<CUnitAssistMoveTask*>(task));
  }

  /**
   * Address: 0x005F1BD0 (FUN_005F1BD0, Moho::CUnitAssistMoveTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned `CUnitAssistMoveTask`.
   */
  void CUnitAssistMoveTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CUnitAssistMoveTaskRuntimeView*>(objectStorage);
  }

  /**
   * Address: 0x005F1CA0 (FUN_005F1CA0, Moho::CUnitAssistMoveTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs in-place destructor for one `CUnitAssistMoveTask` without
   * deallocating storage.
   */
  void CUnitAssistMoveTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitAssistMoveTaskRuntimeView*>(objectStorage);
    if (!task) {
      return;
    }
    task->~CUnitAssistMoveTaskRuntimeView();
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
