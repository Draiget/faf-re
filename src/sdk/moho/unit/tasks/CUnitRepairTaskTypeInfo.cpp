#include "moho/unit/tasks/CUnitRepairTaskTypeInfo.h"

#include "moho/unit/tasks/CUnitRepairTask.h"

#include <cstdlib>
#include <new>
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

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedListenerECommandEventType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Listener<moho::ECommandEvent>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitRepairTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitRepairTask));
    }
    return cached;
  }

  class CUnitRepairTaskReflectionView final
    : public moho::CCommandTask
    , public moho::CUnitRepairTaskListenerPad
    , public moho::Listener<moho::ECommandEvent>
  {
  public:
    moho::CBuildTaskHelper mBuildHelper;
    moho::CUnitCommand* mCommand;
    moho::WeakPtr<moho::Unit> mTargetUnit;
    moho::WeakPtr<moho::Unit> mBuildTargetUnit;
    bool mInPosition;
    bool mIsSilo;
    bool mGuardAssistMode;
    bool mInheritingWork;

    /**
     * Address: 0x005F8BE0 (FUN_005F8BE0, ??0CUnitRepairTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the reflection-construction `CUnitRepairTask` storage lane:
     * listener self-links, build-helper defaults, and weak-target slots.
     */
    CUnitRepairTaskReflectionView()
      : CCommandTask()
      , CUnitRepairTaskListenerPad{}
      , Listener<moho::ECommandEvent>()
      , mBuildHelper()
      , mCommand(nullptr)
      , mTargetUnit{}
      , mBuildTargetUnit{}
      , mInPosition(false)
      , mIsSilo(false)
      , mGuardAssistMode(false)
      , mInheritingWork(false)
    {
      mListenerPad = 0;
      mListenerLink.ListResetLinks();
      mTargetUnit.ClearLinkState();
      mBuildTargetUnit.ClearLinkState();
    }

    ~CUnitRepairTaskReflectionView() override
    {
      mTargetUnit.UnlinkFromOwnerChain();
      mBuildTargetUnit.UnlinkFromOwnerChain();
      mListenerLink.ListResetLinks();
    }

    int Execute() override
    {
      return -1;
    }

    void OnEvent(moho::ECommandEvent) override {}
  };

  static_assert(sizeof(CUnitRepairTaskReflectionView) == 0x9C, "CUnitRepairTaskReflectionView size must be 0x9C");
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mBuildHelper) == 0x40,
    "CUnitRepairTaskReflectionView::mBuildHelper offset must be 0x40"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mCommand) == 0x84,
    "CUnitRepairTaskReflectionView::mCommand offset must be 0x84"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mTargetUnit) == 0x88,
    "CUnitRepairTaskReflectionView::mTargetUnit offset must be 0x88"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mBuildTargetUnit) == 0x90,
    "CUnitRepairTaskReflectionView::mBuildTargetUnit offset must be 0x90"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mInPosition) == 0x98,
    "CUnitRepairTaskReflectionView::mInPosition offset must be 0x98"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mIsSilo) == 0x99, "CUnitRepairTaskReflectionView::mIsSilo offset must be 0x99"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mGuardAssistMode) == 0x9A,
    "CUnitRepairTaskReflectionView::mGuardAssistMode offset must be 0x9A"
  );
  static_assert(
    offsetof(CUnitRepairTaskReflectionView, mInheritingWork) == 0x9B,
    "CUnitRepairTaskReflectionView::mInheritingWork offset must be 0x9B"
  );

  [[nodiscard]] CUnitRepairTaskReflectionView* ToReflectionView(moho::CUnitRepairTask* const task) noexcept
  {
    return reinterpret_cast<CUnitRepairTaskReflectionView*>(task);
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
   * Sets the reflected size (0x9C) and wires base / allocator callbacks.
   */
  void CUnitRepairTaskTypeInfo::Init()
  {
    size_ = 0x9C;
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CUnitRepairTaskTypeInfo::NewRef,
      &CUnitRepairTaskTypeInfo::CtrRef,
      &CUnitRepairTaskTypeInfo::Delete,
      &CUnitRepairTaskTypeInfo::Destruct
    );
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    Finish();
  }

  /**
   * Address: 0x005FD340 (FUN_005FD340, Moho::CUnitRepairTaskTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `CCommandTask` as the primary reflection base at offset 0.
   */
  void __stdcall CUnitRepairTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
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
   * Address: 0x005FD3A0 (FUN_005FD3A0, Moho::CUnitRepairTaskTypeInfo::AddBase_Listener_ECommandEvent)
   *
   * What it does:
   * Registers `Listener<ECommandEvent>` as the secondary reflection base at
   * offset `0x34`.
   */
  void __stdcall CUnitRepairTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedListenerECommandEventType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0x34;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x005FC360 (FUN_005FC360, Moho::CUnitRepairTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one repair-task reflection object and returns its typed
   * reflection reference.
   */
  gpg::RRef CUnitRepairTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitRepairTaskReflectionView();
    return gpg::RRef{reinterpret_cast<CUnitRepairTask*>(task), CachedCUnitRepairTaskType()};
  }

  /**
   * Address: 0x005FC400 (FUN_005FC400, Moho::CUnitRepairTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one repair-task reflection object in caller-provided
   * storage and returns its typed reflection reference.
   */
  gpg::RRef CUnitRepairTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = ToReflectionView(static_cast<CUnitRepairTask*>(objectStorage));
    if (task) {
      new (task) CUnitRepairTaskReflectionView();
    }
    return gpg::RRef{reinterpret_cast<CUnitRepairTask*>(task), CachedCUnitRepairTaskType()};
  }

  /**
   * Address: 0x005FC3E0 (FUN_005FC3E0, Moho::CUnitRepairTaskTypeInfo::Delete)
   *
   * What it does:
   * Deletes one heap-owned repair-task reflection object through the deleting
   * destructor lane.
   */
  void CUnitRepairTaskTypeInfo::Delete(void* const objectStorage)
  {
    delete ToReflectionView(static_cast<CUnitRepairTask*>(objectStorage));
  }

  /**
   * Address: 0x005FC470 (FUN_005FC470, Moho::CUnitRepairTaskTypeInfo::Destruct)
   *
   * What it does:
   * Runs the non-deleting destructor lane for one repair-task reflection
   * object.
   */
  void CUnitRepairTaskTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const task = ToReflectionView(static_cast<CUnitRepairTask*>(objectStorage));
    if (!task) {
      return;
    }

    task->~CUnitRepairTaskReflectionView();
  }

  /**
   * Address: 0x00BCF930 (FUN_00BCF930, register_CUnitRepairTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitRepairTaskTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup);
  }
} // namespace moho
