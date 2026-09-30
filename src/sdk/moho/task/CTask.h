#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostUtils.h"
#include "moho/app/WinApp.h"
#include "moho/misc/InstanceCounter.h"
#include "platform/Platform.h"

namespace moho
{
  enum ETaskState
  {
    TASKSTATE_Preparing = 0x0,
    TASKSTATE_Waiting = 0x1,
    TASKSTATE_Starting = 0x2,
    TASKSTATE_Processing = 0x3,
    TASKSTATE_Complete = 0x4,
    TASKSTATE_5 = 0x5,
    TASKSTATE_6 = 0x6,
    TASKSTATE_7 = 0x7,
    TASKSTATE_8 = 0x8,
  };

  class CTaskThread;
  class CTaskStage;

  class MOHO_EMPTY_BASES CTask : public boost::noncopyable_::noncopyable, public InstanceCounter<CTask>
  {
#if !defined(MOHO_ABI_MSVC8_COMPAT)
    // Preserve legacy base-subobject slot at +0x04 when empty-bases are collapsed.
    MOHO_EBO_PADDING_FIELD(1);
#endif

  public:
    /**
     * What it does:
     * Saves this object's members. Inlined into `gpg::SerSaveLoadHelper<CTask>::Serialize` 0x00408E40.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * What it does:
     * Loads this object's members. Inlined into `gpg::SerSaveLoadHelper<CTask>::Deserialize` 0x00408E00.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00408C90 (FUN_00408C90, scalar deleting thunk)
     * Address: 0x00408CB0 (FUN_00408CB0, non-deleting body)
     *
     * VFTable SLOT: 0
     */
    virtual ~CTask();

    /**
     * Address: 0x00A82547 (FUN_00A82547, _purecall in base)
     *
     * VFTable SLOT: 1
     */
    virtual int Execute() = 0;

    /**
     * Address: 0x00408C40 (FUN_00408C40, ??0CTask@Moho@@QAE@PAVCTaskThread@1@_N@Z)
     */
    CTask(CTaskThread* thread, bool owning);

    /**
     * Address: 0x00408D70 (FUN_00408D70, ?TaskInterruptSubtasks@CTask@Moho@@QAEXXZ)
     *
     * What it does:
     * Removes and optionally deletes all subtasks above `this` in the owning thread stack.
     */
    void TaskInterruptSubtasks();

    /**
     * Address: 0x00408DB0 (FUN_00408DB0, ?TaskResume@CTask@Moho@@QAEX_NH@Z)
     *
     * What it does:
     * Sets thread pending counter, unstages thread when needed, and optionally
     * interrupts subtasks recursively.
     */
    void TaskResume(bool recursiveInterrupt, int pendingFrames);

    /**
     * Address: 0x00409A40 (FUN_00409A40, Moho::CTask::CreateTaskThread)
     *
     * IDA signature:
     * Moho::CTaskThread *__userpurge Moho::CTask::CreateTaskThread@<eax>(
     *         Moho::CTask *dispatch@<esi>, Moho::CTaskStage *stage@<edi>, bool own);
     *
     * What it does:
     * Allocates one `CTaskThread` on `stage` and pushes `dispatch` onto that
     * thread's task stack, preserving the previous top in `dispatch->mSubtask`.
     * `own` becomes the task's auto-delete flag, so the thread destroys the
     * task when it unwinds.
     */
    static CTaskThread* CreateTaskThread(CTask* dispatch, CTaskStage* stage, bool own);

  public:
    bool* mDestroyFlag{nullptr};        // 0x08
    CTaskThread* mOwnerThread{nullptr}; // 0x0C
    CTask* mSubtask{nullptr};           // 0x10 (task stack link)
    bool mAutoDelete{false};            // 0x14
    // 0x15..0x17: layout alignment bytes (no direct task-path field accesses recovered).
    std::uint8_t mAlignmentPad15[3]{};
  };

  static_assert(sizeof(CTask) == 0x18, "size of CTask must be 0x18");
  static_assert(offsetof(CTask, mDestroyFlag) == 0x08, "CTask::mDestroyFlag offset must be 0x08");
  static_assert(offsetof(CTask, mOwnerThread) == 0x0C, "CTask::mOwnerThread offset must be 0x0C");
  static_assert(offsetof(CTask, mSubtask) == 0x10, "CTask::mSubtask offset must be 0x10");
  static_assert(offsetof(CTask, mAutoDelete) == 0x14, "CTask::mAutoDelete offset must be 0x14");

  /**
   * Address: 0x004CC750 (FUN_004CC750)
   *
   * What it does:
   * Loads one `CTask` base lane through reflected type metadata.
   */
  void ReadCTaskBase(gpg::ReadArchive* archive, void* object, const gpg::RRef& ownerRef);

  /**
   * Address: 0x004CC780 (FUN_004CC780)
   *
   * What it does:
   * Saves one `CTask` base lane through reflected type metadata.
   */
  void WriteCTaskBase(gpg::WriteArchive* archive, const void* object, const gpg::RRef& ownerRef);

  class CTaskTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00408B90 (FUN_00408B90, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CTaskTypeInfo() override;

    /**
     * Address: 0x00408B80 (FUN_00408B80, ?GetName@CTaskTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00408B60 (FUN_00408B60, ?Init@CTaskTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CTaskTypeInfo) == 0x64, "CTaskTypeInfo size must be 0x64");

  template <class T>
  class MOHO_EMPTY_BASES CPushTask : public CTask
  {
  public:
    /**
     * Address: 0x007C8650 (FUN_007C8650, ??0CPushTask_CDiscoveryService@Moho@@QAE@@Z)
     * Address: 0x007C8B50 (FUN_007C8B50, ??0?$CPushTask@VCLobby@Moho@@@Moho@@QAE@XZ)
     *
     * What it does:
     * Recovered constructor path shared by `CPushTask<T>` instantiations.
     */
    CPushTask();

    /**
     * Address: 0x007C8BF0 (FUN_007C8BF0, CPushTask<CLobby>::Execute, vtable 0x00E3ED70 slot 1)
     *
     * What it does:
     * The before-wait stage's task body: the owner's push phase, then stay
     * scheduled. A class with both a push and a pull task gets one `Execute`
     * per task, so a push phase that destroys its owner (a lobby launching)
     * never runs the pull phase on the freed object.
     */
    int Execute() override
    {
      static_cast<T*>(this)->PushTask();
      return 1;
    }

  private:
    int32_t padding0_;
  };
  // Sizes are asserted next to each owner (CLobby.h, CGpgNetInterface.h):
  // `Execute` calls into the owner, so `CPushTask<void>` no longer compiles.

  template <class T>
  /**
   * Address: 0x007C8650 (FUN_007C8650, CPushTask<CDiscoveryService> specialization)
   * Address: 0x007C8B50 (FUN_007C8B50, CPushTask<CLobby> specialization)
   *
   * What it does:
   * Builds a `CTaskThread` on the before-wait stage and links this task as the
   * thread top, preserving existing subtask chaining.
   */
  CPushTask<T>::CPushTask()
    : CTask(new CTaskThread(&WIN_GetBeforeWaitStage()), false)
  {}

  template <class T>
  class MOHO_EMPTY_BASES CPullTask : public CTask
  {
  public:
    /**
     * Address: 0x007BB1B0 (FUN_007BB1B0, ??0CPullTask_CGpgNetInterface@Moho@@QAE@@Z)
     * Address: 0x007C8590 (FUN_007C8590, ??0CPullTask_CDiscoveryService@Moho@@QAE@@Z)
     * Address: 0x007C8C10 (FUN_007C8C10, ??0?$CPullTask@VCLobby@Moho@@@Moho@@QAE@XZ)
     *
     * What it does:
     * Recovered constructor path shared by `CPullTask<T>` instantiations.
     */
    CPullTask();

    /**
     * Address: 0x007C8CB0 (FUN_007C8CB0, CPullTask<CLobby>::Execute)
     * Address: 0x007BB250 (FUN_007BB250, CPullTask<CGpgNetInterface>::Execute)
     *
     * What it does:
     * The before-events stage's task body: the owner's pull phase, then stay
     * scheduled.
     */
    int Execute() override
    {
      static_cast<T*>(this)->PullTask();
      return 1;
    }
  };

  template <class T>
  /**
   * Address: 0x007BB1B0 (FUN_007BB1B0, CPullTask<CGpgNetInterface> specialization)
   * Address: 0x007C8590 (FUN_007C8590, CPullTask<CDiscoveryService> specialization)
   * Address: 0x007C8C10 (FUN_007C8C10, CPullTask<CLobby> specialization)
   *
   * What it does:
   * Builds a `CTaskThread` on the before-events stage and links this task as the
   * thread top, preserving existing subtask chaining.
   */
  CPullTask<T>::CPullTask()
    : CTask(new CTaskThread(&WIN_GetBeforeEventsStage()), false)
  {}

  /**
   * Address: 0x00BC2FC0 (FUN_00BC2FC0, register_CTaskTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskTypeInfo` descriptor.
   */
  void register_CTaskTypeInfo();
} // namespace moho
