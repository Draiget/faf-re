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

  class MOHO_EMPTY_BASES CTask : public boost::noncopyable_::noncopyable, public InstanceCounter<CTask>
  {
#if !defined(MOHO_ABI_MSVC8_COMPAT)
    // Preserve legacy base-subobject slot at +0x04 when empty-bases are collapsed.
    MOHO_EBO_PADDING_FIELD(1);
#endif

  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00408C90 (scalar deleting thunk)
     * Address: 0x00408CB0 (FUN_00408CB0, non-deleting body)
     *
     * VFTable SLOT: 0
     */
    virtual ~CTask();

    /**
     * Address: 0x00A82547 (_purecall in base)
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

  class CTaskSerializer
  {
  public:
    /**
     * Address: 0x0040A290 (FUN_0040A290, sub_40A290)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CTask RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

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

  static_assert(sizeof(CTaskSerializer) == 0x14, "CTaskSerializer size must be 0x14");
  static_assert(sizeof(CTaskTypeInfo) == 0x64, "CTaskTypeInfo size must be 0x64");

  template <class T>
  class MOHO_EMPTY_BASES CPushTask : public CTask
  {
  public:
    CPushTask();

  private:
    int32_t padding0_;
  };
  static_assert(sizeof(CPushTask<void>) == 0x1C, "size of CPushTask must be 0x1C");

  template <class T>
  CPushTask<T>::CPushTask()
    : CTask(new CTaskThread(WIN_GetBeforeWaitStage()), false)
  {}

  template <class T>
  class MOHO_EMPTY_BASES CPullTask : public CTask
  {
  public:
    CPullTask();
  };
  static_assert(sizeof(CPullTask<void>) == 0x18, "size of CPullTask must be 0x18");

  template <class T>
  CPullTask<T>::CPullTask()
    : CTask(new CTaskThread(WIN_GetBeforeEventsStage()), false)
  {}
} // namespace moho
