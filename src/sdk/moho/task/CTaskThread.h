#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class CTask;
  class CTaskStage;

  class CTaskThread : public TDatListItem<CTaskThread, void>, InstanceCounter<CTaskThread>
  {
  public:
    static gpg::RType* sType;

    // Head of intrusive weak-link chain (owner slot at +0x08 in CTaskThread).
    WeakPtr<CTaskThread>* mEventLinkHead; // 0x08
    CTaskStage* mStage;                   // 0x0C
    CTask* mTaskTop;                      // 0x10
    int mPendingFrames;                   // 0x14
    bool mStaged;                         // 0x18
    // 0x19..0x1B: layout alignment bytes (no direct task-path field accesses recovered).
    std::uint8_t mAlignmentPad19[3];

    /**
     * Address: 0x004090E0 (FUN_004090E0, ??1CTaskThread@Moho@@QAE@@Z)
     *
     * What it does:
     * Clears task stack, unlinks pending event-link chain, and unlinks thread
     * node from whichever stage list currently owns it.
     */
    ~CTaskThread();

    /**
     * Address: 0x00409050 (FUN_00409050, ??0CTaskThread@Moho@@QAE@@Z)
     */
    CTaskThread(CTaskStage* stage);

    /**
     * Address: 0x00409190 (FUN_00409190, ?Destroy@CTaskThread@Moho@@QAEPAVCTaskStage@2@XZ)
     */
    CTaskStage* Destroy() noexcept;

    /**
     * Address: 0x004093E0 (FUN_004093E0, ?Stage@CTaskThread@Moho@@QAEXXZ)
     */
    void Stage();

    /**
     * Address: 0x004091C0 (FUN_004091C0, ?Unstage@CTaskThread@Moho@@QAEXXZ)
     */
    void Unstage();
  };
  static_assert(sizeof(CTaskThread) == 0x1C, "CTaskThread == 0x1C");
  static_assert(offsetof(CTaskThread, mEventLinkHead) == 0x08, "CTaskThread::mEventLinkHead offset must be 0x08");
  static_assert(offsetof(CTaskThread, mStage) == 0x0C, "CTaskThread::mStage offset must be 0x0C");
  static_assert(offsetof(CTaskThread, mTaskTop) == 0x10, "CTaskThread::mTaskTop offset must be 0x10");
  static_assert(offsetof(CTaskThread, mPendingFrames) == 0x14, "CTaskThread::mPendingFrames offset must be 0x14");
  static_assert(offsetof(CTaskThread, mStaged) == 0x18, "CTaskThread::mStaged offset must be 0x18");

  class CTaskThreadConstruct
  {
  public:
    /**
     * Address: 0x0040A630 (FUN_0040A630, sub_40A630)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into CTaskThread RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CTaskThreadSerializer
  {
  public:
    /**
     * Address: 0x0040A6B0 (FUN_0040A6B0, sub_40A6B0)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CTaskThread RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CTaskThreadTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00408FA0 (FUN_00408FA0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CTaskThreadTypeInfo() override;

    /**
     * Address: 0x00408F90 (FUN_00408F90, ?GetName@CTaskThreadTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00408F70 (FUN_00408F70, ?Init@CTaskThreadTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  class CTaskStage
  {
  public:
    TDatList<CTaskThread, void> mThreads;       // 0x00
    TDatList<CTaskThread, void> mStagedThreads; // 0x08
    bool mActive{true};                         // 0x10
    // 0x11..0x13: layout alignment bytes (no direct task-path field accesses recovered).
    std::uint8_t mAlignmentPad11[3]{};

    /**
     * Address: 0x004099C0 (FUN_004099C0)
     */
    void Teardown();

    /**
     * Address: 0x00409AC0 (FUN_00409AC0)
     *
     * What it does:
     * Runs one frame for staged task threads and reconciles stage lists.
     */
    void UserFrame();
  };

  /**
   * Address context:
   * - `0x008D1B57` (`CScApp::Main`) loads this global and dispatches one
   *   per-frame user task-stage update.
   */
  extern CTaskStage* sUserStage;

  class CTaskStageSerializer
  {
  public:
    /**
     * Address: 0x0040A7F0 (FUN_0040A7F0, sub_40A7F0)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CTaskStage RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CTaskStageTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00409860 (FUN_00409860, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~CTaskStageTypeInfo() override;

    /**
     * Address: 0x00409850 (FUN_00409850, ?GetName@CTaskStageTypeInfo@Moho@@UBEPBDXZ)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00409810 (FUN_00409810, ?Init@CTaskStageTypeInfo@Moho@@UAEXXZ)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CTaskThreadConstruct) == 0x14, "CTaskThreadConstruct size must be 0x14");
  static_assert(sizeof(CTaskThreadSerializer) == 0x14, "CTaskThreadSerializer size must be 0x14");
  static_assert(sizeof(CTaskThreadTypeInfo) == 0x64, "CTaskThreadTypeInfo size must be 0x64");
  static_assert(sizeof(CTaskStage) == 0x14, "CTaskStage size must be 0x14");
  static_assert(offsetof(CTaskStage, mThreads) == 0x00, "CTaskStage::mThreads offset must be 0x00");
  static_assert(offsetof(CTaskStage, mStagedThreads) == 0x08, "CTaskStage::mStagedThreads offset must be 0x08");
  static_assert(offsetof(CTaskStage, mActive) == 0x10, "CTaskStage::mActive offset must be 0x10");
  static_assert(sizeof(CTaskStageSerializer) == 0x14, "CTaskStageSerializer size must be 0x14");
  static_assert(sizeof(CTaskStageTypeInfo) == 0x64, "CTaskStageTypeInfo size must be 0x64");
} // namespace moho
