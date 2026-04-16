#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/TDatList.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/WeakPtr.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  class CTask;
  class CTaskThread;
  class CTaskStage;

#ifndef MOHO_WEAKPTR_OWNER_LINK_OFFSET_CTASKTHREAD_DEFINED
#define MOHO_WEAKPTR_OWNER_LINK_OFFSET_CTASKTHREAD_DEFINED
  template <>
  struct WeakPtrOwnerLinkOffset<CTaskThread>
  {
    static constexpr std::uintptr_t value = 0x08;
  };
#endif

  class CTaskThread : public TDatListItem<CTaskThread, void>, InstanceCounter<CTaskThread>
  {
  public:
    static gpg::RType* sType;
    static gpg::RType* sPointerType;

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
     * Address: 0x0040C5F0 (FUN_0040C5F0, Moho::CTaskThread::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for `CTaskThread*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

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

    /**
     * Address: 0x0040CF90 (FUN_0040CF90, Moho::CTaskThread::MemberDeserialize)
     *
     * What it does:
     * Loads stage pointer, pending-frame counter, staged flag, and task stack.
     */
    void MemberDeserialize(gpg::ReadArchive* archive, gpg::RRef* ownerRef);

    /**
     * Address: 0x0040CFE0 (FUN_0040CFE0, Moho::CTaskThread::MemberSerialize)
     *
     * What it does:
     * Saves stage pointer, pending-frame counter, staged flag, and task stack.
     */
    void MemberSerialize(gpg::WriteArchive* archive, gpg::RRef* ownerRef);
  };
  static_assert(sizeof(CTaskThread) == 0x1C, "CTaskThread == 0x1C");
  static_assert(offsetof(CTaskThread, mEventLinkHead) == 0x08, "CTaskThread::mEventLinkHead offset must be 0x08");
  static_assert(offsetof(CTaskThread, mStage) == 0x0C, "CTaskThread::mStage offset must be 0x0C");
  static_assert(offsetof(CTaskThread, mTaskTop) == 0x10, "CTaskThread::mTaskTop offset must be 0x10");
  static_assert(offsetof(CTaskThread, mPendingFrames) == 0x14, "CTaskThread::mPendingFrames offset must be 0x14");
  static_assert(offsetof(CTaskThread, mStaged) == 0x18, "CTaskThread::mStaged offset must be 0x18");
  static_assert(WeakPtr<CTaskThread>::kOwnerLinkOffset == 0x08, "CTaskThread weak-owner slot offset must be 0x08");

  class CTaskThreadConstruct
  {
  public:
    /**
     * Address: 0x004094E0 (FUN_004094E0, Moho::CTaskThreadConstruct::Construct)
     * Address: 0x00724910 (FUN_00724910)
     *
     * What it does:
     * Forwards serializer construct callback into CTaskThread allocation/init path.
     */
    static void Construct(void* archive, void* objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0040B420 (FUN_0040B420, Moho::CTaskThreadConstruct::Deconstruct)
     *
     * What it does:
     * Runs `CTaskThread` destructor and releases storage for constructed object.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x0040A630 (FUN_0040A630, sub_40A630)
     * Slot: 0
     *
     * What it does:
     * Binds construct/delete callbacks into CTaskThread RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  class CTaskThreadSerializer
  {
  public:
    /**
      * Alias of FUN_004095F0 (non-canonical helper lane).
     *
     * What it does:
     * Loads stage pointer, pending-frame counter, staged flag, and task stack.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
      * Alias of FUN_00409610 (non-canonical helper lane).
     *
     * What it does:
     * Saves stage pointer, pending-frame counter, staged flag, and task stack.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0040A6B0 (FUN_0040A6B0, sub_40A6B0)
     * Slot: 0
     *
     * What it does:
     * Binds load/save serializer callbacks into CTaskThread RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
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
    static gpg::RType* sType;

    TDatList<CTaskThread, void> mThreads;       // 0x00
    TDatList<CTaskThread, void> mStagedThreads; // 0x08
    bool mActive{true};                         // 0x10
    // 0x11..0x13: layout alignment bytes (no direct task-path field accesses recovered).
    std::uint8_t mAlignmentPad11[3]{};

    /**
     * Address: 0x00409910 (FUN_00409910, ??0CTaskStage@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes both intrusive thread-list sentinels and marks stage active.
     */
    CTaskStage();

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

    /**
     * Address: 0x00409CE0 (FUN_00409CE0, Moho::CTaskStage::SerializeThreads)
     *
     * What it does:
     * Writes owned thread-pointer lanes for main list and staged list, each
     * terminated by a null pointer lane.
     */
    void SerializeThreads(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00409DB0 (FUN_00409DB0, Moho::CTaskStage::DeserializeThreads)
     *
     * What it does:
     * Reads owned thread-pointer lanes and relinks decoded nodes into stage
     * main list followed by stage staged-list.
     */
    void DeserializeThreads(gpg::ReadArchive* archive);
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
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  class CTaskStageTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004097B0 (FUN_004097B0, ??0CTaskStageTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs and preregisters RTTI descriptor for `CTaskStage`.
     */
    CTaskStageTypeInfo();

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

  /**
   * Address: 0x00BC3020 (FUN_00BC3020, register_CTaskThreadTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskThreadTypeInfo` descriptor and registers
   * process-exit teardown.
   */
  void register_CTaskThreadTypeInfo();

  /**
   * Address: 0x00BC3040 (FUN_00BC3040, register_CTaskThreadConstruct)
   *
   * What it does:
   * Initializes the startup `CTaskThreadConstruct` helper and registers
   * process-exit intrusive-link cleanup.
   */
  void register_CTaskThreadConstruct();

  /**
   * Address: 0x00BC30C0 (FUN_00BC30C0, register_CTaskStageTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskStageTypeInfo` descriptor and registers
   * process-exit teardown.
   */
  void register_CTaskStageTypeInfo();

  /**
   * Address: 0x00BC30E0 (FUN_00BC30E0, register_CTaskStageSerializer)
   *
   * What it does:
   * Initializes startup serializer callbacks for `CTaskStage` and registers
   * process-exit intrusive-link cleanup.
   */
  void register_CTaskStageSerializer();
} // namespace moho
