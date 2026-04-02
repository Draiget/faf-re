#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/condition.h"
#include "boost/mutex.h"
#include "boost/shared_ptr.h"
#include "boost/thread.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/time/Timer.h"
#include "ISTIDriver.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/net/Common.h"
#include "platform/Platform.h"
#include "SSyncFilter.h"

namespace moho
{
  class LaunchInfoBase;
  class CMarshaller;
  class CDecoder;

  struct SSyncPublishedCommandPacket
  {
    CmdId commandId;                       // +0x00
    std::uint8_t pad_0004_0008[0x04]{};    // +0x04
    std::uint8_t serializedBlob0x70[0x70]{}; // +0x08
  };
  static_assert(sizeof(SSyncPublishedCommandPacket) == 0x78, "SSyncPublishedCommandPacket size must be 0x78");
  static_assert(
    offsetof(SSyncPublishedCommandPacket, serializedBlob0x70) == 0x08,
    "SSyncPublishedCommandPacket::serializedBlob0x70 offset must be 0x08"
  );

  /**
   * Sync publication payload exchanged from sim thread to driver consumers.
   *
   * Recovered size/layout from FA `SSyncData` usage in publish/remove paths.
   */
  struct SSyncData
  {
    int32_t mCurBeat = 0;                                  // +0x000
    std::uint8_t pad_0004_0188[0x184]{};                    // +0x004
    msvc8::vector<SSTICommandConstantData> mPublishedCommandDescriptors; // +0x188
    msvc8::vector<SSyncPublishedCommandPacket> mPublishedCommandPackets; // +0x198
    msvc8::vector<CmdId> mPendingCommandEventRemovals;      // +0x1A8
    msvc8::vector<CmdId> mPendingReleasedCommandIds;        // +0x1B8
    std::uint8_t pad_01C8_02B8[0xF0]{};                     // +0x1C8

    void QueuePendingCommandEventRemoval(CmdId commandId);
  };
  static_assert(sizeof(SSTICommandConstantData) == 0x3C, "SSTICommandConstantData size must be 0x3C");
  static_assert(
    offsetof(SSTICommandConstantData, unk2) == 0x20,
    "SSTICommandConstantData::unk2 offset must be 0x20"
  );
  static_assert(
    offsetof(SSyncData, mPublishedCommandDescriptors) == 0x188,
    "SSyncData::mPublishedCommandDescriptors offset must be 0x188"
  );
  static_assert(
    offsetof(SSyncData, mPublishedCommandPackets) == 0x198,
    "SSyncData::mPublishedCommandPackets offset must be 0x198"
  );
  static_assert(
    offsetof(SSyncData, mPendingCommandEventRemovals) == 0x1A8,
    "SSyncData::mPendingCommandEventRemovals offset must be 0x1A8"
  );
  static_assert(
    offsetof(SSyncData, mPendingReleasedCommandIds) == 0x1B8,
    "SSyncData::mPendingReleasedCommandIds offset must be 0x1B8"
  );
  static_assert(sizeof(SSyncData) == 0x2B8, "SSyncData size must be 0x2B8");

  /**
   * 8-byte lock cell used by CSimDriver (matches +0x30..+0x37 layout).
   */
  struct SDriverMutex
  {
    boost::mutex* lock = nullptr; // runtime-owned lock pointer
    uint8_t pad[3]{};
  };
  static_assert(sizeof(SDriverMutex) == 0x8, "SDriverMutex size must be 0x8");

  /**
   * Ring buffer used for pending sync packets.
   *
   * Reconstructed from queue fields at +0x90..+0xA3.
   */
  struct SSyncDataQueue
  {
    uint32_t reserved = 0;
    SSyncData** map = nullptr;
    uint32_t mapSize = 0;
    uint32_t head = 0;
    uint32_t size = 0;

    ~SSyncDataQueue();

    bool Empty() const;
    void PushBack(SSyncData* data);
    SSyncData* PopFront();
    void ClearAndDelete();
  };
  static_assert(sizeof(SSyncDataQueue) == 0x14, "SSyncDataQueue size must be 0x14");

  enum class EDriverState : int32_t
  {
    Startup = 0,
    Ready = 1,
    Dispatching = 2,
    WaitingForMainThread = 3,
    Stopped = 4,
    Failed = 5,
  };

  /**
   * Concrete simulation-thread driver.
   *
   * VFTABLE: 0x00E3350C
   * Size:    0x230
   */
  class CSimDriver final : public ISTIDriver
  {
    friend struct CSimDriverLayoutAssertions;

  public:
    /**
     * Address: 0x0073B570 (FUN_0073B570)
     * Mangled: ??0CSimDriver@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes driver state, synchronization primitives, marshaller, and startup thread state.
     */
    CSimDriver(
      msvc8::auto_ptr<gpg::Stream> stream,
      msvc8::auto_ptr<CClientManagerImpl> clientManager,
      const boost::shared_ptr<LaunchInfoBase>& launchInfo,
      uint32_t commandSourceId
    );

    /**
     * Address: 0x0073BA50 (FUN_0073BA50)
     * Mangled: ??1CSimDriver@Moho@@QAE@@Z
     *
     * What it does:
     * Performs full shutdown and releases all owned resources.
     */
    ~CSimDriver() override;

    // Slot order matches ISTIDriver; addresses here are CSimDriver override entrypoints.
    /**
     * Address: 0x0073BBF0 (FUN_0073BBF0)
     */
    void DisconnectClients() override;
    /**
     * Address: 0x0073BC80 (FUN_0073BC80)
     */
    void ShutDown() override;
    /**
     * Address: 0x0073B190 (FUN_0073B190)
     */
    CClientManagerImpl* GetClientManager() override;
    /**
     * Address: 0x0073BDE0 (FUN_0073BDE0)
     */
    void NoOp() override;
    /**
     * Address: 0x0073C250 (FUN_0073C250)
     */
    void Dispatch() override;
    /**
     * Address: 0x0073C410 (FUN_0073C410)
     */
    void IncrementOutstandingRequests() override;
    /**
     * Address: 0x0073C440 (FUN_0073C440)
     */
    void DecrementOutstandingRequestsAndSignal() override;
    /**
     * Address: 0x0073C4F0 (FUN_0073C4F0)
     */
    bool HasSyncData() override;
    /**
     * Address: 0x0073C520 (FUN_0073C520)
     */
    void GetSyncData(SSyncData*& outSyncData) override;
    /**
     * Address: 0x0073B1A0 (FUN_0073B1A0)
     */
    HANDLE GetSyncDataAvailableEvent() override;
    /**
     * Address: 0x0073C630 (FUN_0073C630)
     */
    double GetSimSpeed() override;
    /**
     * Address: 0x0073B1B0 (FUN_0073B1B0)
     */
    void SetArmyIndex(int armyIndex) override;
    /**
     * Address context:
     * - FAF patch callback `cfunc_SetFocusArmySim` writes this lane directly.
     *
     * What it does:
     * Updates pending focus army without lock/event side effects.
     */
    void SetPendingFocusArmyRaw(std::int32_t focusArmy) noexcept;
    /**
     * Address: 0x0073B270 (FUN_0073B270)
     */
    void SetGeomCams(const msvc8::vector<GeomCamera3>& geoCams) override;
    /**
     * Address: 0x0073B3F0 (FUN_0073B3F0)
     * Retail build: compare-only path for mask A.
     */
    void SetSyncFilterMaskA(const SSyncFilterMaskBlock& block) override;
    /**
     * Address: 0x0073B4B0 (FUN_0073B4B0)
     */
    void SetSyncFilterMaskB(const SSyncFilterMaskBlock& block) override;
    /**
     * Address: 0x0073B240 (FUN_0073B240)
     */
    void SetSyncFilterOptionFlag(bool value) override;
    /**
     * Address: 0x0073C660 (FUN_0073C660)
     */
    void RequestPause() override;
    /**
     * Address: 0x0073C700 (FUN_0073C700)
     */
    void Resume() override;
    /**
     * Address: 0x0073C7A0 (FUN_0073C7A0)
     */
    void SingleStep() override;
    /**
     * Address: 0x0073C840 (FUN_0073C840)
     */
    void CreateUnit(uint32_t armyIndex, const RResId& id, const SCoordsVec2& pos, float heading) override;
    /**
     * Address: 0x0073C8F0 (FUN_0073C8F0)
     */
    void CreateProp(const char* id, const Wm3::Vec3f& loc) override;
    /**
     * Address: 0x0073C990 (FUN_0073C990)
     */
    void DestroyEntity(EntId entityId) override;
    /**
     * Address: 0x0073CA30 (FUN_0073CA30)
     */
    void WarpEntity(EntId entityId, const VTransform& transform) override;
    /**
     * Address: 0x0073CAD0 (FUN_0073CAD0)
     */
    void ProcessInfoPair(void* id, const char* key, const char* val) override;
    /**
     * Address: 0x0073CB70 (FUN_0073CB70)
     */
    void
    IssueCommand(const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, bool clear) override;
    /**
     * Address: 0x0073CC10 (FUN_0073CC10)
     */
    void IssueFactoryCommand(
      const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, bool clear
    ) override;
    /**
     * Address: 0x0073CCB0 (FUN_0073CCB0)
     */
    void IncreaseCommandCount(CmdId id, int count) override;
    /**
     * Address: 0x0073CD50 (FUN_0073CD50)
     */
    void DecreaseCommandCount(CmdId id, int count) override;
    /**
     * Address: 0x0073CDF0 (FUN_0073CDF0)
     */
    void SetCommandTarget(CmdId id, const SSTITarget& target) override;
    /**
     * Address: 0x0073CE90 (FUN_0073CE90)
     */
    void SetCommandType(CmdId id, EUnitCommandType type) override;
    /**
     * Address: 0x0073CF30 (FUN_0073CF30)
     */
    void SetCommandCells(
      CmdId id, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& target
    ) override;
    /**
     * Address: 0x0073CFD0 (FUN_0073CFD0)
     */
    void RemoveCommandFromUnitQueue(CmdId id, EntId unitId) override;
    /**
     * Address: 0x0073D070 (FUN_0073D070)
     */
    void ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args) override;
    /**
     * Address: 0x0073D110 (FUN_0073D110)
     */
    void LuaSimCallback(
      const char* fnName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
    ) override;
    /**
     * Address: 0x0073D1B0 (FUN_0073D1B0)
     */
    void ExecuteDebugCommand(
      const char* command,
      const Wm3::Vector3<float>& worldPos,
      uint32_t focusArmy,
      const BVSet<EntId, EntIdUniverse>& entities
    ) override;
    /**
     * Address: 0x0073DEA0 (FUN_0073DEA0)
     */
    Sim* ProcessEvents() override;
    /**
     * Address: 0x0073DF50 (FUN_0073DF50)
     */
    void ReleaseInterlockRef() override;
    /**
     * Address: 0x0073DF60 (FUN_0073DF60)
     */
    void RequestSaveGame(CSaveGameRequestImpl* request) override;
    /**
     * Address: 0x0073DFE0 (FUN_0073DFE0)
     */
    void DrawNetworkStats(CD3DPrimBatcher* batcher, float anchorX, float anchorY, float scaleX, float scaleY) override;

    /**
     * Address: 0x0073F430 (FUN_0073F430)
     */
    DWORD PerformNextEvent();

  private:
    /**
     * Address: 0x0073D8C0 (FUN_0073D8C0, thunk to FUN_0128FAC0)
     *
     * What it does:
     * Runs one dispatch beat, then executes sync publication and sim-rate sampling.
     */
    void ExecuteDispatchStepLocked(boost::mutex::scoped_lock& lock);
    /**
     * Address: 0x0073DAD0 (FUN_0073DAD0)
     *
     * What it does:
     * Copies pending filter state into active state and queues one sync packet.
     */
    void FinalizeSyncDispatchLocked(int32_t beatToDispatch);
    // Shared tail lifted from FUN_0073B1B0/FUN_0073BBF0 and command wrappers.
    void MarkFirstConnectionActivityLocked();
    /**
     * Address: 0x0073DD70 (FUN_0073DD70) + exception-recovery tail 0x0073DDF9..0x0073DE2B
     */
    void PreparePendingSaveRequestLocked(boost::mutex::scoped_lock& lock);
    // Local source-side adapter for removed out-param command-cookie returns.
    void ForwardCommandResultLocked();
    static void JoinAndDeleteThread(boost::thread*& thread);

  private:
    Sim* mSim = nullptr;                           // +0x04
    CClientManagerImpl* mClientManager = nullptr;  // +0x08
    gpg::Stream* mStream = nullptr;                // +0x0C
    boost::shared_ptr<LaunchInfoBase> mLaunchInfo; // +0x10
    uint32_t mCommandSourceId = 0;                 // +0x18
    int32_t mLastDequeuedBeat = -1;                // +0x1C
    int32_t mDispatchBeat = 1;                     // +0x20
    int32_t mCommandCookie = 1;                    // +0x24
    CMarshaller* mMarshaller = nullptr;            // +0x28
    CDecoder* mDecoder = nullptr;                  // +0x2C
    SDriverMutex mLock;                            // +0x30
    boost::thread* mSimThread = nullptr;           // +0x38
    int32_t mOutstandingRequests = 1;              // +0x3C
    gpg::time::Timer mTimer;                       // +0x40
    HANDLE mConnectionEvent = nullptr;             // +0x48
    // +0x4C..+0x4F: compiler-inserted alignment before 8-byte cycle timestamp.
    int64_t mLastSyncCycleTime = 0; // +0x50
    bool mStopSimThread = false;    // +0x58
    // +0x59..+0x5F: compiler-inserted alignment before 8-byte cycle timestamp.
    int64_t mFirstCommandCycleTime = 0; // +0x60
    bool mSimBusy = false;              // +0x68
    // +0x69..+0x6B: compiler-inserted alignment before pointer.
    boost::thread* mCreateSimThread = nullptr; // +0x6C
    bool mStopCreateSimThread = false;         // +0x70
    // +0x71..+0x73: compiler-inserted alignment before boost::condition.
    boost::condition mStateChanged;              // +0x74
    EDriverState mState = EDriverState::Startup; // +0x8C
    SSyncDataQueue mSyncDataQueue;               // +0x90
    HANDLE mSyncDataAvailableEvent = nullptr;    // +0xA4
    bool mInterlockedMode = false;               // +0xA8
    // +0xA9..+0xAB: compiler-inserted alignment before int32.
    int32_t mInterlockRefCount = 0;                   // +0xAC
    SSyncFilter mPendingSyncFilter;                   // +0xB0
    SSyncFilter mActiveSyncFilter;                    // +0x120
    CSaveGameRequestImpl* mSaveGameRequest = nullptr; // +0x190
    bool mWantsToSave = false;                        // +0x194
    // +0x195..+0x197: compiler-inserted alignment before 4-byte aligned flag group.
    alignas(4) bool mSaveRequestUsesSuggestedName = false; // +0x198
    // +0x199..+0x19B: compiler-inserted alignment before string.
    msvc8::string mPendingSaveName; // +0x19C
    NetSpeeds mSimSpeedSamples;     // +0x1B8
    int32_t mCurrentSimRate = 10;   // +0x228
  };

  struct CSimDriverLayoutAssertions
  {
    static_assert(sizeof(CSimDriver) == 0x230, "CSimDriver size must be 0x230");
    static_assert(offsetof(CSimDriver, mClientManager) == 0x8, "mClientManager offset mismatch");
    static_assert(offsetof(CSimDriver, mMarshaller) == 0x28, "mMarshaller offset mismatch");
    static_assert(offsetof(CSimDriver, mLastSyncCycleTime) == 0x50, "mLastSyncCycleTime offset mismatch");
    static_assert(offsetof(CSimDriver, mStopSimThread) == 0x58, "mStopSimThread offset mismatch");
    static_assert(offsetof(CSimDriver, mFirstCommandCycleTime) == 0x60, "mFirstCommandCycleTime offset mismatch");
    static_assert(offsetof(CSimDriver, mSimBusy) == 0x68, "mSimBusy offset mismatch");
    static_assert(offsetof(CSimDriver, mCreateSimThread) == 0x6C, "mCreateSimThread offset mismatch");
    static_assert(offsetof(CSimDriver, mStopCreateSimThread) == 0x70, "mStopCreateSimThread offset mismatch");
    static_assert(offsetof(CSimDriver, mState) == 0x8C, "mState offset mismatch");
    static_assert(offsetof(CSimDriver, mSyncDataAvailableEvent) == 0xA4, "mSyncDataAvailableEvent offset mismatch");
    static_assert(offsetof(CSimDriver, mInterlockedMode) == 0xA8, "mInterlockedMode offset mismatch");
    static_assert(offsetof(CSimDriver, mInterlockRefCount) == 0xAC, "mInterlockRefCount offset mismatch");
    static_assert(offsetof(CSimDriver, mPendingSyncFilter) == 0xB0, "mPendingSyncFilter offset mismatch");
    static_assert(offsetof(CSimDriver, mActiveSyncFilter) == 0x120, "mActiveSyncFilter offset mismatch");
    static_assert(offsetof(CSimDriver, mSaveGameRequest) == 0x190, "mSaveGameRequest offset mismatch");
    static_assert(offsetof(CSimDriver, mWantsToSave) == 0x194, "mWantsToSave offset mismatch");
    static_assert(
      offsetof(CSimDriver, mSaveRequestUsesSuggestedName) == 0x198, "mSaveRequestUsesSuggestedName offset mismatch"
    );
    static_assert(offsetof(CSimDriver, mPendingSaveName) == 0x19C, "mPendingSaveName offset mismatch");
    static_assert(offsetof(CSimDriver, mSimSpeedSamples) == 0x1B8, "mSimSpeedSamples offset mismatch");
    static_assert(offsetof(CSimDriver, mCurrentSimRate) == 0x228, "mCurrentSimRate offset mismatch");
  };

  /**
   * Address: 0x0073F4E0 (FUN_0073F4E0)
   * Mangled:
   * ?SIM_CreateDriver@Moho@@YAPAVISTIDriver@1@V?$auto_ptr@VIClientManager@Moho@@@std@@V?$auto_ptr@VStream@gpg@@@4@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@I@Z
   *
   * What it does:
   * Factory that transfers stream/client ownership and returns a new `CSimDriver`.
   */
  ISTIDriver* SIM_CreateDriver(
    CClientManagerImpl* clientManager,
    gpg::Stream* stream,
    const boost::shared_ptr<LaunchInfoBase>& launchInfo,
    uint32_t commandSourceId
  );

  /**
   * Address context: process-global `sSimDriver` ownership lane used by world/app frame code.
   *
   * What it does:
   * Returns the currently active simulation driver instance, or nullptr.
   */
  [[nodiscard]] ISTIDriver* SIM_GetActiveDriver();

  /**
   * Address context:
   * - world teardown path (`WLD_Teardown`) clears process-global driver ownership
   *   before destroying the detached instance.
   *
   * What it does:
   * Detaches and returns the active simulation driver pointer, then clears the
   * global active-driver lane.
   */
  [[nodiscard]] ISTIDriver* SIM_DetachActiveDriver();
} // namespace moho
