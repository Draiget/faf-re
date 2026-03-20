// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include "boost/recursive_mutex.h"
#include "gpg/core/streams/PipeStream.h"
#include "gpg/core/time/Timer.h"
#include "IClientManager.h"
#include "legacy/containers/Vector.h"
#include "moho/command/ICommandSink.h"

namespace moho
{
  class INetConnector;
  class INetConnection;
  class CClientBase;
  class CLocalClient;
  class CNullClient;
  class CMessageStream;
  class CClientManagerImpl;

  class CMarshaller final : public ICommandSink
  {
  public:
    /**
     * Address: <synthetic host-build helper>
     *
     * What it does:
     * Default-constructs marshaller with null manager pointer.
     */
    CMarshaller();

    /**
     * Address: 0x006E5A60 (FUN_006E5A60)
     *
     * What it does:
     * Initializes marshaller vtable and binds owner client-manager pointer.
     */
    explicit CMarshaller(CClientManagerImpl* manager);

    /**
     * Address: 0x006E5A90 (FUN_006E5A90)
     * Address: 0x102C0F90
     *
     * What it does:
     * Marshals `CMDST_SetCommandSource` with 1-byte source id.
     */
    void SetCommandSource(CommandSourceId sourceId) override;

    /**
     * Address: 0x006E5B90 (FUN_006E5B90)
     * Address: 0x102C1090
     *
     * What it does:
     * Marshals `CMDST_CommandSourceTerminated` without payload.
     */
    void OnCommandSourceTerminated() override;

    /**
     * Address: 0x006E5C70 (FUN_006E5C70)
     * Address: 0x102C1170
     *
     * What it does:
     * Marshals `CMDST_VerifyChecksum` payload (`MD5Digest`, `CSeqNo`).
     */
    void VerifyChecksum(const gpg::MD5Digest& digest, CSeqNo seqNo) override;

    /**
     * Address: 0x006E5DB0 (FUN_006E5DB0)
     * Address: 0x102C1270
     *
     * What it does:
     * Marshals `CMDST_RequestPause` without payload.
     */
    void RequestPause() override;

    /**
     * Address: 0x006E5E90 (FUN_006E5E90)
     * Address: 0x102C1350
     *
     * What it does:
     * Marshals `CMDST_Resume` without payload.
     */
    void Resume() override;

    /**
     * Address: 0x006E5F70 (FUN_006E5F70)
     * Address: 0x102C1430
     *
     * What it does:
     * Marshals `CMDST_SingleStep` without payload.
     */
    void SingleStep() override;

    /**
     * Address: 0x006E6050 (FUN_006E6050)
     * Address: 0x102C1510
     *
     * What it does:
     * Marshals `CMDST_CreateUnit` (army byte, blueprint id, position, heading).
     */
    void CreateUnit(uint32_t armyIndex, const RResId& blueprintId, const SCoordsVec2& pos, float heading) override;

    /**
     * Address: 0x006E61E0 (FUN_006E61E0)
     * Address: 0x102C1660
     *
     * What it does:
     * Marshals `CMDST_CreateProp` (blueprint id string and world position).
     */
    void CreateProp(const char* blueprintPath, const Wm3::Vec3f& pos) override;

    /**
     * Address: 0x006E6320 (FUN_006E6320)
     * Address: 0x102C1780
     *
     * What it does:
     * Marshals `CMDST_DestroyEntity` with entity id payload.
     */
    void DestroyEntity(EntId entityId) override;

    /**
     * Address: 0x006E6420 (FUN_006E6420)
     * Address: 0x102C1880
     *
     * What it does:
     * Marshals `CMDST_WarpEntity` (entity id + transform).
     */
    void WarpEntity(EntId entityId, const VTransform& transform) override;

    /**
     * Address: 0x006E6560 (FUN_006E6560)
     * Address: 0x102C1990
     *
     * What it does:
     * Marshals `CMDST_ProcessInfoPair` (`EntId` + key/value strings).
     */
    void ProcessInfoPair(void* id, const char* key, const char* val) override;

    /**
     * Address: 0x006E6690 (FUN_006E6690)
     * Address: 0x102C1AD0
     *
     * What it does:
     * Marshals `CMDST_IssueCommand` (entity set + command data + clear flag).
     */
    void IssueCommand(
      const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandData, bool clear
    ) override;

    /**
     * Address: 0x006E67D0 (FUN_006E67D0)
     * Address: 0x102C1BF0
     *
     * What it does:
     * Marshals `CMDST_IssueFactoryCommand` (entity set + command data + clear flag).
     */
    void IssueFactoryCommand(
      const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandData, bool clear
    ) override;

    /**
     * Address: 0x006E6910 (FUN_006E6910)
     * Address: 0x102C1D10
     *
     * What it does:
     * Marshals `CMDST_IncreaseCommandCount` (`CmdId`, count delta).
     */
    void IncreaseCommandCount(CmdId cmdId, int count) override;

    /**
     * Address: 0x006E6A40 (FUN_006E6A40)
     * Address: 0x102C1E20
     *
     * What it does:
     * Marshals `CMDST_DecreaseCommandCount` (`CmdId`, count delta).
     */
    void DecreaseCommandCount(CmdId cmdId, int count) override;

    /**
     * Address: 0x006E6B70 (FUN_006E6B70)
     * Address: 0x102C1F30
     *
     * What it does:
     * Marshals `CMDST_SetCommandTarget` (`CmdId`, target payload).
     */
    void SetCommandTarget(CmdId cmdId, const SSTITarget& target) override;

    /**
     * Address: 0x006E6C90 (FUN_006E6C90)
     * Address: 0x102C2040
     *
     * What it does:
     * Marshals `CMDST_SetCommandType` (`CmdId`, command type enum value).
     */
    void SetCommandType(CmdId cmdId, EUnitCommandType type) override;

    /**
     * Address: 0x006E6DD0 (FUN_006E6DD0)
     * Address: 0x102C2150
     *
     * What it does:
     * Marshals `CMDST_SetCommandCells` (`CmdId`, cell list, target position).
     */
    void SetCommandCells(
      CmdId cmdId, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& pos
    ) override;

    /**
     * Address: 0x006E6F30 (FUN_006E6F30)
     * Address: 0x102C22A0
     *
     * What it does:
     * Marshals `CMDST_RemoveCommandFromQueue` (`CmdId`, unit/entity id).
     */
    void RemoveCommandFromUnitQueue(CmdId cmdId, EntId entityId) override;

    /**
     * Address: 0x006E71F0 (FUN_006E71F0)
     * Address: 0x102C24F0
     *
     * What it does:
     * Marshals `CMDST_ExecuteLuaInSim` (function string + Lua byte stream).
     */
    void ExecuteLuaInSim(const char* functionName, const LuaPlus::LuaObject& args) override;

    /**
     * Address: 0x006E7300 (FUN_006E7300)
     * Address: 0x102C2620
     *
     * What it does:
     * Marshals `CMDST_LuaSimCallback` (callback, Lua args, entity set).
     */
    void LuaSimCallback(
      const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
    ) override;

    /**
     * Address: 0x006E7070 (FUN_006E7070)
     * Address: 0x102C23B0
     *
     * What it does:
     * Marshals `CMDST_DebugCommand` (string, world pos, army byte, selected entities).
     */
    void ExecuteDebugCommand(
      const char* commandText,
      const Wm3::Vector3<float>& worldPos,
      uint32_t armyIndex,
      const BVSet<EntId, EntIdUniverse>& entities
    ) override;

    /**
     * Address: 0x006E7420 (FUN_006E7420)
     * Address: 0x102C2760
     *
     * What it does:
     * Marshals `CMDST_Advance` with beat delta payload.
     */
    void AdvanceBeat(int beatDelta) override;

    /**
     * Address: 0x006E7520 (FUN_006E7520)
     * Address: 0x102C2860
     *
     * What it does:
     * Marshals `CMDST_EndGame` without payload.
     */
    void EndGame() override;

  private:
    /**
     * Address: 0x006E7600 (FUN_006E7600)
     * Address: 0x102C2940
     *
     * What it does:
     * Writes count + sorted entity ids from `BVSet<EntId,EntIdUniverse>`.
     */
    void WriteEntIdSet(CMessageStream& stream, const BVSet<EntId, EntIdUniverse>& entities);

    /**
     * Address: 0x006E76C0 (FUN_006E76C0)
     * Address: 0x102C29D0
     *
     * What it does:
     * Writes `SSTICommandIssueData` wire payload in engine order.
     */
    void WriteCommandData(CMessageStream& stream, const SSTICommandIssueData& commandData);

    /**
     * Address: 0x006E7890 (FUN_006E7890)
     * Address: 0x102C2B20
     *
     * What it does:
     * Writes compact target payload: target type byte + type-specific data.
     */
    void WriteTarget(CMessageStream& stream, const SSTITarget& target);

    /**
     * Address: 0x006E7940 (FUN_006E7940)
     * Address: <inlined in MohoEngine WriteCommandData/SetCommandCells>
     *
     * What it does:
     * Writes compact SOCellPos vector payload (count + raw cell array).
     */
    static void WriteCells(CMessageStream& stream, const gpg::core::FastVector<SOCellPos>& cells);

  public:
    CClientManagerImpl* mClientManager{nullptr};
  };
  static_assert(sizeof(CMarshaller) == 0x8, "CMarshaller size must be 0x8");

  /**
   * VFTABLE: 0x00E16B64
   * COL:  0x00E6AF24
   */
  class CClientManagerImpl : public IClientManager
  {
  public:
    /**
     * Address: 0x0053E050
     * Slot: 0
     */
    virtual ~CClientManagerImpl();

    /**
     * Address: 0x0053E180
     * Slot: 1
     */
    virtual IClient*
    CreateLocalClient(const char* name, int32_t index, LaunchInfoBase* launchInfo, unsigned int sourceId);

    /**
     * Address: 0x0053E260
     * Slot: 2
     */
    virtual IClient* CreateNetClient(
      const char* name, int32_t index, LaunchInfoBase* info, uint32_t sourceId, INetConnection* connection
    );

    /**
     * Address: 0x0053E400
     * Slot: 3
     */
    virtual IClient* CreateReplayClient(int*, BVIntSet* set);

    /**
     * Address: 0x0053E330
     * Slot: 4
     */
    virtual IClient* CreateNullClient(const char* name, int32_t index, LaunchInfoBase* info, uint32_t sourceId);

    /**
     * Address: 0x0053BCB0
     * Slot: 5
     */
    virtual INetConnector* GetConnector();

    /**
     * Address: 0x0053BCC0
     * Slot: 6
     */
    virtual size_t NumberOfClients();

    /**
     * Address: 0x0053BCE0
     * Slot: 7
     */
    virtual IClient* GetClient(int idx);

    /**
     * Address: 0x0053E470
     * Slot: 8
     */
    virtual IClient* GetClientWithData(LaunchInfoBase* info);

    /**
     * Address: 0x0053BD10
     * Slot: 9
     */
    virtual IClient* GetLocalClient();

    /**
     * Address: 0x0053BD20
     * Slot: 10
     */
    virtual void SetUIInterface(IClientMgrUIInterface*);

    /**
     * Address: 0x0053E4B0
     * Slot: 11
     */
    virtual void Cleanup();

    /**
     * Address: 0x0053E560
     * Slot: 12
     */
    virtual bool IsEveryoneReady();

    /**
     * Address: 0x0053E590
     * Slot: 13
     */
    virtual void SetSimRate(int rate);

    /**
     * Address: 0x0053E720
     * Slot: 14
     */
    virtual int GetSimRate();

    /**
     * Address: 0x0053E7E0
     * Slot: 15
     */
    virtual int GetSimRateRequested();

    /**
     * Address: 0x0053E850
     * Slot: 16
     */
    virtual void BroadcastIntParam(int value);

    /**
     * Address: 0x0053E990
     * Slot: 17
     */
    virtual void ProcessClients(CMessage& msg);

    /**
     * Address: 0x0053EA30
     * Slot: 18
     */
    virtual void DoBeat();

    /**
     * Address: 0x0053EDA0
     * Slot: 19
     */
    virtual void SelectEvent(HANDLE ev);

    /**
     * Address: 0x0053EF90
     * Slot: 20
     */
    virtual void GetPartiallyQueuedBeat(int& out);

    /**
     * Address: 0x0053EFD0
     * Slot: 21
     */
    virtual void GetAvailableBeat(int& out);

    /**
     * Address: 0x0053F010
     * Slot: 22
     */
    virtual void UpdateStates(int beat);

    /**
     * Address: 0x0053F4C0
     * Slot: 23
     * Demangled: Moho::CClientManagerImpl::Func3
     */
    virtual SSendStampView GetBetween(int since);

    /**
     * Address: 0x0053F5A0
     * Slot: 24
     * Demangled: Moho::CClientManagerImpl::Func4
     */
    virtual SClientBottleneckInfo GetBottleneckInfo();

    /**
     * Address: 0x0053F920
     * Slot: 25
     */
    virtual void Debug();

    /**
     * Address: 0x0053F830
     * Slot: 26
     */
    virtual void Disconnect();

  public:
    boost::recursive_mutex mLock;
    IClientMgrUIInterface* mInterface{nullptr};
    msvc8::vector<CClientBase*> mClients;
    INetConnector* mConnector{nullptr};
    CClientBase* mLocalClient{nullptr};
    bool mWeAreReady{false};
    bool mEveryoneIsReady{false};
    int mDispatchedBeat{0};
    int mAvailableBeat{0};
    int mFullyQueuedBeat{0};
    int mPartiallyQueuedBeat{0};
    int mGameSpeedClock{0};
    int mGameSpeedRequester{0};
    int mGameSpeed{0};
    bool mAdjustableGameSpeed{false};
    HANDLE mCurrentEvent{nullptr};
    int gap{0};
    gpg::time::Timer mTimer3;
    SSendStampBuffer mStampBuffer;
    gpg::PipeStream mStream;
    CMarshaller mMarshaller;
    gpg::time::Timer mDispatchedTimer;
    gpg::time::Timer mTimer2;
  };

} // namespace moho
