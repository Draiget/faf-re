#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/ISTIDriver.h"
#include "remote/client/RemoteClientManager.h"
#include "remote/client/ServerViewClient.h"

// Engine addition, server mode (plan WP2.8, WP11; research/WP11-network-client-map.md "Session start and the sim
// assumptions"): the driver of a game client in a server session, which has no sim. Every beat's `SSyncData` is
// rebuilt from the server's `View` messages (`CServerViewClient`); commands go to the server as the messages a
// lockstep client broadcasts (`CMarshaller`), in `ESeatMessage::Command` frames on the session's channel; the session
// is ready once this client has loaded, as the server holds the game until every player has (`Loaded`).
//
// What the server doesn't send yet stays empty in the packets (research map: session tables, poses, the lanes nobody
// sends). The beat a command is issued at (`IssueCommand`'s return) is the newest beat shown plus one: the server's
// answer (`CommandAnswer`, the beat it went in) comes later and is counted (plan WP3.7).

namespace moho
{
  class CHeightField;
  class CSimResources;
  class LaunchInfoBase;
  class RRuleGameRules;
  struct SSTIArmyConstantData;
}

namespace LuaPlus
{
  class LuaState;
}

namespace faf::remote::client
{
  class CNetworkSimDriver final : public moho::ISTIDriver
  {
  public:
    /**
     * `rules`: the session's (`CWldSession::mRules`), which outlives the driver. The local client: the session's
     * client index, the player's uid and command source, as the launch info gives them. `heights`: the client's own
     * map's, as loaded (the server's terrain edits go on a copy); may be null.
     */
    CNetworkSimDriver(
      moho::RRuleGameRules& rules, const moho::LaunchInfoBase& launch, const char* playerName, int clientIndex, std::int32_t uid,
      unsigned int sourceId, const moho::CHeightField* heights
    );
    ~CNetworkSimDriver() override;

    void DisconnectClients() override;
    void ShutDown() override;
    moho::CClientManagerImpl* GetClientManager() override;
    void NoOp() override;
    void Dispatch() override;
    void IncrementOutstandingRequests() override;
    void DecrementOutstandingRequestsAndSignal() override;
    bool HasSyncData() override;
    void GetSyncData(moho::SSyncData*& outSyncData) override;
    HANDLE GetSyncDataAvailableEvent() override;
    double GetSimSpeed() override;
    void SetArmyIndex(int armyIndex) override;
    void SetGeomCams(const fa::vector<moho::GeomCamera3>& geoCams) override;
    void SetSyncFilterMaskA(const moho::SSyncFilterMaskBlock& block) override;
    void SetSyncFilterMaskB(const moho::SSyncFilterMaskBlock& block) override;
    void SetSyncFilterOptionFlag(bool value) override;
    void RequestPause(std::int32_t* outCommandCookie) override;
    void Resume(std::int32_t* outCommandCookie) override;
    moho::CmdId SingleStep() override;
    moho::CmdId CreateUnit(uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, float heading)
      override;
    moho::CmdId CreateProp(const char* id, const Wm3::Vec3f& loc) override;
    moho::CmdId DestroyEntity(moho::EntId entityId) override;
    moho::CmdId WarpEntity(moho::EntId entityId, const moho::VTransform& transform) override;
    moho::CmdId ProcessInfoPair(moho::EntId entityId, gpg::StrArg key, gpg::StrArg val) override;
    moho::CmdId IssueCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    moho::CmdId IssueFactoryCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities, const moho::SSTICommandIssueData& data, bool clear
    ) override;
    moho::CmdId IncreaseCommandCount(moho::CmdId id, int count) override;
    moho::CmdId DecreaseCommandCount(moho::CmdId id, int count) override;
    moho::CmdId SetCommandTarget(moho::CmdId id, const moho::SSTITarget& target) override;
    moho::CmdId SetCommandType(moho::CmdId id, moho::EUnitCommandType type) override;
    moho::CmdId SetCommandCells(
      moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
    ) override;
    moho::CmdId RemoveCommandFromUnitQueue(moho::CmdId id, moho::EntId unitId) override;
    moho::CmdId ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args) override;
    moho::CmdId LuaSimCallback(
      const char* fnName, const LuaPlus::LuaObject& args, const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    moho::CmdId ExecuteDebugCommand(
      const char* command, const Wm3::Vector3<float>& worldPos, uint32_t focusArmy,
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>& entities
    ) override;
    /** No sim on this side: null (`WEmitterWx` and the other callers check). */
    moho::Sim* ProcessEvents() override;
    void ReleaseInterlockRef() override;
    void RequestSaveGame(moho::ISaveRequest* request) override;
    void DrawNetworkStats(moho::CD3DPrimBatcher* batcher, float anchorX, float anchorY, float scaleX, float scaleY)
      override;

    [[nodiscard]] const CServerViewClient* Views() const noexcept { return mViews.get(); }

  private:
    /** One message from the server for the session. */
    void Take(const std::vector<std::uint8_t>& message);
    /** The packet for one view: its entity lanes rebuilt, the beat's fields and its Lua `Sync` table (`lua`). */
    void QueueView(const SViewMessage& view, std::span<const std::uint8_t> lua);
    /** Views whose beat's `LuaSync` has come, or that the next beat's view proves won't come, become packets. */
    void ReleaseViews();
    /** Sends one command message (`CMarshaller` built it) as a `Command` frame. */
    void SendCommandFrame(moho::CMessage& message);
    /** The beat a command just sent will be applied at, as best this side knows: the newest shown plus one. */
    [[nodiscard]] moho::CmdId IssueBeat() const noexcept;
    void LogSummary(const char* when) const;

    moho::RRuleGameRules& mRules;
    CRemoteClientManager mClientManager;
    moho::CMarshaller mMarshaller;
    std::unique_ptr<CServerViewClient> mViews;
    std::unique_ptr<LuaPlus::LuaState> mEmptySyncLua; // makes the `Sync` table's bytes for a view with no Lua lane
    std::vector<std::uint8_t> mEmptySync;
    // Every army's constants (index, names, civilian), as the sim's first packet gives them (`Sim::Sync`
    // `mNewGrids`), made from the launch's army setups; given with the first packet, which makes the session's armies.
    std::vector<moho::SSTIArmyConstantData> mArmyConstants;
    bool mArmiesGiven = false;
    // The session's resource deposits (it takes them from every packet, and its map draws them): an empty set for a
    // packet the view client gave none (the session tables' deposits are the packets' from the first view on).
    boost::shared_ptr<moho::CSimResources> mResources;
    const moho::CHeightField* mSeedHeights = nullptr; // copied into the view client when it is made
    std::uint64_t mTablesBad = 0;
    std::deque<std::unique_ptr<moho::SSyncData>> mPackets;
    // Views waiting for their beat's Lua lane (`LuaSync`, sent once the server's `Sync` for the beat is routed).
    struct SPendingView
    {
      std::vector<std::uint8_t> message;
      std::uint32_t beat = 0;
      bool haveLua = false;
      std::vector<std::uint8_t> lua;
    };
    std::deque<SPendingView> mPendingViews;
    std::map<std::uint32_t, std::vector<std::uint8_t>> mEarlyLua; // a `LuaSync` before its view (the pipeline)
    std::uint64_t mLuaMissing = 0;
    HANDLE mAvailable = nullptr;
    std::int32_t mLastBeat = -1;
    std::int32_t mServerBeat = -1;
    bool mShutDown = false;
    std::uint64_t mViewsTaken = 0;
    std::uint64_t mViewsBad = 0;
    std::uint64_t mCommandsSent = 0;
    std::uint64_t mAnswers[3] = {};
    std::uint64_t mLuaLanesBad = 0;
    std::uint64_t mLuaTablesLogged = 0;
  };

  /** Plan WP2.8: this player's part of the server's launch, as the session starter worked it out. */
  struct SServerLaunch
  {
    std::string playerName;
    int clientIndex = -1;
    std::int32_t uid = 0;
    unsigned int source = 0;
  };

  /** The session starter: the next session is a server session, this player's part of it as given. */
  void SetServerLaunch(const SServerLaunch& launch);
  /** A server session's launch was set: `WLD_DoLoading` makes the network driver, not a sim. */
  [[nodiscard]] bool HasServerLaunch() noexcept;
  /** `WLD_DoLoading`, in a server session: the driver, over the session's rules and its map's heights (may be null). */
  [[nodiscard]] moho::ISTIDriver* CreateServerSessionDriver(
    moho::RRuleGameRules& rules, const moho::LaunchInfoBase& launch, const moho::CHeightField* heights
  );
} // namespace faf::remote::client
