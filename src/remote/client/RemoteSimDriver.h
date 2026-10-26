#pragma once

#include <chrono>
#include <memory>
#include <optional>

#include "moho/sim/ISTIDriver.h"
#include "Wm3AxisAlignedBox3.h"
#include "legacy/containers/AutoPtr.h"
#include "moho/misc/CDecoder.h"
#include "remote/client/LockstepDriver.h"
#include "remote/client/LoopbackCommands.h"
#include "remote/client/LoopbackLink.h"
#include "remote/client/RemoteClientManager.h"

// Engine addition, server mode (plan WP11): the client's remote driver, in its first,
// in-process loopback form. It owns the session's lockstep driver as its "server": each sync
// packet that driver produces goes through the server side of the wire format (frame builder,
// optional dead reckoning, encoder) and the client side (decoder, `CSyncRebuilder`) before
// `DoBeat` sees it, so the session runs on what the entities lane carried. Lanes the wire
// format does not carry yet pass through from the server's packet (SyncRebuilder.h).
//
// Commands (driver slots 17-35) go as the messages a networked client sends: `CMarshaller`
// builds each one for `CRemoteClientManager`, the stand-in server decodes it with `CDecoder`
// and `CLoopbackCommandIntake` hands it to the owned driver (WP11.1). Session requests still go
// to the owned driver directly; the network form replaces it with the server connection
// (WP10). Only `/loopback` builds this driver (`WrapForLoopback`); without it a session is the
// lockstep one, unchanged.

namespace moho
{
  class RRuleGameRules;
}

namespace LuaPlus
{
  class LuaState;
}

namespace faf::remote::client
{
  class CRemoteSimDriver final : public moho::ISTIDriver
  {
  public:
    CRemoteSimDriver(
      std::unique_ptr<moho::ISTIDriver> server, moho::RRuleGameRules& rules, const wire::SFrameCodec& codec,
      const SLoopbackOptions& options
    );
    ~CRemoteSimDriver() override;

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
    void SetGeomCams(const msvc8::vector<moho::GeomCamera3>& geoCams) override;
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
    moho::Sim* ProcessEvents() override;
    void ReleaseInterlockRef() override;
    void RequestSaveGame(moho::CSaveGameRequestImpl* request) override;
    void DrawNetworkStats(moho::CD3DPrimBatcher* batcher, float anchorX, float anchorY, float scaleX, float scaleY)
      override;

    /** The lockstep driver standing in for the server. */
    [[nodiscard]] moho::ISTIDriver* Server() const noexcept { return mServer.get(); }

  private:
    /** One beat through the wire: server encode, client decode and rebuild. */
    void PassThroughWire(moho::SSyncData& packet);
    void LogSummary(const char* when) const;
    /** Marshals one command (`send` calls `mMarshaller`) through to the server; its cookie. */
    template <class Send>
    moho::CmdId SendCommand(Send&& send);

    std::unique_ptr<moho::ISTIDriver> mServer;
    CLoopbackLink mLink;
    // The command path (WP11.1): marshaller -> client manager -> the server's decoder -> intake.
    CLoopbackCommandIntake mIntake;
    std::unique_ptr<LuaPlus::LuaState> mCommandLua; // decodes the Lua payloads on the server end
    msvc8::auto_ptr<gpg::Stream> mNoRecording;
    moho::CDecoder mServerDecoder;
    CRemoteClientManager mClientManager;
    moho::CMarshaller mMarshaller;
    std::uint64_t mCommandsSent = 0;
    std::uint64_t mCommandsDropped = 0;
    // Session requests (WP11.1).
    /** Sends the cameras held back by the rate limit once their interval has passed. */
    void FlushGeomCams(bool force);
    SLoopbackOptions mOptions;
    std::uint64_t mArmyRequests = 0;
    std::uint64_t mArmyRefusals = 0;
    msvc8::vector<moho::GeomCamera3> mPendingCams;
    bool mHavePendingCams = false;
    std::chrono::steady_clock::time_point mLastCamsSent{};
    std::uint64_t mCamsReceived = 0;
    std::uint64_t mCamsSent = 0;
  };


  /**
   * `/loopback` on the command line (and `/loopbackdr <steps>` for dead reckoning): wraps a new
   * session's lockstep driver in a `CRemoteSimDriver`. Otherwise returns `driver` unchanged.
   * A multiplayer session is never wrapped (logged): only a replay or a single-player
   * session, so the switch cannot change what a client does in a game with other people.
   */
  [[nodiscard]] moho::ISTIDriver* WrapForLoopback(
    moho::ISTIDriver* driver, moho::RRuleGameRules& rules, const Wm3::AxisAlignedBox3f& mapBounds, bool multiplayer
  );
} // namespace faf::remote::client
