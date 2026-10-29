#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "moho/net/CClientBase.h"
#include "moho/net/CClientManagerImpl.h"
#include "remote/wire/Roster.h"

// Engine addition, server mode (plan WP11.1, WP11.4): the remote client's client manager. A
// lockstep client manager broadcasts each command message (`CMarshaller` hands it to
// `ProcessClients`) to every peer; this one gives it to the connection to the server instead,
// which decodes it with the engine's own `CDecoder`.
//
// It is also what the session's `GetClientManager()` returns: the user code reads the roster,
// the sim rate and the connection state through `IClientManager`'s virtuals only (the ~20 call
// sites, research/WP11.1-command-path.md), so every one of them is answered here. In loopback
// each is the stand-in's answer (the session's own lockstep client manager); the networked form
// answers from what the server sends (WP11.4, still to do).

namespace faf::remote::client
{
  class CRemoteClientManager;

  /**
   * One roster entry as the user code sees a client (`CClientBase`): name, owner, command
   * sources, sim rate, ping and quiet time, connection and ejection votes, all from the server's
   * roster. It has no peer stream of its own: chat for it goes to the server, which relays it.
   */
  class CRosterClient final : public moho::CClientBase
  {
  public:
    using ChatRelay = std::function<void(int clientIndex, gpg::MemBuffer<const char> data)>;

    CRosterClient(CRemoteClientManager& manager, const wire::SRosterEntry& entry, ChatRelay relay);

    /** The server's latest about this client (name, owner and sources included). */
    void Update(const wire::SRosterEntry& entry);
    [[nodiscard]] const wire::SRosterEntry& Entry() const noexcept { return mEntry; }

    float GetStatusMetricA() override;
    float GetStatusMetricB() override;
    bool NoEjectionPending() override;
    void CollectEjecters(msvc8::vector<const moho::CClientBase*>& out) override;
    int32_t GetSimRate() override;
    /** A remote client exchanges no peer messages: everything comes through the server. */
    void Process(moho::CMessage& msg) override;
    void ReceiveChat(gpg::MemBuffer<const char> data) override;

  private:
    CRemoteClientManager& mOwner;
    wire::SRosterEntry mEntry;
    ChatRelay mRelay;
  };

  class CRemoteClientManager final : public moho::CClientManagerImpl
  {
  public:
    /** Takes each command message, as `CMarshaller` built it, in order. */
    using CommandHandler = std::function<void(moho::CMessage& message)>;

    /** `standIn`: the client manager whose answers this one gives (loopback); null for none. */
    CRemoteClientManager(CommandHandler onCommand, moho::IClientManager* standIn);
    ~CRemoteClientManager() override;

    /** A command message for the server (the lockstep form sends it to every client). */
    void ProcessClients(moho::CMessage& message) override;

    /**
     * The server's roster (WP11.4): from now on the roster questions (clients, the local one,
     * an owner's) are answered from it, and chat for a client goes through `relay`. A client
     * object keeps its address for the session (user code may hold one); one the roster drops
     * stays, disconnected.
     */
    void ApplyRoster(const wire::SRoster& roster, CRosterClient::ChatRelay relay);
    [[nodiscard]] bool HasRoster() const noexcept { return mHaveRoster; }
    /** The sim rate the server's frames carry (WP11.5): from now on `GetSimRate` answers it. */
    void SetServerSimRate(int rate) noexcept
    {
      mServerSimRate = rate;
      mHaveServerSimRate = true;
    }
    /** The roster client of a session client index, or null. */
    [[nodiscard]] CRosterClient* RosterClient(int index) const noexcept;

    moho::IClient* CreateLocalClient(const char* name, int idx, int32_t ownerId, unsigned int sourceId) override;
    moho::IClient* CreateNetClient(
      const char* name, int idx, int32_t ownerId, unsigned int sourceId, moho::INetConnection* connection
    ) override;
    moho::IClient* CreateReplayClient(gpg::Stream** stream, moho::BVIntSet* sources) override;
    moho::IClient* CreateNullClient(const char* name, int idx, int32_t ownerId, unsigned int sourceId) override;
    moho::INetConnector* GetConnector() override;
    size_t NumberOfClients() override;
    moho::IClient* GetClient(int idx) override;
    moho::IClient* GetClientWithData(int32_t ownerId) override;
    moho::IClient* GetLocalClient() override;
    void SetUIInterface(moho::IClientMgrUIInterface* uiInterface) override;
    void Cleanup() override;
    bool IsEveryoneReady() override;
    void SetSimRate(int rate) override;
    int GetSimRate() override;
    int GetSimRateRequested() override;
    void BroadcastIntParam(int value) override;
    void DoBeat() override;
    void SelectEvent(HANDLE ev) override;
    void GetPartiallyQueuedBeat(int& out) override;
    void GetAvailableBeat(int& out) override;
    void UpdateStates(int beat) override;
    moho::SSendStampWindow GetBetween(int since) override;
    moho::SClientBottleneckInfo GetBottleneckInfo() override;
    void Debug() override;
    void Disconnect() override;

  private:
    CommandHandler mOnCommand;
    moho::IClientManager* mStandIn;
    bool mHaveRoster = false;
    bool mHaveServerSimRate = false;
    int mServerSimRate = 0;
    int mLocalIndex = -1;
    std::vector<std::unique_ptr<CRosterClient>> mRoster; // by client index; null where none
  };

  /**
   * The roster a server sends, read from a lockstep client manager (in loopback the session's
   * own, standing in for the server). `localIndex`: the receiving client's entry.
   */
  [[nodiscard]] wire::SRoster ReadRoster(moho::IClientManager& manager, int localIndex);
} // namespace faf::remote::client
