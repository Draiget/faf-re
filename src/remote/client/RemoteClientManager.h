#pragma once

#include <functional>

#include "moho/net/CClientManagerImpl.h"

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
  };
} // namespace faf::remote::client
