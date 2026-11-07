#include "remote/client/RemoteClientManager.h"

#include <algorithm>
#include <utility>

// Engine addition, server mode: see RemoteClientManager.h.

namespace faf::remote::client
{
  namespace
  {
    [[nodiscard]] moho::BVIntSet SourcesOf(const wire::SRosterEntry& entry)
    {
      moho::BVIntSet sources{};
      for (const std::uint8_t source : entry.sources) {
        (void)sources.Add(source);
      }
      return sources;
    }

    [[nodiscard]] std::uint32_t FirstSource(const wire::SRosterEntry& entry) noexcept
    {
      return entry.sources.empty() ? 0xFFu : entry.sources.front();
    }
  } // namespace

  CRosterClient::CRosterClient(CRemoteClientManager& manager, const wire::SRosterEntry& entry, ChatRelay relay)
    : moho::CClientBase(
        entry.index, &manager, entry.name.c_str(), entry.ownerId,
        [](moho::BVIntSet&& sources) -> moho::BVIntSet& { return sources; }(SourcesOf(entry)), // copied by the base,
        FirstSource(entry)
      )
    , mOwner(manager)
    , mEntry(entry)
    , mRelay(std::move(relay))
  {
    mSimRate = entry.simRate;
  }

  void CRosterClient::Update(const wire::SRosterEntry& entry)
  {
    if (entry.name != mEntry.name) {
      mNickname = fa::string(entry.name.c_str());
    }
    mOwnerId = entry.ownerId;
    if (entry.sources != mEntry.sources) {
      mValidCommandSources = SourcesOf(entry);
      mCommandSourceId = FirstSource(entry);
    }
    mSimRate = entry.simRate;
    mEntry = entry;
  }

  float CRosterClient::GetStatusMetricA()
  {
    return mEntry.ping;
  }

  float CRosterClient::GetStatusMetricB()
  {
    return mEntry.quiet;
  }

  bool CRosterClient::NoEjectionPending()
  {
    return mEntry.connected;
  }

  void CRosterClient::CollectEjecters(fa::vector<const moho::CClientBase*>& out)
  {
    for (const std::uint8_t index : mEntry.ejectedBy) {
      if (const CRosterClient* const ejecter = mOwner.RosterClient(index); ejecter != nullptr) {
        out.push_back(ejecter);
      }
    }
  }

  int32_t CRosterClient::GetSimRate()
  {
    return mEntry.simRate;
  }

  void CRosterClient::Process(moho::CMessage&)
  {
  }

  void CRosterClient::ReceiveChat(const gpg::MemBuffer<const char> data)
  {
    if (mRelay) {
      mRelay(mEntry.index, data);
    }
  }

  CRemoteClientManager::CRemoteClientManager(CommandHandler onCommand, moho::IClientManager* const standIn)
    : moho::CClientManagerImpl(0u, nullptr, 0, false)
    , mOnCommand(std::move(onCommand))
    , mStandIn(standIn)
  {}

  CRemoteClientManager::~CRemoteClientManager() = default;

  void CRemoteClientManager::ApplyRoster(const wire::SRoster& roster, CRosterClient::ChatRelay relay)
  {
    std::vector<bool> listed(mRoster.size(), false);
    for (const wire::SRosterEntry& entry : roster.entries) {
      if (entry.index >= mRoster.size()) {
        mRoster.resize(entry.index + 1u);
        listed.resize(entry.index + 1u, false);
      }
      std::unique_ptr<CRosterClient>& client = mRoster[entry.index];
      if (client) {
        client->Update(entry);
      } else {
        client = std::make_unique<CRosterClient>(*this, entry, relay);
      }
      listed[entry.index] = true;
    }
    for (std::size_t i = 0; i < mRoster.size(); ++i) {
      if (mRoster[i] && !listed[i]) {
        wire::SRosterEntry gone = mRoster[i]->Entry();
        gone.connected = false;
        mRoster[i]->Update(gone);
      }
    }
    mLocalIndex = roster.localIndex;
    mHaveRoster = true;
  }

  CRosterClient* CRemoteClientManager::RosterClient(const int index) const noexcept
  {
    return index >= 0 && static_cast<std::size_t>(index) < mRoster.size() ? mRoster[index].get() : nullptr;
  }

  wire::SRoster ReadRoster(moho::IClientManager& manager, const int localIndex)
  {
    wire::SRoster roster{};
    roster.localIndex = localIndex;
    const std::size_t count = std::min(manager.NumberOfClients(), wire::SRoster::kMaxEntries);
    for (std::size_t i = 0; i < count; ++i) {
      auto* const client = static_cast<moho::CClientBase*>(manager.GetClient(static_cast<int>(i)));
      if (client == nullptr) {
        continue;
      }
      wire::SRosterEntry entry{};
      entry.index = static_cast<std::uint8_t>(client->GetIndex());
      entry.name = client->GetNickname().c_str();
      if (entry.name.size() > wire::SRosterEntry::kMaxNameBytes) {
        entry.name.resize(wire::SRosterEntry::kMaxNameBytes);
      }
      entry.ownerId = client->GetOwnerId();
      const moho::BVIntSet* const sources = client->GetValidCommandSources();
      for (unsigned int value = sources->GetNext(~0u); value != sources->Max(); value = sources->GetNext(value)) {
        if (entry.sources.size() < wire::SRosterEntry::kMaxSources) {
          entry.sources.push_back(static_cast<std::uint8_t>(value));
        }
      }
      entry.simRate = client->mSimRate;
      entry.ping = client->GetStatusMetricA();
      entry.quiet = client->GetStatusMetricB();
      entry.connected = client->NoEjectionPending();
      fa::vector<const moho::CClientBase*> ejecters;
      client->CollectEjecters(ejecters);
      for (const moho::CClientBase* const ejecter : ejecters) {
        entry.ejectedBy.push_back(static_cast<std::uint8_t>(ejecter->GetIndex()));
      }
      roster.entries.push_back(std::move(entry));
    }
    return roster;
  }

  void CRemoteClientManager::ProcessClients(moho::CMessage& message)
  {
    if (mOnCommand) {
      mOnCommand(message);
    }
  }

  // Everything else: the stand-in's answer, or with none (a server session, WP11.4) that of a client with no peers:
  // the base class's peer loops would wait forever with no clients (`DoBeat`), write past its empty client table
  // (`CreateLocalClient`) or send peer messages through `ProcessClients`, which here goes to the server.

  moho::IClient* CRemoteClientManager::AddRosterEntry(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId, const bool local
  )
  {
    if (idx < 0 || static_cast<std::size_t>(idx) >= wire::SRoster::kMaxEntries) {
      return nullptr;
    }
    wire::SRoster roster{};
    roster.localIndex = local ? idx : mLocalIndex;
    for (const std::unique_ptr<CRosterClient>& client : mRoster) {
      if (client) {
        roster.entries.push_back(client->Entry());
      }
    }
    wire::SRosterEntry entry{};
    entry.index = static_cast<std::uint8_t>(idx);
    entry.name = name != nullptr ? name : "";
    if (entry.name.size() > wire::SRosterEntry::kMaxNameBytes) {
      entry.name.resize(wire::SRosterEntry::kMaxNameBytes);
    }
    entry.ownerId = ownerId;
    entry.sources.push_back(static_cast<std::uint8_t>(sourceId));
    entry.connected = true;
    roster.entries.push_back(std::move(entry));
    ApplyRoster(roster, {});
    return RosterClient(idx);
  }

  moho::IClient* CRemoteClientManager::CreateLocalClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateLocalClient(name, idx, ownerId, sourceId) : AddRosterEntry(name, idx, ownerId, sourceId, true);
  }

  moho::IClient* CRemoteClientManager::CreateNetClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId,
    moho::INetConnection* const connection
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateNetClient(name, idx, ownerId, sourceId, connection)
                               : AddRosterEntry(name, idx, ownerId, sourceId, false);
  }

  moho::IClient* CRemoteClientManager::CreateReplayClient(gpg::Stream** const stream, moho::BVIntSet* const sources)
  {
    return mStandIn != nullptr ? mStandIn->CreateReplayClient(stream, sources) : nullptr;
  }

  moho::IClient* CRemoteClientManager::CreateNullClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateNullClient(name, idx, ownerId, sourceId) : AddRosterEntry(name, idx, ownerId, sourceId, false);
  }

  moho::INetConnector* CRemoteClientManager::GetConnector()
  {
    return mStandIn != nullptr ? mStandIn->GetConnector() : CClientManagerImpl::GetConnector();
  }

  // The roster, once the server has sent one (WP11.4).

  size_t CRemoteClientManager::NumberOfClients()
  {
    if (mHaveRoster) {
      return mRoster.size();
    }
    return mStandIn != nullptr ? mStandIn->NumberOfClients() : CClientManagerImpl::NumberOfClients();
  }

  moho::IClient* CRemoteClientManager::GetClient(const int idx)
  {
    if (mHaveRoster) {
      return RosterClient(idx);
    }
    return mStandIn != nullptr ? mStandIn->GetClient(idx) : CClientManagerImpl::GetClient(idx);
  }

  moho::IClient* CRemoteClientManager::GetClientWithData(const int32_t ownerId)
  {
    if (mHaveRoster) {
      for (const std::unique_ptr<CRosterClient>& client : mRoster) {
        if (client && client->GetOwnerId() == ownerId) {
          return client.get();
        }
      }
      return nullptr;
    }
    return mStandIn != nullptr ? mStandIn->GetClientWithData(ownerId) : CClientManagerImpl::GetClientWithData(ownerId);
  }

  moho::IClient* CRemoteClientManager::GetLocalClient()
  {
    if (mHaveRoster) {
      return RosterClient(mLocalIndex);
    }
    return mStandIn != nullptr ? mStandIn->GetLocalClient() : CClientManagerImpl::GetLocalClient();
  }

  void CRemoteClientManager::SetUIInterface(moho::IClientMgrUIInterface* const uiInterface)
  {
    if (mStandIn != nullptr) {
      mStandIn->SetUIInterface(uiInterface);
    } else {
      CClientManagerImpl::SetUIInterface(uiInterface);
    }
  }

  void CRemoteClientManager::Cleanup()
  {
    if (mStandIn != nullptr) {
      mStandIn->Cleanup();
    } else if (!std::exchange(mReady, true) && mOnLoaded) {
      mOnLoaded(); // the server's start barrier: it starts when every player has loaded
    }
  }

  bool CRemoteClientManager::IsEveryoneReady()
  {
    // A server session: the server holds the game until everyone has loaded, so this side is ready once it has.
    return mStandIn != nullptr ? mStandIn->IsEveryoneReady() : mReady;
  }

  void CRemoteClientManager::SetSimRate(const int rate)
  {
    if (mStandIn != nullptr) {
      mStandIn->SetSimRate(rate);
    }
    // A server session: the server sets the rate (game speed requests are a later plan item).
  }

  int CRemoteClientManager::GetSimRate()
  {
    if (mHaveServerSimRate) {
      return mServerSimRate;
    }
    return mStandIn != nullptr ? mStandIn->GetSimRate() : CClientManagerImpl::GetSimRate();
  }

  int CRemoteClientManager::GetSimRateRequested()
  {
    return mStandIn != nullptr ? mStandIn->GetSimRateRequested() : CClientManagerImpl::GetSimRateRequested();
  }

  void CRemoteClientManager::BroadcastIntParam(const int value)
  {
    if (mStandIn != nullptr) {
      mStandIn->BroadcastIntParam(value);
    }
  }

  void CRemoteClientManager::DoBeat()
  {
    if (mStandIn != nullptr) {
      mStandIn->DoBeat();
    }
  }

  void CRemoteClientManager::SelectEvent(const HANDLE ev)
  {
    if (mStandIn != nullptr) {
      mStandIn->SelectEvent(ev);
    } else {
      CClientManagerImpl::SelectEvent(ev);
    }
  }

  void CRemoteClientManager::GetPartiallyQueuedBeat(int& out)
  {
    if (mStandIn != nullptr) {
      mStandIn->GetPartiallyQueuedBeat(out);
    } else {
      CClientManagerImpl::GetPartiallyQueuedBeat(out);
    }
  }

  void CRemoteClientManager::GetAvailableBeat(int& out)
  {
    if (mStandIn != nullptr) {
      mStandIn->GetAvailableBeat(out);
    } else {
      CClientManagerImpl::GetAvailableBeat(out);
    }
  }

  void CRemoteClientManager::UpdateStates(const int beat)
  {
    if (mStandIn != nullptr) {
      mStandIn->UpdateStates(beat);
    } else {
      CClientManagerImpl::UpdateStates(beat);
    }
  }

  moho::SSendStampWindow CRemoteClientManager::GetBetween(const int since)
  {
    return mStandIn != nullptr ? mStandIn->GetBetween(since) : CClientManagerImpl::GetBetween(since);
  }

  moho::SClientBottleneckInfo CRemoteClientManager::GetBottleneckInfo()
  {
    return mStandIn != nullptr ? mStandIn->GetBottleneckInfo() : CClientManagerImpl::GetBottleneckInfo();
  }

  void CRemoteClientManager::Debug()
  {
    if (mStandIn != nullptr) {
      mStandIn->Debug();
    } else {
      CClientManagerImpl::Debug();
    }
  }

  void CRemoteClientManager::Disconnect()
  {
    if (mStandIn != nullptr) {
      mStandIn->Disconnect();
    } else {
      CClientManagerImpl::Disconnect();
    }
  }
} // namespace faf::remote::client
