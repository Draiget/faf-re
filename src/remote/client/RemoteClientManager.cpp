#include "remote/client/RemoteClientManager.h"

#include <utility>

// Engine addition, server mode: see RemoteClientManager.h.

namespace faf::remote::client
{
  CRemoteClientManager::CRemoteClientManager(CommandHandler onCommand, moho::IClientManager* const standIn)
    : moho::CClientManagerImpl(0u, nullptr, 0, false)
    , mOnCommand(std::move(onCommand))
    , mStandIn(standIn)
  {}

  CRemoteClientManager::~CRemoteClientManager() = default;

  void CRemoteClientManager::ProcessClients(moho::CMessage& message)
  {
    if (mOnCommand) {
      mOnCommand(message);
    }
  }

  // Everything else: the stand-in's answer, or with none that of a client manager without peers.

  moho::IClient* CRemoteClientManager::CreateLocalClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateLocalClient(name, idx, ownerId, sourceId)
                               : CClientManagerImpl::CreateLocalClient(name, idx, ownerId, sourceId);
  }

  moho::IClient* CRemoteClientManager::CreateNetClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId,
    moho::INetConnection* const connection
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateNetClient(name, idx, ownerId, sourceId, connection)
                               : CClientManagerImpl::CreateNetClient(name, idx, ownerId, sourceId, connection);
  }

  moho::IClient* CRemoteClientManager::CreateReplayClient(gpg::Stream** const stream, moho::BVIntSet* const sources)
  {
    return mStandIn != nullptr ? mStandIn->CreateReplayClient(stream, sources)
                               : CClientManagerImpl::CreateReplayClient(stream, sources);
  }

  moho::IClient* CRemoteClientManager::CreateNullClient(
    const char* const name, const int idx, const int32_t ownerId, const unsigned int sourceId
  )
  {
    return mStandIn != nullptr ? mStandIn->CreateNullClient(name, idx, ownerId, sourceId)
                               : CClientManagerImpl::CreateNullClient(name, idx, ownerId, sourceId);
  }

  moho::INetConnector* CRemoteClientManager::GetConnector()
  {
    return mStandIn != nullptr ? mStandIn->GetConnector() : CClientManagerImpl::GetConnector();
  }

  size_t CRemoteClientManager::NumberOfClients()
  {
    return mStandIn != nullptr ? mStandIn->NumberOfClients() : CClientManagerImpl::NumberOfClients();
  }

  moho::IClient* CRemoteClientManager::GetClient(const int idx)
  {
    return mStandIn != nullptr ? mStandIn->GetClient(idx) : CClientManagerImpl::GetClient(idx);
  }

  moho::IClient* CRemoteClientManager::GetClientWithData(const int32_t ownerId)
  {
    return mStandIn != nullptr ? mStandIn->GetClientWithData(ownerId) : CClientManagerImpl::GetClientWithData(ownerId);
  }

  moho::IClient* CRemoteClientManager::GetLocalClient()
  {
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
    } else {
      CClientManagerImpl::Cleanup();
    }
  }

  bool CRemoteClientManager::IsEveryoneReady()
  {
    return mStandIn != nullptr ? mStandIn->IsEveryoneReady() : CClientManagerImpl::IsEveryoneReady();
  }

  void CRemoteClientManager::SetSimRate(const int rate)
  {
    if (mStandIn != nullptr) {
      mStandIn->SetSimRate(rate);
    } else {
      CClientManagerImpl::SetSimRate(rate);
    }
  }

  int CRemoteClientManager::GetSimRate()
  {
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
    } else {
      CClientManagerImpl::BroadcastIntParam(value);
    }
  }

  void CRemoteClientManager::DoBeat()
  {
    if (mStandIn != nullptr) {
      mStandIn->DoBeat();
    } else {
      CClientManagerImpl::DoBeat();
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
