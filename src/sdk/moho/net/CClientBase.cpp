#include "CClientBase.h"

#include <mutex>

#include "CClientManagerImpl.h"
#include "ECmdStreamOp.h"
#include "gpg/core/streams/MemBufferStream.h"
using namespace moho;

BVIntSet* CClientBase::GetValidCommandSources() {
	return &mValidCommandSources;
}

bool CClientBase::NoEjectionPending() {
	std::scoped_lock lock(mManager->mLock);
	return mEjectPending;
}

const msvc8::vector<int32_t>* CClientBase::GetLatestAcksVector() {
	std::scoped_lock lock(mManager->mLock);
	return &mLatestAckReceived;
}

void CClientBase::GetLatestBeatDispatchedRemote(uint32_t& out) {
	std::scoped_lock lock(mManager->mLock);
	out = mLatestBeatDispatchedRemote;
}

void CClientBase::GetAvailableBeatRemote(uint32_t& out) {
	std::scoped_lock lock(mManager->mLock);
	out = mAvailableBeatRemote;
}

void CClientBase::ReceiveChat(gpg::MemBuffer<const char> data) {
	CMessage msg{ ECmdStreamOp::Replay_ReceiveChat };
	msg.Append(data, data.Size());
	Process(msg);
}

void CClientBase::GetQueuedBeat(uint32_t& out) {
	std::scoped_lock lock(mManager->mLock);
	out = mQueuedBeat;
}

void CClientBase::Eject() {
	std::scoped_lock lock(mManager->mLock);
	if (mEjectPending) {
		return;
	}

	mEjectPending = true;
	mReady = true;
	Open();
	ProcessEject(mManager, mQueuedBeat);
}

int32_t CClientBase::GetSimRate() {
	std::scoped_lock lock(mManager->mLock);
	return mSimRate;
}

CClientBase::CClientBase(
	int clientIndex, 
	CClientManagerImpl* manager, 
	const char* name,
	LaunchInfoBase* launchInfo,
	BVIntSet& commandSources,
	uint32_t sourceId
) :
	IClient(name, clientIndex, launchInfo),
	mManager(manager),
	mValidCommandSources(commandSources),
	mCommandSourceId(sourceId)
{
}

void CClientBase::ProcessEject(CClientManagerImpl* manager, const uint32_t beat) const {
	CMessage msg{ ECmdStreamOp::Replay_Eject };
	CMessageStream s(msg, CMessageStream::Access::kReadWrite);
	s.Write(mIndex);
	s.Write(beat);
	manager->ProcessClients(msg);

	for (CClientBase* client : manager->mClients) {
		client->RemoveEjectRequestsByRequester(this);
	}
}

void CClientBase::RemoveEjectRequestsByRequester(const CClientBase* requester) {
	if (mEjectRequests.empty()) {
		return;
	}

	for (std::size_t i = mEjectRequests.size(); i-- > 0; ) {
		if (mEjectRequests[i]->mRequester == requester) {
			mEjectRequests.erase(mEjectRequests.begin() + static_cast<std::ptrdiff_t>(i));
		}
	}
}
