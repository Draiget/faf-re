// ReSharper disable CppTooWideScope
#include "CNetUDPConnection.h"

#include "CLobby.h"
#include "CNetUDPConnector.h"
#include "ECmdStreamOp.h"
#include "ELobbyMsg.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

int32_t net_SendDelay = 0; // 0x00F58DE4
int32_t net_AckDelay = 0; // 0x00F58DE0
int32_t net_DebugLevel = 0; // 0x010A6384
float net_ResendPingMultiplier = 1; // 0x00F58DFC
int32_t net_ResendDelayBias = 0; // 0x00F58E00
int32_t net_MinResendDelay = 0; // 0x00F58DE8
int32_t net_MaxResendDelay = 0; // 0x00F58DEC
int32_t net_MaxSendRate = 1000; // 0x00F58DF0
int32_t net_LogPackets = 0; // 0x010A6381
int32_t net_MaxBacklog = 0; // 0x00F58DF4

float CNetUDPConnection::GetPing() {
	boost::recursive_mutex::scoped_lock lock{ mConnector->lock_ };
	return mPingTime;
}

float CNetUDPConnection::GetTime() {
	boost::recursive_mutex::scoped_lock lock{ mConnector->lock_ };
	if (!mLastRecv) {
		return -1.0;
	}

	const std::int64_t now = mConnector->GetTime();
	return static_cast<float>(now - mLastRecv) * 0.001f;
}

void CNetUDPConnection::Write(NetDataSpan* data) {
	const uint8_t* begin = data->start;
	const uint8_t* end = data->end;
    const size_t len = static_cast<size_t>(end - begin);
	boost::recursive_mutex::scoped_lock lock{ mConnector->lock_ };

	if (auto* target = mOutputFilterStream) {
		target->VirtWrite(reinterpret_cast<const char*>(begin), len);
	} else {
		mPendingOutputData.VirtWrite(reinterpret_cast<const char*>(begin), len);
	}

	// Schedule earliest send time once:
	// mSendBy = now + net_SendDelay * 1000 (ms > us ticks in bin)
	if (mSendBy.mTime == 0) {
		const std::int64_t now = mConnector->GetTime();
		mSendBy.mTime = now + static_cast<std::int64_t>(net_SendDelay) * 1000;
	}

	// Mark output pending (mHasWritten = 1 in the binary)
	// mHasPendingOutput ?
	mHasWritten = true;

	// Update counters and MD5 of total queued bytes
	mTotalBytesQueued += static_cast<std::uint64_t>(len);
	mTotalBytesQueuedMD5.Update(begin, len);

	// Verbose debug (net_DebugLevel >= 3)
	if (net_DebugLevel >= 3) {
		const auto dig = mTotalBytesQueuedMD5.Digest();
		const auto ts = gpg::FileTimeToString(mConnector->GetTime());

		const unsigned msgType = len ? begin[0] : 0;
		gpg::Debugf("%s: %s: msg type %u queued [%zu bytes, total now %llu, md5 %s]",
			ts.c_str(), ToString().c_str(), msgType, len,
			static_cast<unsigned long long>(mTotalBytesQueued),
			dig.ToString().c_str());
	}

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

void CNetUDPConnection::Close() {
	boost::recursive_mutex::scoped_lock lock{ mConnector->lock_ };
	if (mOutputShutdown) {
		return;
	}

	if (mOutputFilterStream != nullptr) {
		mOutputFilterStream->VirtClose(gpg::Stream::ModeSend);
		delete mOutputFilterStream;
	}

	mPendingOutputData.VirtClose(gpg::Stream::ModeSend);
	mOutputShutdown = true;
	mHasWritten = false;

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

msvc8::string CNetUDPConnection::ToString() {
	const auto host = NET_GetHostName(mAddr);
	return gpg::STR_Printf("%s:%d", host.c_str(), static_cast<int>(mPort));
}

void CNetUDPConnection::ScheduleDestroy() {
	boost::recursive_mutex::scoped_lock lock{ mConnector->lock_ };
	Close();
	mScheduleDestroy = true;

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

CNetUDPConnection::CNetUDPConnection(
	CNetUDPConnector& connector,
	const u_long address,
	const u_short port,
	const ENetConnectionState state
) :
	mConnector(&connector), // [esi+0x418]               
	mAddr(address), // [esi+0x41C]
	mPort(port), // [esi+0x420]
	mOurCompressionMethod(net_CompressionMethod), // [esi+0x424]
	mState(state),
	mUnAckedPayloads(),
	mEarlyPackets(), // [esi+0x42C]
	mMessage()
{
	// Init timers and timestamps
	// (ASM zeroes a lot of POD around; we rely on default ctor or explicit zeros above)
	mLastSend.Reset();
	mSendTime = 0;
	mLastRecv = 0;
	mLastKeepAlive = 0;

	// Init small scratch buffers
	std::memset(mNonceA, 0, sizeof(mNonceA));
	std::memset(mNonceB, 0, sizeof(mNonceB));
	v293 = 0;
	mTime1 = 0;

	// Initialize sliding timings array (128 * 16 bytes in ASM via eh-vector-ctor)
	for (auto& t : mTimings) {
		t = {}; // zero-init one slot
	}

	// Initialize MD5 accumulators
	mTotalBytesQueuedMD5.Reset();
	mTotalBytesSentMD5.Reset();
	mTotalBytesReceivedMD5.Reset();
	mTotalBytesDispatchedMD5.Reset();

	// Streams: output first (at +0x4B8)
	// ctor call observed in ASM
	// NOTE: mOutputData default-constructs; ensure default ctor matches
	// the in-game PipeStream behavior (no pending buffers, etc.)
	// Then clear filter & flags (ASM stores 0 to [0x500],[0x508],[0x50C],[0x50D])
	mOutputFilterStream = nullptr;
	mFlushedOutputData = 0;
	mOutputShutdown = false;
	mSentShutdown = false;

	// Streams: input (at +0x0D98)
	// ctor call observed in ASM
	// Set ring pointers/layout around [0x0DE8..0x0DF4] - wrap:
	{
		// Clear filter and EoI flags (matches writes at +0xDE0, +0xDE4, +0xDE5)
		mFilterStream = nullptr;
		mReceivedEndOfInput = false;
		mDispatchedEndOfInput = false;
		// Nothing else to do: PipeStream() ctor already allocated a buffer
		// and set [mReadHead==mReadEnd==begin(), mWriteHead==mWriteStart==begin(), mWriteEnd==end()].
	}

	mSendBy.Reset();

	// Link this connection into connector's intrusive list
	// ASM: uses node at +0x410; do the same in Attach().
	connector.mConnections.push_front(this);

	// Select SEND compression (controlled by Moho::net_CompressionMethod)
	switch (mOurCompressionMethod) {
	case NETCOMP_None:
		// Log: "NET: using no compression for send"
		gpg::Logf("NET: using no compression for send: %s", CNetUDPConnection::ToString().c_str());
		break;
	case NETCOMP_Deflate: {
		gpg::Logf("NET: using deflate compression for send: %s", CNetUDPConnection::ToString().c_str());

		// Allocate filter (operator new 0x460 seen in asm).
		// Construct zlib filter for deflate (send path).
		const auto filterStream = new gpg::ZLibOutputFilterStream(&mPendingOutputData, gpg::FLOP_Deflate);
		if (filterStream) {
			if (mOutputFilterStream) {
				operator delete(mOutputFilterStream);
			}
			mOutputFilterStream = filterStream;
		} else {
			gpg::Warnf("NET: failed to allocate ZLibOutputFilterStream, falling back to no compression");
			mOurCompressionMethod = NETCOMP_None;
		}
		break;
	}
	default:
		gpg::Warnf("Unknown compression method %d, assuming none.", static_cast<int>(mOurCompressionMethod));
		mOurCompressionMethod = NETCOMP_None;
		break;
	}

	// Initialize pings structure and ping time
	std::memset(&mPings, 0, sizeof(mPings));
	mPingTime = 0.0f;
}

CNetUDPConnection::~CNetUDPConnection() {
	constexpr int poolCap = 0x14u;

	auto recyclePacket = [this](SNetPacket* p) noexcept {
		if (!p) {
			return;
		}
		if (mConnector->mPacketPoolSize >= poolCap) {
			operator delete(p);
		} else {
			mConnector->mPacketList.push_back(p);
			++mConnector->mPacketPoolSize;
		}
	};

	// Un-acked
	for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end(); )
	{
		auto* n = it.node();
		auto* p = static_cast<SNetPacket*>(n);
		it = mUnAckedPayloads.erase(it);
		recyclePacket(p);
	}

	// Early
	for (auto it = mEarlyPackets.begin(); it != mEarlyPackets.end(); )
	{
		auto* n = it.node();
		auto* p = static_cast<SNetPacket*>(n);
		it = mEarlyPackets.erase(it);
		recyclePacket(p);
	}
}

// 0x00486910
void CNetUDPConnection::CreateFilterStream() {
	mState = kNetStateAnswering;

	CMessage msg{ ELobbyMsg::LOBMSG_ConnMade };
	mInputBuffer.Write(msg.mBuff.Data(), msg.mBuff.Size());

	if (mReceivedCompressionMethod == NETCOMP_None) {
		gpg::Logf("NET: using no compression for receives from %s", ToString().c_str());

		// No filter needed on receive side; drop any old one.
		if (mFilterStream) {
			delete mFilterStream;
			mFilterStream = nullptr;
		}
		return;
	} 

	if (mReceivedCompressionMethod != NETCOMP_Deflate) {
		GPG_UNREACHABLE()
	}

	gpg::Logf("NET: using deflate compression for receives from %s", ToString().c_str());

	const auto* const old = mFilterStream;
	mFilterStream = new gpg::ZLibOutputFilterStream(&mInputBuffer, gpg::FLOP_Deflate);
	delete old;
}

bool CNetUDPConnection::ProcessConnect(const SNetPacket* packet) {
	const auto& pConnect = *reinterpret_cast<const SPacketBodyConnect*>(packet->data);

	// Obsolete CONNECT: ignore
	if (pConnect.time <= mTime1) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring obsolete CONNECT",
				GetPort(), ToString().c_str());
		}
		return true;
	}

	// Fresh packet: record last-recv wall clock from peer
	mLastRecv = packet->mSentTime;

	// Unknown compression method
	if (pConnect.comp >= NETCOMP_Deflate + 1) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring connect w/ unknown compression method (%u)",
				GetPort(), ToString().c_str(), static_cast<unsigned>(pConnect.comp));
		}
		return true;
	}

	switch (mState) {
	case kNetStatePending:    // 0
	case kNetStateAnswering:  // 2
	{
		// Copy remote nonce and adopt compression.
		std::memcpy(mNonceB, pConnect.nonceA, sizeof(mNonceB));
		mTime1 = pConnect.time;
		mReceivedCompressionMethod = pConnect.comp;

		// Binary rebinds/repurposes packet memory to this connection.
		AdoptPacket(packet);
		return true;
	}
	case kNetStateConnecting: // 1 (Connecting)
	{
		std::memcpy(mNonceB, pConnect.nonceA, sizeof(mNonceB));
		mTime1 = pConnect.time;
		mReceivedCompressionMethod = pConnect.comp;

		AdoptPacket(packet);

		// Transition to Answering
		mState = kNetStateAnswering;
		return true;
	}
	case kNetStateEstablishing: // 3
	case kNetStateTimedOut:     // 4
	{
		// Move to Retired and shut down input.
		mState = kNetStateTimedOut; // 5
		mReceivedEndOfInput = true;

		// Close input side (ModeBoth per binary)
		mInputBuffer.Close(gpg::Stream::ModeBoth);

		if (mConnector->event_) {
#if defined(_WIN32)
			WSASetEvent(mConnector->event_);
#endif
		}
		return false;
	}
	default:
		GPG_UNREACHABLE()
		return false;
	}
}

void CNetUDPConnection::ProcessAnswer(const SNetPacket* packet) {
	const auto& pAnswer = *reinterpret_cast<const SPacketBodyAnswer*>(packet->data);

	// Strict size check: expected 92 bytes
	if (packet->mSize != 92) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring wrong length ANSWER (got %d bytes, required %d)",
				GetPort(), ToString().c_str(), packet->mSize, 92);
		}
		return;
	}

	// Obsolete ANSWER
	if (pAnswer.time <= mTime1) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring obsolete ANSWER",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Receiver nonce must match what we sent earlier
	if (std::memcmp(mNonceA, pAnswer.nonceB, sizeof(mNonceA)) != 0) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER with wrong receiver nonce",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Unknown compression method
	if (pAnswer.comp >= 2u) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring answer w/ unknown compression method (%u)",
				GetPort(), ToString().c_str(), static_cast<unsigned>(pAnswer.comp));
		}
		return;
	}

	// Must be in Connecting (1) or Answering (2)
	if (mState == kNetStatePending) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on pending connection",
				GetPort(), ToString().c_str());
		}
		return;
	}

	if (!(mState == kNetStateConnecting || mState == kNetStateAnswering)) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on established connection",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Update remote timing/window from header.
	UpdatePingInfoFromPacket(*packet);

	// Refresh peer time and negotiated params.
	mLastRecv = packet->mSentTime;
	std::memcpy(mNonceB, pAnswer.nonceA, sizeof(mNonceB));
	mTime1 = pAnswer.time;
	mReceivedCompressionMethod = pAnswer.comp;

	// Enable RX filter according to negotiated compression. 
	CreateFilterStream();

	// Binary rebinds/repurposes packet memory to this connection. 
	AdoptPacket(packet);

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

bool CNetUDPConnection::ProcessAckInternal(const SNetPacket* packet) {
	switch (mState) {
	case kNetStatePending: { // 0
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Pending connection.",
				GetPort(), ToString().c_str());
		}
		return false;
	}
	case kNetStateConnecting: { // 1
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Connecting connection.",
				GetPort(), ToString().c_str());
		}
		return false;
	}
	case kNetStateAnswering: // 2
		// First ACK on Active path turns on RX filter if not set.
		CreateFilterStream();
	case kNetStateEstablishing: // 3
		break; // proceed
	case kNetStateTimedOut: // 4
		// Transition per binary: Error -> Closing before handling.
		mState = kNetStateEstablishing;
		break;
	case kNetStateErrored: { // 5
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Errored connection.",
				GetPort(), ToString().c_str());
		}
		return false;
	}
	default:
		GPG_UNREACHABLE()
		return false;
	}

	// Validate that remote's ExpectedSeq isn't ahead of what we've sent.
	const uint16_t expected = packet->header.mExpectedSequenceNumber;
	if (static_cast<int16_t>(mNextSequenceNumber - expected) < 0) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessHeader(): ignoring acknowledgement of data we haven't sent (packet=%u, next=%u)",
				GetPort(), ToString().c_str(),
				static_cast<unsigned>(expected),
				static_cast<unsigned>(mNextSequenceNumber));
		}
		return false;
	}

	// Fold in timing/window accounting first.
	UpdatePingInfoFromPacket(*packet);

	// Ack window: ack everything older than 'expected', and also bits in early mask for last 32.
	const uint32_t earlyMask = packet->header.mEarlyMask;

	// Iterate intrusive list of un-acked payloads. We must be tolerant to node deletion while iterating.
	for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end(); ++it) {
		auto* n = it.node();
		auto* p = static_cast<SNetPacket*>(n);
		const int16_t d = static_cast<int16_t>(p->header.mSequenceNumber - expected);

		bool ack = false;
		if (d < 0) {
			// Packet seq < expected: implicitly acknowledged.
			ack = true;
		} else {
			// d in [1..32] acknowledged by early mask bit (d-1).
			const uint16_t idx = static_cast<uint16_t>(d - 1);
			if (idx <= 0x1F) {
				ack = ((earlyMask >> idx) & 1u) != 0;
			}
		}

		if (ack) {
			// Return packet to connector's pool (binary calls CNetUDPConnector::AddPacket(&p, connector))
			if (mConnector) {
				mConnector->AddPacket(p);
			}
			// The ReleasePacket should also unlink from mUnAckedPayloads; if not, remove explicitly here.
			// mUnAckedPayloads.erase(prev_it) - implement with your intrusive list API
		}
	}

	// Track far end's window head if it advanced.
	if (static_cast<int16_t>(expected - mRemoteExpectedSequenceNumber) > 0) {
		mRemoteExpectedSequenceNumber = expected;
	}

	return true;
}

void CNetUDPConnection::ProcessData(SNetPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return;
	}

	AdoptPacket(packet);

	// Compute delta = seq - expected
	const uint16_t seq = packet->header.mSequenceNumber;
	const int16_t  delta = static_cast<int16_t>(seq - mExpectedSequenceNumber);

	if (delta < 0) {
		// Repeat of old DATA
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessData(): ignoring repeat of old DATA (seqno=%d, expected=%d)",
				GetPort(), ToString().c_str(),
				static_cast<unsigned>(seq),
				static_cast<unsigned>(mExpectedSequenceNumber));
		}
		return;
	}

	if (delta > 32) {
		// Too far in the future
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessData(): ignoring DATA from too far in the future (seqno=%d, expected=%d, delta=%d)",
				GetPort(), ToString().c_str(),
				static_cast<unsigned>(seq),
				static_cast<unsigned>(mExpectedSequenceNumber),
				static_cast<int>(delta));
		}
		return;
	}

	// Queue packet into early set (sorted, unique)
	const bool inserted = InsertEarlySorted(packet);
	// Update last receive time regardless; asm sets mLastRecv = pack->mSentTime at insert path
	mLastRecv = packet->mSentTime;

	if (!inserted) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessData(): ignoring repeat of future DATA (seqno=%d, expected=%d)",
				GetPort(), ToString().c_str(),
				static_cast<unsigned>(seq),
				static_cast<unsigned>(mExpectedSequenceNumber));
		}
		if (mConnector) {
			mConnector->AddPacket(packet);
		}
		return;
	}

	// Drain in-order packets from the head
	bool progressed = false;
	while (true) {
		if (mEarlyPackets.empty()) {
			break;
		}

		// End-of-stream guard
		if (mReceivedEndOfInput) {
			if (net_DebugLevel) {
				gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring DATA after end-of-stream",
					GetPort(), ToString().c_str());
			}

			SNetPacket* drop = EarlyPopFront();
			if (drop && mConnector) {
				mConnector->AddPacket(drop);
			}
			continue;
		}

		// Peek head; stop if not the expected sequence
		auto* n = mEarlyPackets.begin().node();
		auto* headPacket = static_cast<SNetPacket*>(n);
		if (headPacket->header.mSequenceNumber != mExpectedSequenceNumber) {
			break;
		}

		// Consume this packet
		ConsumePacketHeaderData(headPacket);
		progressed = true;
	}

	// Rebuild ACK mask from remaining early packets
	EarlyRebuildAckMask(mExpectedSequenceNumber, mMask);

	// Signal connector event if progressed (matches SetEvent path in asm)
#if defined(_WIN32)
	if (progressed && mConnector && mConnector->mSelectedEvent) {
		SetEvent(mConnector->mSelectedEvent);
	}
#endif
}

bool CNetUDPConnection::ProcessAck(const SNetPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;
	return true;
}

bool CNetUDPConnection::ProcessKeepAlive(const SNetPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;
	AdoptPacket(packet); // SPacket::SPacket(pkt, this)
	return true;
}

bool CNetUDPConnection::ProcessGoodbye(const SNetPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;

	if (!mReceivedEndOfInput)
	{
		mState = kNetStateErrored;
		mReceivedEndOfInput = true;

		if (mFilterStream) {
			mFilterStream->Close(gpg::Stream::ModeBoth); // VirtClose(2)
			const auto* z = mFilterStream;
			mFilterStream = nullptr;
			delete z; // vtable dtr in asm
		}

		mInputBuffer.Close(gpg::Stream::ModeBoth);
#if defined(_WIN32)
		if (mConnector && mConnector->mSelectedEvent) {
			SetEvent(mConnector->mSelectedEvent);
		}
#endif
	}

	return true;
}

int64_t CNetUDPConnection::CalcResendDelay(const SNetPacket* packet) const {
	const float baseMs = 
		mPingTime * net_ResendPingMultiplier + 
		static_cast<float>(net_ResendDelayBias);

	int rc = packet->mResendCount;
	if (rc > 3) {
		rc = 3;
	}

	int delayMs = static_cast<int>((1 << rc) * baseMs);
	if (delayMs > net_MaxResendDelay) {
		delayMs = net_MaxResendDelay;
	}
	if (delayMs < net_MinResendDelay) {
		delayMs = net_MinResendDelay;
	}

	return static_cast<int64_t>(delayMs) * 1000LL;
}

int CNetUDPConnection::GetBacklog(const int64_t time) {
	if (mSendTime != 0) {
		const int result = mSendTime - (time - mLastSend.mTime) * net_MaxSendRate * 0.000001;
		if (result > 0) {
			return result;
		}
		mSendTime = 0;
	}
	return 0;
}

int CNetUDPConnection::GetBacklogTimeout(const LONGLONG time, int& timeout) {
	const int backlog = GetBacklog(time);
	if (backlog > net_MaxBacklog) {
		timeout = 1000 * (backlog - net_MaxBacklog) / net_MaxSendRate;
		return false;
	}

	timeout = 0;
	return true;
}

int64_t CNetUDPConnection::TimeSince(const int64_t time) const {
	const int64_t since = (time - mConnector->GetTime()) / 1000;
	if (since < 0) {
		return 0;
	}
	return since;
}

int64_t CNetUDPConnection::SendData() {
	if (mDestroyed) { 
		return -1;
	}

	switch (mState)
	{
	case kNetStatePending:
	case kNetStateErrored:
		if (mScheduleDestroy) {
			mDestroyed = true;
			return -1;
		}
		return -1;

	case kNetStateConnecting:
	{
		if (mScheduleDestroy) {
			mDestroyed = true;
			return -1;
		}

		if (mInResponseTo != 0 || mConnector->GetTime() - mLastSend.mTime > 1'000'000) {
			SendPacket(NewConnectPacket());
		}

		return TimeSince(mLastSend.mTime + 1'000'000);
	}

	case kNetStateAnswering:
	{
		if (mScheduleDestroy) {
			mDestroyed = true;
			return -1;
		}

		if (mInResponseTo != 0 || mConnector->GetTime() - mLastSend.mTime > 1'000'000) {
			SendPacket(NewAnswerPacket());
		}

		return TimeSince(mLastSend.mTime + 1'000'000);
	}

	case kNetStateEstablishing:
	{
		const int64_t curTime = mConnector->GetTime();
		const int64_t idle = curTime - mLastRecv;

		if (curTime - mLastRecv > 10'000'000) {
			if (net_DebugLevel) {
				gpg::Logf("CNetUDPConnection<%u,%s>::SendData(): connection timed out.",
					GetPort(), ToString().c_str());
			}
			mState = kNetStateTimedOut;
			[[fallthrough]];
		} else {
			SNetPacket* packet = nullptr;
			if (!mUnAckedPayloads.empty() && curTime >= mUnAckedPayloads.ListGetNext()->mSentTime) {
				packet = mUnAckedPayloads.ListGetNext();
				packet->ListUnlink();
			} else if (HasPacketWaiting(curTime)) {
				packet = ReadPacket();
			} else if (mScheduleDestroy && mSentShutdown && mUnAckedPayloads.empty()) {
				packet = NewGoodbyePacket();
				mDestroyed = true;
			} else if (curTime >= mLastKeepAlive + mKeepAliveFreqUs) {
				packet = NewPacket(true, 0, KEEPALIVE);
			} else if (mInResponseTo == 0 && curTime >= mSendBy.mTime) {
				packet = NewPacket(true, 0, ACK);
			}

			if (packet) {
				SendPacket(packet);
			}

			if (mFlushedOutputData || mPendingOutputData.GetLength() > 0x1F1) {
				return 0;
			}

			auto since = TimeSince(mLastKeepAlive + mKeepAliveFreqUs);
			if (!mUnAckedPayloads.empty()) {
				const auto sentTime = mUnAckedPayloads.ListGetNext()->mSentTime;
				since = ChooseTimeout(since, TimeSince(sentTime));
			}
			if (mSendBy.mTime != 0 &&
				(mInResponseTo != 0 || mPendingOutputData.GetLength() != 0 || mHasWritten)) 
			{
				since = ChooseTimeout(since, TimeSince(mSendBy.mTime));
			}
			return since;
		}
	}
	case kNetStateTimedOut:
	{
		if (mScheduleDestroy) {
			mDestroyed = true;
			return -1;
		}

		if (mConnector->GetTime() - mLastKeepAlive > mKeepAliveFreqUs) {
			SendPacket(NewPacket(true, 0, KEEPALIVE));
		}
		return TimeSince(mLastKeepAlive + mKeepAliveFreqUs);
	}

	default:
		GPG_UNREACHABLE()
		return -1;
	}
}

bool CNetUDPConnection::HasPacketWaiting(const int64_t nowUs) {
	// Window check (16-bit arithmetic in asm)
	if (static_cast<int16_t>(mNextSequenceNumber - mRemoteExpectedSequenceNumber) > 32) {
		return false;
	}

	gpg::PipeStream* out = &mPendingOutputData;

	// End-of-stream pending? (read head == read end && AtEnd && !mSentShutdown)
	if (mPendingOutputData.mReadHead == mPendingOutputData.mReadEnd && 
		out->VirtAtEnd() &&
		!mSentShutdown)
	{
		return true;
	}

	// Hold-off sending small chunks until mSendBy or keepalive kick-in
	if (nowUs <= mSendBy.mTime &&
		!mFlushedOutputData &&
		nowUs < (mLastKeepAlive + mKeepAliveFreqUs))
	{
		// 497 bytes threshold from asm
		return mPendingOutputData.GetLength() >= kNetPacketMaxPayload;
	}

	// Pending flush request?
	if (mHasWritten) {
		if (mOutputFilterStream) {
			mOutputFilterStream->VirtFlush();
		}
		out->VirtFlush();
		mHasWritten = false;
	}

	// Any bytes available?
	return mPendingOutputData.GetLength() != 0;
}

SNetPacket* CNetUDPConnection::ReadPacket() {
	// clamp payload to wire limit
	unsigned int len = mPendingOutputData.GetLength();
	if (len >= static_cast<unsigned int>(kNetPacketMaxPayload)) {
		len = kNetPacketMaxPayload;
	}

	// allocate with header inheritance (seq/expected/mask)
	SNetPacket* packet = NewPacket(true, static_cast<int>(len), DATA);
	if (!packet) {
		return nullptr;
	}

	// copy payload
	if (len != 0) {
		const auto dst = reinterpret_cast<char*>(&packet->data[0]);

		// fast path if contiguous
		if (len <= static_cast<unsigned int>(mPendingOutputData.mReadEnd - mPendingOutputData.mReadHead)) {
			std::memcpy(dst, mPendingOutputData.mReadHead, len);
			mPendingOutputData.mReadHead += len;
		} else {
			mPendingOutputData.Read(dst, len); // virtual read
		}

		// adjust "flushed output" debt
		if (len >= mFlushedOutputData) {
			mFlushedOutputData = 0;
		} else {
			mFlushedOutputData -= len;
		}

		// stats + md5
		mTotalBytesSent += len;
		mTotalBytesSentMD5.Update(dst, len);

		// advance local sequence
		++mNextSequenceNumber;
		return packet;
	}

	// zero-length DATA > EOF marker;
	// flag shutdown and advance seq
	++mNextSequenceNumber;
	mSentShutdown = true;
	return packet;
}

SNetPacket* CNetUDPConnection::NewConnectPacket() const {
	constexpr auto payloadSize = sizeof(SPacketBodyConnect);

	// allocate with no header inheritance (seq/expected/mask all zero)
	SNetPacket* packet = NewPacket(false, payloadSize, CONNECT);
	if (!packet) {
		return nullptr;
	}

	auto& connectPacket = packet->As<SPacketBodyConnect>();

	connectPacket.protocol = ENetProtocolType::kUdp;
	connectPacket.time = mConnector->GetTime();
	connectPacket.comp = mOurCompressionMethod;

	std::memcpy(connectPacket.nonceA, mNonceA, 32);
	return packet;
}

SNetPacket* CNetUDPConnection::NewAnswerPacket() const {
	constexpr auto payloadSize = sizeof(SPacketBodyAnswer);

	// allocate with no header inheritance (seq/expected/mask all zero)
	SNetPacket* packet = NewPacket(false, payloadSize, ANSWER);
	if (!packet) {
		return nullptr;
	}

	auto& answerPacket = packet->As<SPacketBodyAnswer>();

	answerPacket.protocol = ENetProtocolType::kUdp;
	answerPacket.time = mConnector->GetTime();
	answerPacket.comp = mOurCompressionMethod;

	std::memcpy(answerPacket.nonceA, mNonceA, 32);
	std::memcpy(answerPacket.nonceB, mNonceB, 32);
	return packet;
}

SNetPacket* CNetUDPConnection::NewGoodbyePacket() const {
	SNetPacket* packet = NewPacket(false, 0, GOODBYE);
	if (!packet) {
		return nullptr;
	}

	return packet;
}

SNetPacket* CNetUDPConnection::NewPacket(const bool inherit, const int size, const EPacketState state) const {
	// take from connector's pool or allocate
	SNetPacket* pkt;
	if (mConnector->mPacketList.mNext != &mConnector->mPacketList) {
		--mConnector->mPacketPoolSize;
		pkt = reinterpret_cast<SNetPacket*>(mConnector->mPacketList.mNext);
		// unlink from pool
		pkt->mPrev->mNext = pkt->mNext;
		pkt->mNext->mPrev = pkt->mPrev;
	} else {
		// 536 bytes (0x218 from asm)
		pkt = new SNetPacket();
		if (!pkt) {
			return nullptr;
		}
	}
	// reset intrusive node
	pkt->mNext = pkt;
	pkt->mPrev = pkt;

	// zero resend counter and set wire sizes/state
	pkt->mResendCount = 0;
	pkt->mSize = static_cast<int32_t>(size) + kNetPacketHeaderSize;
	pkt->header.mState = state;

	// sequence/ack header inheritance
	pkt->header.mSequenceNumber = inherit ? mNextSequenceNumber : 0;
	pkt->header.mExpectedSequenceNumber = inherit ? mExpectedSequenceNumber : 0;
	pkt->header.mEarlyMask = inherit ? mMask : 0u;

	// payload length always set in header (even for control packets)
	pkt->header.mPayloadLength = static_cast<std::uint16_t>(size);

	return pkt;
}

void CNetUDPConnection::SendPacket(SNetPacket* packet) {
	packet->header.mSerialNumber = mNextSerialNumber;
	packet->header.mInResponseTo = mInResponseTo;

#if defined(_WIN32)
	sockaddr_in to{};
	to.sin_family = AF_INET;
	to.sin_port = htons(mPort);
	to.sin_addr.s_addr = htonl(mAddr);
#else
#error "Implement me on non-Windows platform!"
#endif

	const auto payloadLen = static_cast<int>(packet->GetPayloadSize());
	const auto payload = static_cast<const char*>(packet->GetPayload());
	sendto(mConnector->socket_, payload, payloadLen, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to));

	const int64_t nowUs = mConnector->GetTime();
	mConnector->LogPacket(0, nowUs, mAddr, mPort, payload, payloadLen);

	if (packet->header.mState == DATA) {
		++packet->mResendCount;
		packet->mSentTime = nowUs + CalcResendDelay(packet); // microseconds
		InsertUnAckedSorted(packet);
	} else {
		// Return to connector pool immediately for any other:
		// CONNECT, ANSWER, RESETSERIAL, SERIALRESET, ACK, KEEPALIVE, GOODBYE, NATTRAVERSAL
		mConnector->AddPacket(packet);
	}

	if (net_DebugLevel >= 2) {
		const auto pktStr = packet->ToString();
		const auto connStr = ToString();
		const auto timeStr = gpg::FileTimeToString(gpg::time::GetTime());
		gpg::Debugf("%s: send %s, %s",
			timeStr.c_str(),
			connStr.c_str(),
			pktStr.c_str());
	}

	++mNextSerialNumber;
	mInResponseTo = 0;

	if (mPendingOutputData.GetLength()) {
		// time in us
		mSendBy.mTime = nowUs + 1000LL * net_SendDelay;
	} else {
		mSendBy.mTime = 0;
	}

	mTimings[packet->header.mSerialNumber & 0x7F].mSource = packet->header.mSerialNumber;
	mTimings[packet->header.mSerialNumber & 0x8000007F].mTime.Reset();

	mSendTime = packet->mSize + GetBacklog(nowUs);
	mLastSend.mTime = nowUs;

	if (packet->header.mState != KEEPALIVE) {
		mLastKeepAlive = nowUs;
	}

	if (packet->header.mState == GOODBYE) {
		mKeepAliveFreqUs = 2'000'000; // 2s
	}
}

void CNetUDPConnection::FlushInput() {
	if (!mScheduleDestroy && !mReceivedEndOfInput) {
		if (mFilterStream != nullptr) {
			mFilterStream->VirtFlush();
		}
		mInputBuffer.VirtFlush();
	}
}

bool CNetUDPConnection::FlushOutput() {
	if (!mOutputShutdown) {
		if (mOutputFilterStream != nullptr) {
			mOutputFilterStream->VirtFlush();
		}
		mPendingOutputData.VirtFlush();
		mFlushedOutputData = mPendingOutputData.GetLength();
	}
	return mFlushedOutputData != 0;
}

void CNetUDPConnection::DispatchFromInput() {
	if (mDispatchedEndOfInput || mScheduleDestroy) {
		return;
	}

	while (mMessage.Read(&mInputBuffer)) {
		const ECmdStreamOp streamCmd = mMessage.GetType();

		if (streamCmd != ECmdStreamOp::Answering) {
			const size_t len = mMessage.mBuff.Size();
			mTotalBytesDispatched += len;
			mTotalBytesDispatchedMD5.Update(&mMessage.mBuff[0], len);
		}

		if (net_DebugLevel >= 3) {
			msvc8::string digStr = mTotalBytesDispatchedMD5.Digest().ToString();
			msvc8::string thisStr = ToString();
			msvc8::string timeStr = gpg::FileTimeToString(mConnector->GetTime());
			gpg::Debugf(
				"%s: %s: msg type %d dispatched [%d bytes, total now %lld, md5 %s]",
				timeStr.c_str(),
				thisStr.c_str(),
				&mMessage.mBuff[0],
				mMessage.mBuff.Size(),
				mTotalBytesDispatched,
				digStr.c_str()
			);
		}

		const auto receiver = mReceivers[static_cast<uint8_t>(mMessage.GetType())];
		if (receiver == nullptr) {
			msvc8::string host = NET_GetHostName(mAddr);
			gpg::Warnf(
				"No receiver for message type %d received from %s:%d.",
				mMessage.GetType(),
				host.c_str(),
				mPort
			);
		} else {
			receiver->Receive(&mMessage, this);
		}
		mMessage.mBuff.Clear();
		mMessage.mPos = 0;
		if (mScheduleDestroy) {
			return;
		}
	}
	if (!mInputBuffer.CanRead() && mInputBuffer.VirtAtEnd()) {
		mDispatchedEndOfInput = true;
		if (mState == kNetStateErrored) {
			Dispatch(new CMessage{ ELobbyMsg::LOBMSG_ConnLostErrored });
		} else {
			Dispatch(new CMessage{ ELobbyMsg::LOBMSG_ConnLostEof });
		}
	}
}

void CNetUDPConnection::Debug() {
	const auto time = mConnector->GetTime();
	gpg::Logf("  CNetUDPConnection 0x%08x:", this);
	const msvc8::string address = NET_GetDottedOctetFromUInt32(mAddr);
	const msvc8::string hostname = NET_GetHostName(mAddr);
	gpg::Logf("    remote addr: %s[%s]:%d", hostname.c_str(), address.c_str(), mPort);
	const char* state;
	if (mState > kNetStateErrored) {
		state = gpg::STR_Printf("??? (%d)", mState).c_str();
	} else {
		state = NetConnectionStateToStr(mState);
	}
	gpg::Logf("    State: %s", state);
	gpg::Logf("    Last Send: %7dusec ago", time - mLastSend.mTime);
	gpg::Logf("    Last Recv: %7dusec ago", time - mLastRecv);
	gpg::Logf("    Last KeepAlive: %7dusec ago", time - mLastKeepAlive);
	gpg::Logf("    KeepAlive Freq: %d", mKeepAliveFreqUs);
	gpg::Logf("    Next Serial Number: %d", mNextSerialNumber);
	gpg::Logf("    In Response To: %d", mInResponseTo);
	if (mSendBy.mTime != 0) {
		gpg::Logf("    Send By: %7dusec from now", mSendBy.mTime - time);
	} else {
		gpg::Logf("    Send By: NA");
	}
	const LONGLONG sentTime = GetBacklog(time);
	gpg::Logf("    Backlog: %d bytes", sentTime);
	gpg::Logf("    Next Sequence Number: %d", mNextSequenceNumber);
	gpg::Logf("    Remote Expected Sequence Number: %d", mRemoteExpectedSequenceNumber);
	gpg::Logf("    Expected Sequence Number: %d", mExpectedSequenceNumber);
	gpg::Logf("    Pending Output Data: %d", mPendingOutputData.GetLength());
	gpg::Logf("    Flushed Output Data: %d", mFlushedOutputData);
	gpg::Logf("    Output Shutdown: %s", mOutputShutdown ? "true" : "false");
	gpg::Logf("    Sent Shutdown: %s", mSentShutdown ? "true" : "false");
	gpg::Logf("    Unacked Payloads:");
	for (const auto* packet : mUnAckedPayloads.owners()) {
		packet->LogPacket("Sent", time);
	}
	gpg::Logf("    Ping Time=%f", mPingTime);
	gpg::Logf("    Early Packets:");
	for (const auto* packet : mUnAckedPayloads.owners()) {
		packet->LogPacket("Received", time);
	}
	gpg::Logf("    Buffered Input Data: %d bytes", mInputBuffer.GetLength());
	gpg::Logf("    Received End of Input: %s", mReceivedEndOfInput ? "true" : "false");
	gpg::Logf("    Dispatched End of Input: %s", mDispatchedEndOfInput ? "true" : "false");
	gpg::Logf("    Closed: %s", mScheduleDestroy);
	gpg::Logf("    Total bytes queued: %llu [%s]", mTotalBytesQueued, mTotalBytesQueuedMD5.Digest().ToString().c_str());
	gpg::Logf("    Total bytes sent: %llu [%s]", mTotalBytesSent, mTotalBytesSentMD5.Digest().ToString().c_str());
	gpg::Logf("    Total bytes received: %llu [%s]", mTotalBytesReceived, mTotalBytesReceivedMD5.Digest().ToString().c_str());
	gpg::Logf("    Total bytes dispatched: %llu [%s]", mTotalBytesDispatched, mTotalBytesDispatchedMD5.Digest().ToString().c_str());

}

void CNetUDPConnection::AdoptPacket(const SNetPacket* packet) {
	mInResponseTo = packet->header.mSerialNumber;

	if (mSendBy.mTime == 0) {
		// net_AckDelay (ms) -> us
		const int64_t ackDelayUs = static_cast<int64_t>(net_AckDelay) * 1000LL;
		mSendBy.mTime = packet->mSentTime + ackDelayUs;
	}
}

void CNetUDPConnection::UpdatePingInfoFromPacket(const SNetPacket& packet) {
	if (!packet.header.mInResponseTo) {
		return;
	}

	const uint16_t src = packet.header.mInResponseTo;
	const uint32_t index = (src & 0x7F); // 128-entry ring

	if (mTimings[index].mSource == src)
	{
		// Elapsed time in ms since we timestamped that serial
		const float rawMs = mTimings[index].mTime.ElapsedMilliseconds();

		// Update running stats (median/jitter)
		mPings.Append(rawMs);
		const float filtered = mPings.Median();
		mPingTime = filtered;
		const float jit = mPings.Jitter(filtered);

		if (net_DebugLevel) {
			gpg::Logf("Ping time: raw=%7.3fms filtered=%7.3fms, jitter=%7.3f", rawMs, mPingTime, jit);
		}

		// Reset keep-alive cadence to 2s (microseconds)
		mKeepAliveFreqUs = 2'000'000;
	}
}

bool CNetUDPConnection::InsertEarlySorted(SNetPacket* packet) {
	// Ensure the node is detached
	const auto node = packet->ListUnlink();

	// Walk list to find insertion point (first element with seq > p->seq)
	for (auto* cur : mEarlyPackets.owners()) {
		if (cur->header.mSequenceNumber == packet->header.mSequenceNumber) {
			// Duplicate of a future DATA - ignore insertion
			return false;
		}

		if (static_cast<int16_t>(cur->header.mSequenceNumber - packet->header.mSequenceNumber) > 0) {
			cur->ListLinkBefore(cur);
		}
	}

	// Insert at tail (before end sentinel)
	node->ListLinkBefore(mEarlyPackets.end().node());
	return true;
}

SNetPacket* CNetUDPConnection::EarlyPopFront() {
	if (mEarlyPackets.empty()) {
		return nullptr;
	}

	const auto node = mEarlyPackets.ListUnlink();
	auto* p = static_cast<SNetPacket*>(node);
	return p;
}

void CNetUDPConnection::EarlyRebuildAckMask(const uint16_t expected, uint32_t& mask) {
	mask = 0;
	for (const auto* cur : mEarlyPackets.owners()) {
		const int16_t d = static_cast<int16_t>(cur->header.mSequenceNumber - expected);
		if (d >= 1 && d <= 32) {
			mask |= (1u << (d - 1));
		}
	}
}

void CNetUDPConnection::ConsumePacketHeaderData(SNetPacket* packet) {
	const uint16_t payloadLen = packet->header.mPayloadLength;

	if (payloadLen != 0) {
		const auto payload = reinterpret_cast<const char*>(&packet->data[0]);

		// Stats
		mTotalBytesReceived += payloadLen;
		mTotalBytesReceivedMD5.Update(payload, payloadLen);

		// Write through filter if present
		if (mFilterStream) {
			mFilterStream->Write(payload, payloadLen);
		} else {
			mInputBuffer.Write(payload, payloadLen);
		}
	} else {
		// End-of-input marker
		if (mFilterStream) {
			mFilterStream->Close(gpg::Stream::ModeBoth);
			const auto* z = mFilterStream;
			mFilterStream = nullptr;
			delete z;
		}
		mInputBuffer.Close(gpg::Stream::ModeBoth);
		mReceivedEndOfInput = true;
	}

	// Advance expected sequence
	++mExpectedSequenceNumber;

	// Return packet to pool
	if (mConnector) {
		mConnector->AddPacket(packet);
	}
}

void CNetUDPConnection::InsertUnAckedSorted(SNetPacket* packet) {
	const auto node = packet->ListUnlink();

	for (auto* cur : mUnAckedPayloads.owners()) {
		if (packet->mSentTime < cur->mSentTime) {
			node->ListLinkBefore(cur);
			return;
		}
	}
	// append at tail
	node->ListLinkBefore(mUnAckedPayloads.end().node());
}
