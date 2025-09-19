// ReSharper disable CppTooWideScope
#include "CNetUDPConnection.h"

#include "CNetUDPConnector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/ZLibOutputFilterStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

int32_t net_SendDelay = 0;
int32_t net_AckDelay = 0;
int32_t net_DebugLevel = 0;
float net_ResendPingMultiplier = 1;
int32_t net_ResendDelayBias = 0;
int32_t net_MaxResendDelay = 0;
int32_t net_MinResendDelay = 0;
int32_t net_MaxSendRate = 1000;
int32_t net_LogPackets = 0;

float CNetUDPConnection::GetPing() {
	gpg::core::SharedLock(mConnector->lock_);
	return mPingTime;
}

float CNetUDPConnection::GetTime() {
	gpg::core::SharedLock(mConnector->lock_);
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
	gpg::core::SharedLock(mConnector->lock_);

	if (auto* target = mOutputFilterStream) {
		target->VirtWrite(reinterpret_cast<const char*>(begin), len);
	} else {
		mOutputData.VirtWrite(reinterpret_cast<const char*>(begin), len);
	}

	// Schedule earliest send time once:
	// mSendBy = now + net_SendDelay * 1000 (ms > us ticks in bin)
	if (!mSendBy.mTime) {
		const std::int64_t now = mConnector->GetTime();
		mSendBy.mTime = now + static_cast<std::int64_t>(net_SendDelay) * 1000;
	}

	// Mark output pending (gap500[0] = 1 in the binary)
	// mHasPendingOutput ?
	gap500[0] = true;

	// Update counters and MD5 of total queued bytes
	mTotalBytesQueued += static_cast<std::uint64_t>(len);
	mTotalBytesQueuedMD5.Update(begin, len);

	// Verbose debug (net_DebugLevel >= 3)
	if (net_DebugLevel >= 3) {
		const auto dig = mTotalBytesQueuedMD5.Digest();
		const auto ts = gpg::FileTimeToString(static_cast<FILETIME>(mConnector->GetTime()));

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
	gpg::core::SharedLock(mConnector->lock_);
	if (mOutputShutdown) {
		return;
	}

	if (mOutputFilterStream != nullptr) {
		mOutputFilterStream->VirtClose(gpg::Stream::ModeSend);
		delete mOutputFilterStream;
	}

	mOutputData.VirtClose(gpg::Stream::ModeSend);
	mOutputShutdown = true;
	// mHasPendingOutput ?
	gap500[0] = false;

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

msvc8::string CNetUDPConnection::ToString() {
	const auto host = NET_GetHostName(mAddr);
	return gpg::STR_Printf("%s:%d", host.c_str(), static_cast<int>(mPort));
}

void CNetUDPConnection::ScheduleDestroy() {
	gpg::core::SharedLock(mConnector->lock_);
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
	mFilterStream(nullptr), 
	mMessage(0, 0) // [esi+0x42C]
{
	// Init timers and timestamps
	// (ASM zeroes a lot of POD around; we rely on default ctor or explicit zeros above)
	mLastSend.Reset();
	mSendTime = 0;
	mLastRecv = 0;
	mLastKeepAlive = 0;

	mUnAckedPayloads.init_empty();
	mEarlyPackets.init_empty();

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
	connector.mConnections.push_front(&mConnList);

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
		const auto filterStream = new gpg::ZLibOutputFilterStream(&mOutputData, 1);
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

	auto recyclePacket = [this](SPacket* p) noexcept {
		if (!p) {
			return;
		}
		if (mConnector->mPacketPoolSize >= poolCap) {
			operator delete(p);
		} else {
			mConnector->mPacketList.push_back(&p->mList);
			++mConnector->mPacketPoolSize;
		}
	};

	// Un-acked
	for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end(); )
	{
		auto* n = it.node();
		SPacket* p = UnAckedView::owner_from_node(n);
		it = mUnAckedPayloads.erase(it);
		recyclePacket(p);
	}

	// Early
	for (auto it = mEarlyPackets.begin(); it != mEarlyPackets.end(); )
	{
		auto* n = it.node();
		SPacket* p = EarlyView::owner_from_node(n);
		it = mEarlyPackets.erase(it);
		recyclePacket(p);
	}
}

void CNetUDPConnection::CreateFilterStream() {
	// Original assigns raw 3 into mState; route via helper for clarity/portability.
	SetState(ENetConnectionState::Answering);

	// 1) Push a small control message (type 201) into the input buffer.
	//    The original code emits CMessage(201) and appends its bytes into PipeStream.
	{
		const CMessage msg{ 0, static_cast<char>(201) };

		const char* const src = msg.mBuf.start_;
		const size_t size = static_cast<size_t>(msg.mBuf.end_ - msg.mBuf.start_);

		// Fast path: write directly if there is enough contiguous space in the write window.
		char* const writeHead = mInputBuffer.mWriteHead;
		const char* const writeEnd = mInputBuffer.mWriteEnd;

		const size_t avail = static_cast<size_t>(writeEnd - writeHead);
		if (size > avail) {
			// Fallback to the virtual streaming write (handles growth/flush).
			mInputBuffer.VirtWrite(src, size);
		} else {
			std::memcpy(writeHead, src, size);
			mInputBuffer.mWriteHead += size;
		}
	}

	// 2) Decide on receive compression and (re)create the filter.
	//    In the binary, non-zero means "deflate" (value 1), zero means "no compression".
	const auto receivedCompressionMethod =
		static_cast<ENetCompressionMethod>(mReceivedCompressionMethod);

	// Build a human-readable endpoint string for logs.
	const msvc8::string who = ToString();

	if (receivedCompressionMethod != NETCOMP_None) {
		// The original asserts that only value 1 (deflate) is expected here.
		if (receivedCompressionMethod != NETCOMP_Deflate) {
			GPG_UNREACHABLE()
		}

		gpg::Logf("NET: using deflate compression for receives from %s", who.c_str());

		// Replace existing filter with a fresh inflate (operation=0) filter attached to mInputBuffer.
		// Note: in the game binary mOperation==0 -> inflate, mOperation==1 -> deflate.
		auto* const old = mFilterStream;
		mFilterStream = new gpg::ZLibOutputFilterStream(&mInputBuffer, /*operation=*/0);
		if (old) {
			delete old;
		}
	} else {
		gpg::Logf("NET: using no compression for receives from %s", who.c_str());

		// No filter needed on receive side; drop any old one.
		if (mFilterStream)
		{
			delete mFilterStream;
			mFilterStream = nullptr;
		}
	}
}

bool CNetUDPConnection::ProcessConnect(const SPacket* packet) {
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
	case ENetConnectionState::Pending:    // 0
	case ENetConnectionState::Answering:  // 2
	{
		// Copy remote nonce and adopt compression.
		std::memcpy(mNonceB, pConnect.nonceA, sizeof(mNonceB));
		mTime1 = pConnect.time;
		mReceivedCompressionMethod = static_cast<int>(pConnect.comp);

		// Binary rebinds/repurposes packet memory to this connection.
		AdoptPacket(packet);
		return true;
	}
	case ENetConnectionState::Connecting: // 1 (Connecting)
	{
		std::memcpy(mNonceB, pConnect.nonceA, sizeof(mNonceB));
		mTime1 = pConnect.time;
		mReceivedCompressionMethod = static_cast<int>(pConnect.comp);

		AdoptPacket(packet);

		// Transition to Answering
		mState = ENetConnectionState::Answering;
		return true;
	}
	case ENetConnectionState::Establishing: // 3
	case ENetConnectionState::TimedOut:     // 4
	{
		// Move to Retired and shut down input.
		mState = ENetConnectionState::TimedOut; // 5
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

void CNetUDPConnection::ProcessAnswer(const SPacket* packet) {
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
	if (mState == ENetConnectionState::Pending) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on pending connection",
				GetPort(), ToString().c_str());
		}
		return;
	}

	if (!(mState == ENetConnectionState::Connecting || mState == ENetConnectionState::Answering)) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER on established connection",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Update remote timing/window from header.
	ApplyRemoteHeader(*packet);

	// Refresh peer time and negotiated params.
	mLastRecv = packet->mSentTime;
	std::memcpy(mNonceB, pAnswer.nonceA, sizeof(mNonceB));
	mTime1 = pAnswer.time;
	mReceivedCompressionMethod = static_cast<int>(pAnswer.comp);

	// Enable RX filter according to negotiated compression. 
	CreateFilterStream();

	// Binary rebinds/repurposes packet memory to this connection. 
	AdoptPacket(packet);

#if defined(_WIN32)
	WSASetEvent(mConnector->event_);
#endif
}

bool CNetUDPConnection::ProcessAckInternal(const SPacket* packet) {
	switch (mState) {
	case ENetConnectionState::Pending: { // 0
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Pending connection.",
				GetPort(), ToString().c_str());
		}
		return false;
	}
	case ENetConnectionState::Connecting: { // 1
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAck(): ignoring traffic on Connecting connection.",
				GetPort(), ToString().c_str());
		}
		return false;
	}
	case ENetConnectionState::Answering: // 2
		// First ACK on Active path turns on RX filter if not set.
		CreateFilterStream();
	case ENetConnectionState::Establishing: // 3
		break; // proceed
	case ENetConnectionState::TimedOut: // 4
		// Transition per binary: Error -> Closing before handling.
		mState = ENetConnectionState::Establishing;
		break;
	case ENetConnectionState::Errored: { // 5
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
	ApplyRemoteHeader(*packet);

	// Ack window: ack everything older than 'expected', and also bits in early mask for last 32.
	const uint32_t earlyMask = packet->header.mEarlyMask;

	// Iterate intrusive list of un-acked payloads. We must be tolerant to node deletion while iterating.
	for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end(); ++it) {
		auto* n = it.node();
		SPacket* p = UnAckedView::owner_from_node(n);
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

void CNetUDPConnection::ProcessData(SPacket* packet) {
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

			SPacket* drop = EarlyPopFront();
			if (drop && mConnector) {
				mConnector->AddPacket(drop);
			}
			continue;
		}

		// Peek head; stop if not the expected sequence
		SPacket* headPacket = EarlyView::owner_from_node(mEarlyPackets.begin().node());
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
	if (progressed && mConnector && mConnector->v31) {
		SetEvent(mConnector->v31);
	}
#endif
}

bool CNetUDPConnection::ProcessAck(const SPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;
	return true;
}

bool CNetUDPConnection::ProcessKeepAlive(const SPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;
	AdoptPacket(packet); // SPacket::SPacket(pkt, this)
	return true;
}

bool CNetUDPConnection::ProcessGoodbye(const SPacket* packet) {
	if (!ProcessAckInternal(packet)) {
		return false;
	}

	mLastRecv = packet->mSentTime;

	if (!mReceivedEndOfInput)
	{
		mState = ENetConnectionState::Errored;
		mReceivedEndOfInput = true;

		if (mFilterStream) {
			mFilterStream->Close(gpg::Stream::ModeBoth); // VirtClose(2)
			auto* z = mFilterStream;
			mFilterStream = nullptr;
			delete z; // vtable dtr in asm
		}

		mInputBuffer.Close(gpg::Stream::ModeBoth);
#if defined(_WIN32)
		if (mConnector && mConnector->v31) {
			SetEvent(mConnector->v31);
		}
#endif
	}

	return true;
}

int64_t CNetUDPConnection::CalcResendDelay(const SPacket* packet) {
	float baseMs = mPingTime * net_ResendPingMultiplier + static_cast<float>(net_ResendDelayBias);


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

int CNetUDPConnection::GetSentTime(const int64_t nowUs) {
	const uint32_t credit = static_cast<uint32_t>(mSendTime & 0xFFFFFFFFULL);
	if (credit == 0) {
		return 0;
	}

	const double dtUs = static_cast<double>(nowUs - mLastSend.mTime);
	const double remain = static_cast<double>(credit)
		- dtUs * static_cast<double>(net_MaxSendRate) * 1e-6;

	const int r = static_cast<int>(remain);
	if (r > 0)
		return r;

	mSendTime &= 0xFFFFFFFF00000000ULL; // LODWORD(mSendTime) = 0
	return 0;
}

int CNetUDPConnection::SendData() {
	// Helper: time until 'ts' (us).
	// Return -1 if already passed.
	auto timeUntil = [&](const int64_t ts) -> int {
		const int64_t now = mConnector->GetTime();
		const int64_t d = ts - now;
		if (d <= 0) return -1;
		if (d > std::numeric_limits<int>::max()) return std::numeric_limits<int>::max();
		return static_cast<int>(d);
	};

	// already scheduled/finished destruction
	if (v867b) { 
		return -1;
	}

	switch (mState)
	{
	case ENetConnectionState::Pending:
	case ENetConnectionState::Errored:
		if (mScheduleDestroy) {
			v867b = true;
			return -1;
		}
		return -1;

	case ENetConnectionState::Connecting:
	{
		if (mScheduleDestroy) {
			v867b = true;
			return -1;
		}

		const int64_t now = mConnector->GetTime();
		const bool needKick =
			(mInResponseTo != 0) ||
			((now - mLastSend.mTime) >= 1'000'000); // 1s

		if (needKick) {
			SPacket* p = NextConnectPacket();
			SendPacket(p);
		}

		// schedule next kick around 1s cadence
		return timeUntil(mLastSend.mTime + 1'000'000);
	}

	case ENetConnectionState::Answering:
	{
		if (mScheduleDestroy) {
			v867b = true;
			return -1;
		}

		const int64_t now = mConnector->GetTime();
		const bool needKick =
			(mInResponseTo != 0) ||
			((now - mLastSend.mTime) >= 1'000'000);

		if (needKick) {
			SPacket* p = NextAnswerPacket();
			SendPacket(p);
		}

		return timeUntil(mLastSend.mTime + 1'000'000);
	}

	case ENetConnectionState::Establishing:
	{
		const int64_t now = mConnector->GetTime();
		const int64_t idle = now - mLastRecv;

		// Timeout after 10 seconds of no incoming traffic
		if (!(idle < 0 || idle <= 10'000'000)) {
			if (net_DebugLevel) {
				gpg::Logf("CNetUDPConnection<%u,%s>::SendData(): connection timed out.",
					GetPort(), ToString().c_str());
			}
			mState = ENetConnectionState::TimedOut;
			// fallthrough to TimedOut handling below
		} else
		{
			SPacket* toSend = nullptr;

			// Resend logic: if un-acked exists and resend due
			if (!mUnAckedPayloads.empty()) {
				SPacket* head = UnAckedView::owner_from_node(mUnAckedPayloads.begin().node());
				if (now >= head->mSentTime) {
					// Detach for resend
					UnAckedView::node_t* node = UnAckedView::node_from_owner(head);
					node->ListUnlink();
					toSend = head;
				}
			}

			// No resend due: build new packet if we have work
			if (!toSend) {
				if (HasPacketWaiting(now)) {
					toSend = ReadPacket();
				} else if (mScheduleDestroy && mSentShutdown && mUnAckedPayloads.empty()) {
					toSend = NextGoodbyePacket(); // final close/bye packet
					v867b = true;
				} else if (now < (mLastKeepAlive + mKeepAliveFreqUs)) {
					// Ack-only if we owe an ack and deadline reached
					if (mInResponseTo && now >= mSendBy.mTime) {
						// ACK-only; state id per your map
						toSend = NextPacket(true, 0, ACK); 
					}
				} else {
					// Keepalive if period elapsed
					// KEEPALIVE; state id per your map (6 in asm)
					toSend = NextPacket(true, 0, KEEPALIVE);
				}
			}

			if (toSend)
				SendPacket(toSend);

			// Compute next delay:
			// If we have just flushed output or buffer is "big", go now.
			if (mFlushedOutputData || mOutputData.GetLength() > 0x1F1)
				return 0;

			// Soonest of: keepalive deadline, resend of oldest unacked, ack deadline (if owed)
			int next = timeUntil(mLastKeepAlive + mKeepAliveFreqUs);

			if (!mUnAckedPayloads.empty()) {
				const SPacket* head = UnAckedView::owner_from_node(mUnAckedPayloads.begin().node());
				const int r = timeUntil(head->mSentTime);
				if (r != -1 && (next == -1 || next >= r)) {
					next = r;
				}
			}

			if (mSendBy.mTime &&
				(mInResponseTo || mOutputData.GetLength() || gap500[0]))
			{
				int r = timeUntil(mSendBy.mTime);
				if (r != -1 && (next == -1 || next >= r))
					return r;
			}

			return next;
		}
		// fallthrough to TimedOut case
	}
	case ENetConnectionState::TimedOut:
	{
		if (mScheduleDestroy) {
			v867b = true;
			return -1;
		}

		// On timed-out, still send keepalives if interval elapsed
		const int64_t now = mConnector->GetTime();
		if ((now - mLastKeepAlive) > mKeepAliveFreqUs) {
			// KEEPALIVE
			SPacket* p = NextPacket(true, 0, KEEPALIVE);
			SendPacket(p);
		}

		return timeUntil(mLastKeepAlive + mKeepAliveFreqUs);
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

	gpg::PipeStream* out = &mOutputData;

	// End-of-stream pending? (read head == read end && AtEnd && !mSentShutdown)
	if (mOutputData.mReadHead == mOutputData.mReadEnd && 
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
		return mOutputData.GetLength() >= 0x1F1;
	}

	// Pending flush request?
	if (gap500[0]) {
		if (mOutputFilterStream) {
			mOutputFilterStream->VirtFlush();
		}
		out->VirtFlush();
		gap500[0] = 0;
	}

	// Any bytes available?
	return mOutputData.GetLength() != 0;
}

SPacket* CNetUDPConnection::ReadPacket() {
	// clamp payload to wire limit
	unsigned int len = mOutputData.GetLength();
	if (len >= static_cast<unsigned int>(kNetPacketMaxPayload)) {
		len = kNetPacketMaxPayload;
	}

	// allocate with header inheritance (seq/expected/mask)
	SPacket* packet = NextPacket(true, static_cast<int>(len), DATA);
	if (!packet) {
		return nullptr;
	}

	// copy payload
	if (len != 0) {
		const auto dst = reinterpret_cast<char*>(&packet->data[0]);

		// fast path if contiguous
		if (len <= static_cast<unsigned int>(mOutputData.mReadEnd - mOutputData.mReadHead)) {
			std::memcpy(dst, mOutputData.mReadHead, len);
			mOutputData.mReadHead += len;
		} else {
			mOutputData.Read(dst, len); // virtual read
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

SPacket* CNetUDPConnection::NextConnectPacket() const {
	constexpr auto payloadSize = sizeof(SPacketBodyConnect);

	// allocate with no header inheritance (seq/expected/mask all zero)
	SPacket* packet = NextPacket(false, payloadSize, CONNECT);
	if (!packet) {
		return nullptr;
	}

	const auto connectPacket = reinterpret_cast<SPacketConnectPkt*>(packet)->body();

	connectPacket->protocol = 2u;
	connectPacket->time = mConnector->GetTime();
	connectPacket->comp = mOurCompressionMethod;

	std::memcpy(connectPacket->nonceA, mNonceA, 32);
	return packet;
}

SPacket* CNetUDPConnection::NextAnswerPacket() const {
	constexpr auto payloadSize = sizeof(SPacketBodyAnswer);

	// allocate with no header inheritance (seq/expected/mask all zero)
	SPacket* packet = NextPacket(false, payloadSize, ANSWER);
	if (!packet) {
		return nullptr;
	}

	const auto answerPacket = reinterpret_cast<SPacketAnswerPkt*>(packet)->body();

	answerPacket->protocol = 2u;
	answerPacket->time = mConnector->GetTime();
	answerPacket->comp = mOurCompressionMethod;

	std::memcpy(answerPacket->nonceA, mNonceA, 32);
	std::memcpy(answerPacket->nonceB, mNonceB, 32);
	return packet;
}

SPacket* CNetUDPConnection::NextGoodbyePacket() const {
	SPacket* packet = NextPacket(false, 0, GOODBYE);
	if (!packet) {
		return nullptr;
	}

	return packet;
}

SPacket* CNetUDPConnection::NextPacket(const bool inherit, const int size, const EPacketState state) const {
	// take from connector's pool or allocate
	SPacket* pkt;
	if (mConnector->mPacketList.mNext != &mConnector->mPacketList) {
		--mConnector->mPacketPoolSize;
		pkt = reinterpret_cast<SPacket*>(mConnector->mPacketList.mNext);
		// unlink from pool
		pkt->mList.mPrev->mNext = pkt->mList.mNext;
		pkt->mList.mNext->mPrev = pkt->mList.mPrev;
	} else {
		// 536 bytes (0x218 from asm)
		pkt = new SPacket();
		if (!pkt) {
			return nullptr;
		}
	}
	// reset intrusive node
	pkt->mList.mNext = &pkt->mList;
	pkt->mList.mPrev = &pkt->mList;

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

void CNetUDPConnection::SendPacket(SPacket* packet) {
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
		auto pktStr = packet->ToString();
		auto connStr = ToString();
		auto timeStr = gpg::FileTimeToString(gpg::FileTimeLocal());
		gpg::Debugf("%s: send %s, %s",
			timeStr.c_str(),
			connStr.c_str(),
			pktStr.c_str());
	}

	++mNextSerialNumber;
	mInResponseTo = 0;

	if (mOutputData.GetLength()) {
		// time in us
		mSendBy.mTime = nowUs + 1000LL * net_SendDelay;
	} else {
		mSendBy.mTime = 0;
	}

	// Per-serial timing slot (128 ring)
	const std::uint16_t sidx = packet->header.mSerialNumber & 0x7F;
	mTimings[sidx].mSource = packet->header.mSerialNumber;
	mTimings[sidx].mTime.Reset();

	// Pacing credit: low 32 bits accumulate bytes just sent
	const std::uint32_t remain = static_cast<std::uint32_t>(GetSentTime(nowUs));
	const std::uint32_t credit = remain + reinterpret_cast<std::uint32_t>(payload);
	mSendTime = (mSendTime & 0xFFFFFFFF00000000ULL) | credit;

	// Last send / keepalive housekeeping
	mLastSend.mTime = nowUs;

	if (packet->header.mState != ACK) {
		mLastKeepAlive = nowUs;
	}

	if (packet->header.mState == KEEPALIVE) {
		mKeepAliveFreqUs = 2'000'000; // 2s
	}
}

void CNetUDPConnection::SetState(const ENetConnectionState state) {
	mState = state;
}

void CNetUDPConnection::AdoptPacket(const SPacket* packet) {
	mInResponseTo = packet->header.mSerialNumber;

	if (mSendBy.mTime == 0) {
		// net_AckDelay (ms) -> us
		const int64_t ackDelayUs = static_cast<int64_t>(net_AckDelay) * 1000LL;
		mSendBy.mTime = packet->mSentTime + ackDelayUs;
	}
}

void CNetUDPConnection::ApplyRemoteHeader(const SPacket& packet) {
	if (!packet.header.mInResponseTo) {
		return;
	}

	const uint16_t src = packet.header.mInResponseTo;
	const uint32_t idx = (src & 0x7F); // 128-entry ring

	if (mTimings[idx].mSource == src)
	{
		// Elapsed time in ms since we timestamped that serial
		const float rawMs = mTimings[idx].mTime.ElapsedMilliSeconds();

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

bool CNetUDPConnection::InsertEarlySorted(SPacket* packet) {
	// Ensure the node is detached
	auto* node = EarlyView::node_from_owner(packet);
	node->ListUnlink();

	// Walk list to find insertion point (first element with seq > p->seq)
	for (auto it = mEarlyPackets.begin(); it != mEarlyPackets.end(); ++it) {
		const SPacket* cur = EarlyView::owner_from_node(it.node());
		if (cur->header.mSequenceNumber == packet->header.mSequenceNumber) {
			// Duplicate of a future DATA - ignore insertion
			return false;
		}
		if (static_cast<int16_t>(cur->header.mSequenceNumber - packet->header.mSequenceNumber) > 0) {
			// Insert before 'it'
			node->ListLinkBefore(it.node());
			return true;
		}
	}

	// Insert at tail (before end sentinel)
	node->ListLinkBefore(mEarlyPackets.end().node());
	return true;
}

SPacket* CNetUDPConnection::EarlyPopFront() {
	if (mEarlyPackets.empty()) {
		return nullptr;
	}
	const auto it = mEarlyPackets.begin();
	SPacket* p = EarlyView::owner_from_node(it.node());
	(void)mEarlyPackets.erase(it);
	return p;
}

void CNetUDPConnection::EarlyRebuildAckMask(const uint16_t expected, uint32_t& mask) {
	mask = 0;
	for (auto it = mEarlyPackets.begin(); it != mEarlyPackets.end(); ++it) {
		const SPacket* cur = EarlyView::owner_from_node(it.node());
		const int16_t d = static_cast<int16_t>(cur->header.mSequenceNumber - expected);
		if (d >= 1 && d <= 32) {
			mask |= (1u << (d - 1));
		}
	}
}

void CNetUDPConnection::ConsumePacketHeaderData(SPacket* packet) {
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

void CNetUDPConnection::InsertUnAckedSorted(SPacket* packet) {
	auto* selfNode = UnAckedView::node_from_owner(packet);
	selfNode->ListUnlink();

	auto it = mUnAckedPayloads.begin();
	for (; it != mUnAckedPayloads.end(); ++it)
	{
		SPacket* cur = UnAckedView::owner_from_node(it.node());
		if (packet->mSentTime < cur->mSentTime) {
			selfNode->ListLinkBefore(it.node());
			return;
		}
	}
	// append at tail
	selfNode->ListLinkBefore(mUnAckedPayloads.end_node());
}
