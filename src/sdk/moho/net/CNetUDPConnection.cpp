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
	::WSASetEvent(mConnector->event_);
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
	::WSASetEvent(mConnector->event_);
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
	::WSASetEvent(mConnector->event_);
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
	std::memset(mDat1, 0, sizeof(mDat1));
	std::memset(mDat2, 0, sizeof(mDat2));
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
				::operator delete(mOutputFilterStream);
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

	auto recyclePacket = [this](moho::SPacket* p) noexcept {
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

bool CNetUDPConnection::ProcessConnect(const SPacket* pack) {
	// Obsolete CONNECT: ignore
	if (pack->mTime <= mTime1) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring obsolete CONNECT",
				GetPort(), ToString().c_str());
		}
		return true;
	}

	// Fresh packet: record last-recv wall clock from peer
	mLastRecv = pack->mSentTime;

	// Unknown compression method
	if (pack->mCompMethod >= NETCOMP_Deflate + 1) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring connect w/ unknown compression method (%u)",
				GetPort(), ToString().c_str(), static_cast<unsigned>(pack->mCompMethod));
		}
		return true;
	}

	switch (mState) {
	case ENetConnectionState::Pending:    // 0
	case ENetConnectionState::Answering:  // 2
	{
		// Copy remote nonce and adopt compression.
		std::memcpy(mDat2, pack->mDat1, sizeof(mDat2));
		mTime1 = pack->mTime;
		mReceivedCompressionMethod = static_cast<int>(pack->mCompMethod);

		// Binary rebinds/repurposes packet memory to this connection.
		AdoptPacket(pack);
		return true;
	}
	case ENetConnectionState::Connecting: // 1 (Connecting)
	{
		std::memcpy(mDat2, pack->mDat1, sizeof(mDat2));
		mTime1 = pack->mTime;
		mReceivedCompressionMethod = static_cast<int>(pack->mCompMethod);

		AdoptPacket(pack);

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
			::WSASetEvent(mConnector->event_);
#endif
		}
		return false;
	}
	default:
		GPG_UNREACHABLE()
		return false;
	}
}

void CNetUDPConnection::ProcessAnswer(const SPacket* pack) {
	// Strict size check: expected 92 bytes
	if (pack->mSize != 92) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring wrong length ANSWER (got %d bytes, required %d)",
				GetPort(), ToString().c_str(), pack->mSize, 92);
		}
		return;
	}

	// Obsolete ANSWER
	if (pack->mTime <= mTime1) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring obsolete ANSWER",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Receiver nonce must match what we sent earlier
	if (std::memcmp(mDat1, pack->mDat2, sizeof(mDat1)) != 0) {
		if (net_DebugLevel) {
			gpg::Logf("CNetUDPConnection<%u,%s>::ProcessAnswer(): ignoring ANSWER with wrong receiver nonce",
				GetPort(), ToString().c_str());
		}
		return;
	}

	// Unknown compression method
	if (pack->mCompMethod >= 2u) {
		if (net_DebugLevel) {
			gpg::Logf(
				"CNetUDPConnection<%u,%s>::ProcessConnect(): ignoring answer w/ unknown compression method (%u)",
				GetPort(), ToString().c_str(), static_cast<unsigned>(pack->mCompMethod));
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
	ApplyRemoteHeader(*pack);

	// Refresh peer time and negotiated params.
	mLastRecv = pack->mSentTime;
	std::memcpy(mDat2, pack->mDat1, sizeof(mDat2));
	mTime1 = pack->mTime;
	mReceivedCompressionMethod = static_cast<int>(pack->mCompMethod);

	// Enable RX filter according to negotiated compression. 
	CreateFilterStream();

	// Binary rebinds/repurposes packet memory to this connection. 
	AdoptPacket(pack);

#if defined(_WIN32)
	::WSASetEvent(mConnector->event_);
#endif
}

bool CNetUDPConnection::ProcessAck(const SPacket* pack) {
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
	const uint16_t expected = pack->mExpectedSequenceNumber;
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
	ApplyRemoteHeader(*pack);

	// Ack window: ack everything older than 'expected', and also bits in early mask for last 32.
	const uint32_t earlyMask = pack->mEarlyMask;

	// Iterate intrusive list of un-acked payloads. We must be tolerant to node deletion while iterating.
	for (auto it = mUnAckedPayloads.begin(); it != mUnAckedPayloads.end(); ++it) {
		auto* n = it.node();
		SPacket* p = UnAckedView::owner_from_node(n);
		const int16_t d = static_cast<int16_t>(p->mSequenceNumber - expected);

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

void CNetUDPConnection::SetState(const ENetConnectionState state) {
	mState = state;
}

void CNetUDPConnection::AdoptPacket(const SPacket* packet) {
	mInResponseTo = packet->mSerialNumber;

	if (mSendBy.mTime == 0) {
		// net_AckDelay (ms) -> us
		const int64_t ackDelayUs = static_cast<int64_t>(net_AckDelay) * 1000LL;
		mSendBy.mTime = packet->mSentTime + ackDelayUs;
	}
}

void CNetUDPConnection::ApplyRemoteHeader(const SPacket& packet) {
	if (!packet.mInResponseTo) {
		return;
	}

	const uint16_t src = packet.mInResponseTo;
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
