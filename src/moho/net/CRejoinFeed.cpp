#include "CRejoinFeed.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <zlib.h>
#include <zstd.h>

#include "CClientBase.h"
#include "CClientManagerImpl.h"
#include "CMessageStream.h"
#include "CNetClient.h"
#include "Common.h"
#include "EClientMsg.h"
#include "ECmdStreamOp.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"
#include "INetConnection.h"
#include "INetConnector.h"
#include "IMessageReceiver.h"
#include "NetConVars.h"
#include "PeerFeatures.h"
#include "NetMessageRanges.h"
#include "moho/misc/CSaveGameRequestImpl.h"
#include "moho/misc/ISaveRequest.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/SessionStartup.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/net/CNetUDPConnection.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimKeyframe.h"
#include "moho/sim/WldSessionInfo.h"
#include "netlink/EngineLinks.h"

using namespace moho;

namespace
{
  constexpr std::uint8_t kInvalidCommandSource = 0xFFu;

  // What the beats a save holds wrote into the recording, for this client's own replay.
  std::vector<CMessage> sReplayHistory;

  [[nodiscard]] std::int32_t ReadInt32Payload(CMessage& message)
  {
    CMessageStream stream(message, CMessageStream::Access::kReadOnly);
    gpg::BinaryReader reader(&stream);
    std::int32_t value = 0;
    reader.ReadExact(value);
    return value;
  }

  [[nodiscard]] std::uint8_t ReadSourcePayload(CMessage& message)
  {
    if (message.GetMessageSize() < 1) {
      return kInvalidCommandSource;
    }
    CMessageStream stream(message, CMessageStream::Access::kReadOnly);
    gpg::BinaryReader reader(&stream);
    std::uint8_t source = kInvalidCommandSource;
    reader.ReadExact(source);
    return source;
  }

  // Rejoin's messages travel as `CLIMSG_PeerFeatures`: a kind, then their payload.
  constexpr std::size_t kKindBytes = 1u;

  [[nodiscard]] bool IsPeerMessage(CMessage& message, const EPeerMessageKind kind)
  {
    return message.GetType().raw() == static_cast<std::uint8_t>(EClientMsg::CLIMSG_PeerFeatures) &&
      message.GetMessageSize() >= static_cast<int>(kKindBytes) &&
      static_cast<std::uint8_t>(message.mBuff.start_[3]) == static_cast<std::uint8_t>(kind);
  }

  /// The answer to a peer's challenge: this seat's key signs it for that peer.
  [[nodiscard]] CMessage MakeProofMessage(const SRejoinNonce& nonce, const int source, const int peerIndex)
  {
    const SRejoinSignature signature = REJOIN_SignChallenge(nonce, source, peerIndex);
    CMessage proof(EClientMsg::CLIMSG_PeerFeatures);
    CMessageStream stream(proof);
    stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinProof));
    stream.Write(reinterpret_cast<const char*>(signature.data()), signature.size());
    return proof;
  }

  /// The client index a backlog message names.
  [[nodiscard]] std::uint8_t BacklogIndex(CMessage& message)
  {
    return message.GetMessageSize() > static_cast<int>(kKindBytes)
      ? static_cast<std::uint8_t>(message.mBuff.start_[3 + kKindBytes])
      : kInvalidCommandSource;
  }

  [[nodiscard]] CMessage MakeStatusMessage(const ERejoinStage stage, const float progress)
  {
    CMessage message(EClientMsg::CLIMSG_PeerFeatures);
    CMessageStream stream(message);
    stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinProgress));
    stream.Write(static_cast<std::uint8_t>(stage));
    stream.Write(progress);
    return message;
  }

  void WriteAdvance(CClientBase& client, const std::int32_t beatDelta)
  {
    CMessage advance(ECmdStreamOp::CMDST_Advance);
    CMessageStream stream(advance);
    stream.Write(beatDelta);
    client.CClientBase::Process(advance);
  }
} // namespace

CRejoinFeed::CRejoinFeed(
  CClientManagerImpl& manager,
  std::unique_ptr<gpg::Stream> recording,
  const int handoverBeat,
  const bool live,
  const int recordingPeer,
  const int skipBeats
)
  : mManager(manager)
  , mRecording(std::move(recording))
  , mLocal(manager.mLocalClient)
  , mHandoverBeat(handoverBeat)
  , mLive(live)
  , mRecordingPeer(recordingPeer)
{
  const std::size_t clientCount = mManager.mClients.size();
  mHeldIncoming.resize(clientCount);
  mPeerDispatched.resize(clientCount, -1);
  mPeerQueued.resize(clientCount);
  mPeerStreamDispatched.resize(clientCount);
  mBacklog.resize(clientCount);
  if (mLive) {
    for (auto& fromPeer : mBacklog) {
      for (std::size_t index = 0; index < clientCount; ++index) {
        fromPeer.push_back(std::make_unique<gpg::PipeStream>());
      }
    }
  }

  // Every client of the recorded game was there from the start.
  CMessage ready(EClientMsg::CLIMSG_Ready);
  for (CClientBase* const client : mManager.mClients) {
    client->CClientBase::Process(ready);
  }

  if (skipBeats > 0) {
    SkipRecordedBeats(skipBeats);
  }
}

CRejoinFeed::~CRejoinFeed() = default;

void CRejoinFeed::SkipRecordedBeats(const std::int32_t beats)
{
  sReplayHistory.clear();
  while (mReadBeat < beats && mMessage.Read(mRecording.get())) {
    const std::uint8_t type = mMessage.GetType().raw();
    sReplayHistory.push_back(mMessage);
    if (type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_SetCommandSource)) {
      const std::uint8_t source = ReadSourcePayload(mMessage);
      mRecordedSource = source < mManager.mClients.size() ? mManager.mClients[source] : nullptr;
    } else if (type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_CommandSourceTerminated)) {
      // As `CClientBase::UpdateState` would have left a client that was ejected.
      if (mRecordedSource != nullptr) {
        mRecordedSource->mValidCommandSources = BVIntSet{};
        mRecordedSource->mCommandSourceId = kInvalidCommandSource;
      }
    } else if (type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
      mReadBeat += ReadInt32Payload(mMessage);
    }
    mMessage.Clear();
  }

  // Every number here is the game's own, as the peers' messages are.
  mSkippedBeats = mReadBeat;
  const auto beat = static_cast<std::uint32_t>(mSkippedBeats);
  for (CClientBase* const client : mManager.mClients) {
    client->mQueuedBeat = beat;
    client->mDispatchedBeat = beat;
    client->mAvailableBeatRemote = beat;
    for (std::int32_t& ack : client->mLatestAckReceived) {
      ack = mSkippedBeats;
    }
  }
  mManager.mDispatchedBeat = mSkippedBeats;
  mManager.mAvailableBeat = mSkippedBeats;
  mManager.mFullyQueuedBeat = mSkippedBeats;
  mManager.mPartiallyQueuedBeat = mSkippedBeats;

  gpg::Logf("REJOIN: the save holds the game to beat %d", mSkippedBeats);
}

void CRejoinFeed::Pump()
{
  if (mEnded) {
    return;
  }

  if (mLive) {
    // Also while the map loads, or the peers would take the silence for a dead client.
    constexpr std::chrono::seconds kReportInterval{1};
    if (mCatchingUp && std::chrono::steady_clock::now() - mReportedAt >= kReportInterval) {
      ReportStatus();
    }

    // A sim loaded from a save has few beats to run, and nothing runs them until it
    // exists: the peers must not be told this client is back before that.
    if (mSkippedBeats > 0 && !mManager.mWeAreReady) {
      return;
    }

    // The peer has to say how far the recording counts before any of it is read.
    while (mCatchingUp && mBacklogComplete && static_cast<std::int32_t>(mLocal->mQueuedBeat - mLocal->mDispatchedBeat) <= 0) {
      if (mReadBeat >= mMergedBeat) {
        FinishCatchUp();
        return;
      }
      // Short: the peer's sim has not written that far yet; the next pass reads on.
      if (!ReadRecordedBeat()) {
        return;
      }
      DeliverLocalBeat();
    }
    return;
  }

  if (!mCatchingUp) {
    // One beat of the others' data ahead of the driver: a paused sim's driver
    // issues only what some client has already queued, and the recorded resume
    // is in a later beat.
    if (mReadBeat <= static_cast<std::int32_t>(mLocal->mQueuedBeat) && !ReadRecordedBeat()) {
      EndOfRecording();
    }
    return;
  }

  // One beat at a time, as `CReplayClient::Start`: the next one is read when
  // this one has been dispatched, which is as fast as the sim runs.
  while (mCatchingUp && static_cast<std::int32_t>(mLocal->mQueuedBeat - mLocal->mDispatchedBeat) <= 0) {
    if (!ReadRecordedBeat()) {
      EndOfRecording();
      return;
    }
    DeliverLocalBeat();

    if (static_cast<std::int32_t>(mLocal->mQueuedBeat) >= mHandoverBeat) {
      mCatchingUp = false;
      mHandoverPending = true;
      gpg::Logf("REJOIN: caught up to beat %d, the driver issues from here", mHandoverBeat);
    }
  }
}

SRejoinStatus CRejoinFeed::Status() const
{
  if (!mLive) {
    return {};
  }
  if (!mCatchingUp) {
    return std::chrono::steady_clock::now() - mBackAt < kRejoinBackSeconds ? SRejoinStatus{ERejoinStage::Back, -1.0f}
                                                                           : SRejoinStatus{};
  }
  // The first beat waits here until the sim exists to dispatch it.
  if (static_cast<std::int32_t>(mLocal->mDispatchedBeat) <= mSkippedBeats) {
    return SRejoinStatus{ERejoinStage::Loading, -1.0f};
  }
  return SRejoinStatus{
    ERejoinStage::CatchingUp,
    mMergedBeat > mSkippedBeats
      ? static_cast<float>(mReadBeat - mSkippedBeats) / static_cast<float>(mMergedBeat - mSkippedBeats)
      : 0.0f
  };
}

void CRejoinFeed::ReportStatus()
{
  mReportedAt = std::chrono::steady_clock::now();

  const SRejoinStatus status = Status();
  CMessage message = MakeStatusMessage(status.stage, status.progress);
  for (CClientBase* const client : mManager.mClients) {
    if (dynamic_cast<CNetClient*>(client) != nullptr) {
      client->Process(message);
    }
  }
}

bool CRejoinFeed::Route(CMessage& msg)
{
  const std::uint8_t type = msg.GetType().raw();

  if (mCatchingUp) {
    // What the driver or the UI says about beats the recording already holds.
    if (type < static_cast<std::uint8_t>(EClientMsg::CLIMSG_Ack)) {
      return true;
    }
    // Nobody is told yet; the local client keeps its books.
    mLocal->Process(msg);
    return true;
  }

  if (!mLive && type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
    DeliverLocalBeats(ReadInt32Payload(msg));
    return true;
  }
  return false;
}

bool CRejoinFeed::TakeIncoming(CNetClient& client, CMessage& msg)
{
  if (!mLive || !mCatchingUp) {
    return false;
  }

  if (IsPeerMessage(msg, EPeerMessageKind::RejoinBacklog)) {
    const std::uint8_t index = BacklogIndex(msg);
    const auto& fromPeer = mBacklog[static_cast<std::size_t>(client.GetIndex())];
    if (index < fromPeer.size() && msg.GetMessageSize() > 2) {
      fromPeer[index]->VirtWrite(msg.mBuff.start_ + 5, static_cast<std::size_t>(msg.GetMessageSize() - 2));
    }
    return true;
  }
  if (IsPeerMessage(msg, EPeerMessageKind::RejoinInfo)) {
    NotePeerReport(client, msg);
    return true;
  }
  if (IsPeerMessage(msg, EPeerMessageKind::Announce) || IsPeerMessage(msg, EPeerMessageKind::RejoinKey)) {
    mManager.mPeerFeatures->Receive(mManager, client, msg);
    return true;
  }
  if (IsPeerMessage(msg, EPeerMessageKind::RejoinChallenge)) {
    SRejoinNonce nonce{};
    if (msg.GetMessageSize() >= static_cast<int>(kKindBytes + nonce.size())) {
      std::memcpy(nonce.data(), msg.mBuff.start_ + 3 + kKindBytes, nonce.size());
      CMessage proof = MakeProofMessage(nonce, mLocal->GetIndex(), client.GetIndex());
      client.Process(proof);
    }
    return true;
  }

  mHeldIncoming[static_cast<std::size_t>(client.GetIndex())].push_back(msg);
  return true;
}

void CRejoinFeed::NotePeerReport(const CNetClient& peer, CMessage& msg)
{
  const auto peerIndex = static_cast<std::size_t>(peer.GetIndex());
  CMessageStream stream(msg, CMessageStream::Access::kReadOnly);
  gpg::BinaryReader reader(&stream);
  std::uint8_t kind = 0;
  reader.ReadExact(kind);
  std::int32_t dispatched = 0;
  reader.ReadExact(dispatched);
  std::vector<std::int32_t> queued(mManager.mClients.size(), 0);
  for (std::int32_t& beat : queued) {
    reader.ReadExact(beat);
  }
  // Issue #275: each client's stream position at that peer, after the queued beats.
  // An older build ends the report before it.
  std::vector<std::int32_t> streamDispatched;
  const std::size_t withPositions = 1u + sizeof(std::int32_t) * (1u + 2u * queued.size());
  if (static_cast<std::size_t>(msg.GetMessageSize()) >= withPositions) {
    streamDispatched.resize(queued.size(), 0);
    for (std::int32_t& beat : streamDispatched) {
      reader.ReadExact(beat);
    }
  }
  mPeerDispatched[peerIndex] = dispatched;
  mPeerQueued[peerIndex] = queued;
  mPeerStreamDispatched[peerIndex] = std::move(streamDispatched);
  ++mPeersReported;

  int peers = 0;
  for (CClientBase* const client : mManager.mClients) {
    if (dynamic_cast<CNetClient*>(client) != nullptr) {
      ++peers;
    }
  }
  if (mPeersReported < peers) {
    return;
  }

  // Every beat any client has run, every client holds, so the lowest report is
  // at or past all of them, and every peer can go back to it.
  const auto localIndex = static_cast<std::size_t>(mLocal->GetIndex());
  std::int32_t cut = mPeerQueued[static_cast<std::size_t>(mRecordingPeer)][localIndex];
  for (CClientBase* const client : mManager.mClients) {
    if (dynamic_cast<CNetClient*>(client) != nullptr) {
      const std::int32_t held = mPeerQueued[static_cast<std::size_t>(client->GetIndex())][localIndex];
      cut = held < cut ? held : cut;
    }
  }
  mHandoverBeat = cut;
  mMergedBeat = mPeerDispatched[static_cast<std::size_t>(mRecordingPeer)];
  mBacklogComplete = true;
  gpg::Logf(
    "REJOIN: %d peers reported: recording holds to beat %d, this client's old stream ends at beat %d", peers, mMergedBeat, cut
  );

  CMessage cutMessage(EClientMsg::CLIMSG_PeerFeatures);
  CMessageStream cutStream(cutMessage);
  cutStream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinInfo));
  cutStream.Write(cut);
  for (CClientBase* const client : mManager.mClients) {
    if (dynamic_cast<CNetClient*>(client) != nullptr) {
      client->Process(cutMessage);
    }
  }
}

int32_t CRejoinFeed::QueueBacklog(
  CClientBase& client, gpg::PipeStream& backlog, const std::int32_t startBeat, const std::int32_t skipThrough, const std::int32_t stopAt
)
{
  std::int32_t beat = startBeat;
  backlog.VirtFlush();
  while (backlog.GetLength() != 0u && beat < stopAt) {
    CMessage message{};
    if (!message.ReadMessage(&backlog)) {
      break;
    }
    const bool endsBeat = message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance);
    const std::int32_t delta = endsBeat ? ReadInt32Payload(message) : 0;
    if (beat >= skipThrough) {
      client.CClientBase::Process(message);
      if (endsBeat) {
        NoteAcks(client.GetIndex(), static_cast<std::int32_t>(client.mQueuedBeat));
      }
    }
    beat += delta;
  }
  return beat;
}

void CRejoinFeed::FinishCatchUp()
{
  constexpr std::int32_t kNoStop = 0x7FFFFFFF;
  const auto recordingPeer = static_cast<std::size_t>(mRecordingPeer);
  const std::vector<std::int32_t>& recordingQueued = mPeerQueued[recordingPeer];
  const std::int32_t merged = mMergedBeat;
  std::vector<std::int32_t> ownCopyEnd(mManager.mClients.size(), -1);

  // Issue #275: where a peer's copy of a client's stream starts. A multi-beat Advance
  // can leave the stream past the peer's dispatched beat; an older build doesn't say.
  const auto copyStart = [this](const std::size_t peer, const std::size_t index, const std::int32_t otherwise) {
    const std::vector<std::int32_t>& positions = mPeerStreamDispatched[peer];
    return index < positions.size() ? positions[index] : otherwise;
  };

  for (CClientBase* const client : mManager.mClients) {
    const auto index = static_cast<std::size_t>(client->GetIndex());
    // The recording peer's copy holds whole beats, and this client's own only
    // as far as every peer does. A live peer's own copy then goes on from there,
    // with the orders it has not ended a beat for.
    const std::int32_t start = copyStart(recordingPeer, index, merged);
    const std::int32_t stopAt = client == mLocal ? mHandoverBeat : kNoStop;
    if (start > merged) {
      // Beats the recording peer's copy no longer holds: consumed whole by a multi-beat
      // Advance. Their orders came before it and are in the recording, so they are empty here.
      const std::int32_t empty = std::min(start, stopAt) - static_cast<std::int32_t>(client->mQueuedBeat);
      if (empty > 0) {
        CMessage advance{ECmdStreamOp::CMDST_Advance};
        CMessageStream stream(advance);
        stream.Write(empty);
        client->CClientBase::Process(advance);
        NoteAcks(client->GetIndex(), static_cast<std::int32_t>(client->mQueuedBeat));
        gpg::Logf(
          "REJOIN: client %d's stream was at beat %d past the recording's %d: %d empty beats", client->GetIndex(), start, merged, empty
        );
      }
    }
    QueueBacklog(*client, *mBacklog[recordingPeer][index], start, merged, stopAt);
    if (client != mLocal && index != recordingPeer && dynamic_cast<CNetClient*>(client) != nullptr) {
      ownCopyEnd[index] =
        QueueBacklog(*client, *mBacklog[index][index], copyStart(index, index, mPeerDispatched[index]), recordingQueued[index], kNoStop);
    }
  }

  mCatchingUp = false;
  mHandoverPending = true;
  mBackAt = std::chrono::steady_clock::now();
  ReportStatus();
  gpg::Logf(
    "REJOIN: caught up: recording to beat %d, local client queued to beat %u (cut at %d)", mReadBeat, mLocal->mQueuedBeat,
    mHandoverBeat
  );

  // Clients that left before this one came back.
  for (CClientBase* const client : mManager.mClients) {
    if (client != mLocal && dynamic_cast<CNetClient*>(client) == nullptr) {
      if (client->mCommandSourceId == kInvalidCommandSource) {
        client->mEjected = true;
      } else {
        client->Eject();
      }
    }
  }

  // The peers have heard nothing from this client since it died.
  for (CClientBase* const client : mManager.mClients) {
    CMessage ack(EClientMsg::CLIMSG_Ack);
    CMessageStream stream(ack);
    stream.Write(static_cast<std::uint8_t>(client->GetIndex()));
    stream.Write(static_cast<std::int32_t>(client->mQueuedBeat));
    for (CClientBase* const peer : mManager.mClients) {
      if (peer != mLocal) {
        peer->Process(ack);
      }
    }
  }

  // A peer that sent its own copy first has gone on live since, and a recording peer
  // that sent its copy later holds those beats too: each beat is taken once.
  for (CClientBase* const client : mManager.mClients) {
    const auto index = static_cast<std::size_t>(client->GetIndex());
    std::int32_t beat = ownCopyEnd[index];
    for (CMessage& message : mHeldIncoming[index]) {
      if (beat >= 0 && message.GetType().raw() < static_cast<std::uint8_t>(EClientMsg::CLIMSG_Ack)) {
        const bool endsBeat = message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance);
        const std::int32_t delta = endsBeat ? ReadInt32Payload(message) : 0;
        const bool covered = beat < recordingQueued[index];
        beat += delta;
        if (covered) {
          continue;
        }
      }
      client->CClientBase::Process(message);
    }
  }
  mHeldIncoming.clear();
}

bool CRejoinFeed::HoldIssue(std::int32_t& nextIssueBeat)
{
  if (mCatchingUp) {
    return true;
  }
  if (mHandoverPending) {
    mHandoverPending = false;
    nextIssueBeat = static_cast<std::int32_t>(mLocal->mQueuedBeat) + 1;
  }
  return false;
}

bool CRejoinFeed::ReadRecordedBeat()
{
  while (mMessage.Read(mRecording.get())) {
    const std::uint8_t type = mMessage.GetType().raw();

    if (type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_SetCommandSource)) {
      // Not passed on: `UpdateState` writes each client's source itself.
      const std::uint8_t source = ReadSourcePayload(mMessage);
      mRecordedSource = source < mManager.mClients.size() ? mManager.mClients[source] : nullptr;
    } else if (type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
      const std::int32_t beatDelta = ReadInt32Payload(mMessage);
      mReadBeat += beatDelta;
      for (CClientBase* const client : mManager.mClients) {
        if (client != mLocal) {
          client->CClientBase::Process(mMessage);
          NoteAcks(client->GetIndex(), mReadBeat);
        }
      }
      mHeld.VirtWrite(mMessage.mBuff.start_, mMessage.mBuff.Size());
      ++mHeldBeats;
      mMessage.Clear();
      return true;
    } else if (mRecordedSource == mLocal) {
      // From the handover the driver reports this client's checksums itself.
      const bool driverSaysThis = !mCatchingUp && type == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_VerifyChecksum);
      if (!driverSaysThis) {
        mHeld.VirtWrite(mMessage.mBuff.start_, mMessage.mBuff.Size());
      }
    } else if (mRecordedSource != nullptr) {
      mRecordedSource->CClientBase::Process(mMessage);
    }

    mMessage.Clear();
  }
  return false;
}

void CRejoinFeed::DeliverLocalBeat()
{
  mHeld.VirtFlush();
  while (mHeld.GetLength() != 0u) {
    CMessage message{};
    if (!message.ReadMessage(&mHeld)) {
      return;
    }
    const bool endsBeat = message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance);
    mLocal->CClientBase::Process(message);
    if (endsBeat) {
      --mHeldBeats;
      NoteAcks(mLocal->GetIndex(), static_cast<std::int32_t>(mLocal->mQueuedBeat));
      return;
    }
  }
}

void CRejoinFeed::DeliverLocalBeats(const std::int32_t beatDelta)
{
  ++mDriverAdvances;
  mDriverBeats += beatDelta;

  const std::int32_t target = static_cast<std::int32_t>(mLocal->mQueuedBeat) + beatDelta;
  while (static_cast<std::int32_t>(mLocal->mQueuedBeat) < target) {
    if (mHeldBeats == 0 && (mEnded || !ReadRecordedBeat())) {
      EndOfRecording();
      const std::int32_t left = target - static_cast<std::int32_t>(mLocal->mQueuedBeat);
      if (left > 0) {
        WriteAdvance(*mLocal, left);
        NoteAcks(mLocal->GetIndex(), static_cast<std::int32_t>(mLocal->mQueuedBeat));
      }
      return;
    }
    DeliverLocalBeat();
  }
}

void CRejoinFeed::NoteAcks(const int clientIndex, const std::int32_t beat)
{
  CMessage ack(EClientMsg::CLIMSG_Ack);
  CMessageStream stream(ack);
  stream.Write(static_cast<std::uint8_t>(clientIndex));
  stream.Write(beat);
  for (CClientBase* const client : mManager.mClients) {
    if (client != mLocal) {
      client->CClientBase::Process(ack);
    }
  }
}

void CRejoinFeed::EndOfRecording()
{
  if (mEnded) {
    return;
  }
  mEnded = true;
  mCatchingUp = false;
  mHandoverPending = true;

  gpg::Logf(
    "REJOIN: recording ended at beat %d; the driver issued %d beats in %d advances", mReadBeat, mDriverBeats,
    mDriverAdvances
  );

  CClientBase* carrier = mLocal;
  if (carrier->mCommandSourceId == kInvalidCommandSource) {
    for (CClientBase* const client : mManager.mClients) {
      if (client->mCommandSourceId != kInvalidCommandSource) {
        carrier = client;
        break;
      }
    }
  }
  CMessage endGame(ECmdStreamOp::CMDST_EndGame);
  carrier->CClientBase::Process(endGame);

  for (CClientBase* const client : mManager.mClients) {
    if (client != mLocal) {
      WriteAdvance(*client, 1);
      NoteAcks(client->GetIndex(), static_cast<std::int32_t>(client->mQueuedBeat));
      client->Eject();
    }
  }
}

CClientManagerImpl* moho::REJOIN_CreateRehearsalManager(
  const LaunchInfoBase& launchInfo,
  std::unique_ptr<gpg::Stream> recording,
  const int localSource,
  const int handoverBeat,
  const int skipBeats
)
{
  const auto& sources = launchInfo.mCommandSources.mSrcs;
  // Rate 50 is the top of the rate schedule: nothing here runs on a clock.
  CClientManagerImpl* const manager = CLIENT_CreateClientManager(sources.size(), nullptr, 50, true);
  for (std::size_t index = 0; index < sources.size(); ++index) {
    const int client = static_cast<int>(index);
    if (client == localSource) {
      manager->CreateLocalClient(sources[index].mName.c_str(), client, client, static_cast<std::uint32_t>(client));
    } else {
      manager->CreateNullClient(sources[index].mName.c_str(), client, client, static_cast<std::uint32_t>(client));
    }
  }
  manager->mRejoinFeed = std::make_unique<CRejoinFeed>(*manager, std::move(recording), handoverBeat, false, -1, skipBeats);
  return manager;
}

namespace
{
  constexpr std::uint8_t kRecordingBacklog = 0xFFu;
  constexpr std::uint8_t kKeyframeBacklog = 0xFEu;
  constexpr std::int32_t kRequestWithRecording = -2;
  constexpr std::int32_t kRequestWithoutRecording = -1;

  /// A sink plus a copy of what was written to it, and how many beats that holds.
  class CRecordingTee final : public gpg::Stream
  {
  public:
    explicit CRecordingTee(std::unique_ptr<gpg::Stream> sink);
    ~CRecordingTee() override;

    void VirtWrite(const char* data, size_t size) override;
    void VirtFlush() override { mSink->VirtFlush(); }
    void VirtClose(const Mode mode) override { mSink->VirtClose(mode); }

    void Seal();
    void Copy(std::vector<char>& bytes, int& beats);

  private:
    std::unique_ptr<gpg::Stream> mSink;
    std::vector<char> mBytes;
    int mBeats{0};
    bool mSealed{false};
  };

  // One game per process, and the decoder's sim thread writes while the issue
  // thread copies.
  std::mutex sRecordingLock;
  CRecordingTee* sRecording = nullptr;

  CRecordingTee::CRecordingTee(std::unique_ptr<gpg::Stream> sink)
    : mSink(std::move(sink))
  {
    std::scoped_lock lock(sRecordingLock);
    sRecording = this;
  }

  CRecordingTee::~CRecordingTee()
  {
    std::scoped_lock lock(sRecordingLock);
    if (sRecording == this) {
      sRecording = nullptr;
    }
  }

  void CRecordingTee::VirtWrite(const char* const data, const size_t size)
  {
    mSink->Write(data, size);

    std::scoped_lock lock(sRecordingLock);
    mBytes.insert(mBytes.end(), data, data + size);
    // After the header, `CDecoder` writes whole messages, one to a call.
    constexpr size_t kAdvanceBytes = 3u + sizeof(std::int32_t);
    if (mSealed && size >= kAdvanceBytes && static_cast<std::uint8_t>(data[0]) == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
      std::int32_t delta = 0;
      std::memcpy(&delta, data + 3, sizeof(delta));
      mBeats += delta;
    }
  }

  void CRecordingTee::Seal()
  {
    std::scoped_lock lock(sRecordingLock);
    mSealed = true;
  }

  void CRecordingTee::Copy(std::vector<char>& bytes, int& beats)
  {
    bytes = mBytes;
    beats = mBeats;
  }

  [[nodiscard]] bool CopyRecording(std::vector<char>& bytes, int& beats)
  {
    std::scoped_lock lock(sRecordingLock);
    if (sRecording == nullptr) {
      return false;
    }
    sRecording->Copy(bytes, beats);
    return true;
  }

  // Requests waiting for this client to serve them; under the manager's lock.
  struct SPendingServe
  {
    CNetClient* peer;
    bool wantRecording;
    bool wantKeyframe;
  };
  std::vector<SPendingServe> sPendingServes;
  // net_MaxSendRate and net_MaxBacklog while a recording goes out; 0 when they are not raised.
  std::int32_t sSavedSendRate = 0;
  std::int32_t sSavedBacklog = 0;
  // A connection that has 2 KB queued waits at least a millisecond, which keeps it well under
  // net_RejoinSendRate. The game is stopped for this, so a larger burst holds nothing up.
  constexpr std::int32_t kRejoinBacklog = 16384;

  // A packed save: one byte for how, the raw size, then the bytes.
  enum class ERejoinPacking : std::uint8_t
  {
    Zlib = 0,
    Zstd = 1,
  };
  constexpr std::size_t kPackedHeaderBytes = 1u + sizeof(std::uint64_t);
  // On a 160 MB save, against zlib's default: 7.2 MB in 0.33 s, where zlib takes 11.2 MB and 2.08 s.
  constexpr int kRejoinZstdLevel = 3;

  /// Only for a link whose far end runs this build: see `CNetUDPConnection::SetWindow`.
  void WidenRejoinLink(INetConnection* const link)
  {
#if defined(_WIN32)
    if (auto* const udp = dynamic_cast<CNetUDPConnection*>(link)) {
      udp->SetWindow(static_cast<std::uint16_t>(std::clamp(net_RejoinWindow, 32, 4096)));
    }
#else
    (void)link;
#endif
  }

  /// What one peer has said before there is a session to tell.
  class CBootReceiver final : public IMessageReceiver
  {
  public:
    void ReceiveMessage(CMessage* const message, CMessageDispatcher* const) override
    {
      mHeard = true;
      if (IsPeerMessage(*message, EPeerMessageKind::RejoinBacklog) &&
          (BacklogIndex(*message) == kRecordingBacklog || BacklogIndex(*message) == kKeyframeBacklog)) {
        const auto* const payload = message->mBuff.start_ + 5;
        std::vector<char>& bytes = BacklogIndex(*message) == kRecordingBacklog ? mRecording : mKeyframe;
        bytes.insert(bytes.end(), payload, payload + (message->GetMessageSize() - 2));
        return;
      }
      if (IsPeerMessage(*message, EPeerMessageKind::RejoinRecordingSize) &&
          message->GetMessageSize() >= static_cast<int>(kKindBytes + sizeof(mRecordingSize))) {
        std::memcpy(&mRecordingSize, message->mBuff.start_ + 3 + kKindBytes, sizeof(mRecordingSize));
        return;
      }
      if (IsPeerMessage(*message, EPeerMessageKind::RejoinChallenge) &&
          message->GetMessageSize() >= static_cast<int>(kKindBytes + sizeof(SRejoinNonce)) && mLink != nullptr) {
        SRejoinNonce nonce{};
        std::memcpy(nonce.data(), message->mBuff.start_ + 3 + kKindBytes, nonce.size());
        CMessage proof = MakeProofMessage(nonce, mLocalSource, mPeerSource);
        NetDataSpan span{
          reinterpret_cast<std::uint8_t*>(proof.mBuff.start_),
          reinterpret_cast<std::uint8_t*>(proof.mBuff.end_),
        };
        mLink->Write(&span);
        return;
      }
      if (IsPeerMessage(*message, EPeerMessageKind::RejoinRefused)) {
        mRefused = true;
        if (message->GetMessageSize() > static_cast<int>(kKindBytes)) {
          mRefusal = static_cast<ERejoinRefusal>(message->mBuff.start_[3 + kKindBytes]);
        }
        return;
      }
      if (IsPeerMessage(*message, EPeerMessageKind::RejoinInfo)) {
        mReported = true;
      }
      mHeld.push_back(*message);
    }

    /// Where to answer a challenge from this peer, and for which seat.
    void SetProofTarget(INetConnection* const link, const int localSource, const int peerSource)
    {
      mLink = link;
      mLocalSource = localSource;
      mPeerSource = peerSource;
    }

    /// How much of the recording has come, 0 to 1, or negative before its size is known.
    [[nodiscard]] float RecordingProgress() const
    {
      return mRecordingSize > 0 ? static_cast<float>(ReceivedBytes()) / static_cast<float>(mRecordingSize) : -1.0f;
    }

    [[nodiscard]] std::size_t ReceivedBytes() const { return mRecording.size() + mKeyframe.size(); }
    [[nodiscard]] const std::vector<char>& Keyframe() const { return mKeyframe; }

    [[nodiscard]] bool Reported() const { return mReported; }
    [[nodiscard]] bool Refused() const { return mRefused; }
    [[nodiscard]] ERejoinRefusal Refusal() const { return mRefusal; }
    [[nodiscard]] bool Heard() const { return mHeard; }
    [[nodiscard]] const std::vector<char>& Recording() const { return mRecording; }
    [[nodiscard]] std::vector<CMessage>& Held() { return mHeld; }

  private:
    std::vector<char> mRecording;
    std::vector<char> mKeyframe;
    std::vector<CMessage> mHeld;
    std::int32_t mRecordingSize{0};
    bool mReported{false};
    bool mRefused{false};
    bool mHeard{false};
    ERejoinRefusal mRefusal{ERejoinRefusal::Key};
    INetConnection* mLink{nullptr};
    int mLocalSource{-1};
    int mPeerSource{-1};
  };

  void ApplyCut(CClientManagerImpl& manager, CClientBase& peer, const std::int32_t cutBeat)
  {
    const std::int32_t held = static_cast<std::int32_t>(peer.mQueuedBeat);
    std::int32_t beat = static_cast<std::int32_t>(peer.mDispatchedBeat);
    if (cutBeat < beat || cutBeat > held) {
      gpg::Warnf("REJOIN: ignoring a cut at beat %d from client %d: it has run to %d, held to %d", cutBeat, peer.GetIndex(), beat, held);
      return;
    }

    std::vector<CMessage> kept;
    peer.mPipe.VirtFlush();
    while (peer.mPipe.GetLength() != 0u) {
      CMessage message{};
      if (!message.ReadMessage(&peer.mPipe)) {
        break;
      }
      if (beat < cutBeat) {
        if (message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
          beat += ReadInt32Payload(message);
        }
        kept.push_back(message);
      }
    }
    for (CMessage& message : kept) {
      peer.mPipe.VirtWrite(message.mBuff.start_, message.mBuff.Size());
    }
    peer.mQueuedBeat = static_cast<std::uint32_t>(cutBeat);

    // Reports of the beats just dropped are no longer true, and this client's own
    // report is what lets a beat run here.
    const auto peerIndex = static_cast<std::size_t>(peer.GetIndex());
    for (CClientBase* const client : manager.mClients) {
      if (peerIndex < client->mLatestAckReceived.size() && client->mLatestAckReceived[peerIndex] > cutBeat) {
        client->mLatestAckReceived[peerIndex] = cutBeat;
      }
    }
    gpg::Logf("REJOIN: client %d's old stream cut at beat %d, %d beats dropped", peer.GetIndex(), cutBeat, held - cutBeat);
  }
} // namespace

namespace
{
  /// Says which saves this client can load: a save is only good for the build and word size that wrote it.
  [[nodiscard]] std::string KeyframeBuildId()
  {
    return std::string(gpg::diag::BuildCommitShort()) + "/" + std::to_string(sizeof(void*) * 8u);
  }

  /// A file that goes away when it is closed: a save is far too large to be sure of memory for it twice.
  [[nodiscard]] boost::shared_ptr<std::FILE> OpenScratchFile()
  {
    static std::atomic<int> sCount{0};
    std::error_code ignored;
    const std::filesystem::path path = std::filesystem::temp_directory_path(ignored) /
      ("faf_rejoin_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
       std::to_string(sCount.fetch_add(1)) + ".bin");
    std::FILE* file = nullptr;
#if defined(_WIN32)
    if (fopen_s(&file, path.string().c_str(), "w+bD") != 0) {
      file = nullptr;
    }
#else
    if (fopen_s(&file, path.string().c_str(), "w+b") != 0) {
      file = nullptr;
    } else if (file != nullptr) {
      std::error_code removed;
      std::filesystem::remove(path, removed);
    }
#endif
    if (file == nullptr) {
      throw std::runtime_error("cannot write " + path.string());
    }
    return boost::shared_ptr<std::FILE>(file, SFileStarCloser{});
  }

  // A peer's save of the running game, on its way to a client that restarted. Under
  // `sKeyframeLock`: the issue thread asks for it, and the main thread finishes it.
  enum class EKeyframeState
  {
    None,
    Wanted,
    Saving,
    Ready,
  };
  std::mutex sKeyframeLock;
  EKeyframeState sKeyframeState = EKeyframeState::None;
  std::vector<char> sKeyframeBytes; // an original size, then the save packed; empty if it failed

  /// Whether the save is done. The first call asks for one, which the main thread takes to the driver.
  [[nodiscard]] bool KeyframeReady()
  {
    std::scoped_lock lock(sKeyframeLock);
    if (sKeyframeState == EKeyframeState::None) {
      sKeyframeState = EKeyframeState::Wanted;
    }
    return sKeyframeState == EKeyframeState::Ready;
  }

  void FinishKeyframe(std::vector<char> bytes)
  {
    std::scoped_lock lock(sKeyframeLock);
    sKeyframeBytes = std::move(bytes);
    sKeyframeState = EKeyframeState::Ready;
  }

  /**
   * As headless's `CKeyframeRequest`: the sim's thread calls `GetArchive` between beats
   * and saves the sim into it (`CSimDriver::PreparePendingSaveRequestLocked`), and
   * `CSimDriver::Dispatch` then calls `Save` on the main thread.
   */
  class CRejoinKeyframeRequest final : public ISaveRequest
  {
  public:
    explicit CRejoinKeyframeRequest(const Sim& sim)
      : mSim(sim)
    {}

    gpg::WriteArchive* GetArchive() override
    {
      mStart = std::chrono::steady_clock::now();
      // A retail-format save changes the sim (see gSimExactArchive); this one must not.
      gSimExactSaveCount.fetch_add(1u);
      gSimExactArchive.store(true);
      mFile = OpenScratchFile();
      SSimKeyframeHeader header{};
      SIM_CaptureKeyframeHeader(mSim, header);
      mBeat = header.beat;
      if (!SIM_WriteKeyframeHeader(mFile.get(), header)) {
        throw std::runtime_error("cannot write the save's header");
      }
      mArchive = net_RejoinFastSave != 0 ? gpg::CreateFastBinaryWriteArchive(mFile) : gpg::CreateBinaryWriteArchive(mFile);
      return mArchive;
    }

    void Save(const SSaveGameDispatchData& data) override
    {
      delete mArchive;
      mArchive = nullptr;

      std::vector<char> packed;
      if (!data.useSuggestedName || mFile.get() == nullptr) {
        gpg::Warnf("REJOIN: the save failed: %s", data.saveName.c_str());
      } else {
        packed = PackFile();
      }
      mFile.reset();
      FinishKeyframe(std::move(packed));
      delete this;
    }

  private:
    ~CRejoinKeyframeRequest()
    {
      delete mArchive;
    }

    [[nodiscard]] std::vector<char> PackFile()
    {
      const auto packStart = std::chrono::steady_clock::now();
      std::FILE* const file = mFile.get();
      std::fflush(file);
      std::fseek(file, 0, SEEK_END);
      const long size = std::ftell(file);
      std::fseek(file, 0, SEEK_SET);
      if (size <= 0) {
        return {};
      }
      std::vector<unsigned char> raw(static_cast<std::size_t>(size));
      if (std::fread(raw.data(), raw.size(), 1u, file) != 1u) {
        return {};
      }

      const std::uint64_t rawSize = raw.size();
      const ERejoinPacking packing = net_RejoinZstd != 0 ? ERejoinPacking::Zstd : ERejoinPacking::Zlib;
      std::vector<char> packed;
      std::size_t packedSize = 0;
      if (packing == ERejoinPacking::Zstd) {
        packed.resize(kPackedHeaderBytes + ZSTD_compressBound(raw.size()));
        packedSize = ZSTD_compress(
          packed.data() + kPackedHeaderBytes, packed.size() - kPackedHeaderBytes, raw.data(), raw.size(), kRejoinZstdLevel
        );
        if (ZSTD_isError(packedSize) != 0u) {
          return {};
        }
      } else {
        uLongf zlibSize = SIM_KeyframePackBound(static_cast<uLong>(raw.size()));
        packed.resize(kPackedHeaderBytes + zlibSize);
        if (compress2(
              reinterpret_cast<Bytef*>(packed.data() + kPackedHeaderBytes), &zlibSize, raw.data(),
              static_cast<uLong>(raw.size()), Z_DEFAULT_COMPRESSION
            ) != Z_OK) {
          return {};
        }
        packedSize = zlibSize;
      }
      packed[0] = static_cast<char>(packing);
      std::memcpy(packed.data() + 1, &rawSize, sizeof(rawSize));
      packed.resize(kPackedHeaderBytes + packedSize);

      const auto now = std::chrono::steady_clock::now();
      gpg::Logf(
        "REJOIN: saved the game at beat %u: %llu bytes, %llu packed, %.1f s, %.1f s of it packing", mBeat,
        static_cast<unsigned long long>(rawSize), static_cast<unsigned long long>(packedSize),
        std::chrono::duration<double>(now - mStart).count(), std::chrono::duration<double>(now - packStart).count()
      );
      return packed;
    }

    const Sim& mSim;
    std::uint32_t mBeat = 0;
    std::chrono::steady_clock::time_point mStart{};
    boost::shared_ptr<std::FILE> mFile;
    gpg::WriteArchive* mArchive = nullptr;
  };

  // When this client started taking its seat back, for the log.
  std::chrono::steady_clock::time_point sRejoinStart{};

  // A client coming back: the save it was sent, until the session's driver is created.
  boost::shared_ptr<std::FILE> sRestoreFile;
  SSimKeyframeHeader sRestoreHeader{};
} // namespace

void moho::REJOIN_MainFrame(ISTIDriver& driver)
{
  {
    std::scoped_lock lock(sKeyframeLock);
    if (sKeyframeState != EKeyframeState::Wanted) {
      return;
    }
    sKeyframeState = EKeyframeState::Saving;
  }

  const auto* const simDriver = dynamic_cast<CSimDriver*>(&driver);
  const Sim* const sim = simDriver != nullptr ? simDriver->GetSimForReplayCheck() : nullptr;
  if (sim == nullptr) {
    gpg::Warnf("REJOIN: this session cannot save its sim");
    FinishKeyframe({});
    return;
  }
  driver.RequestSaveGame(new CRejoinKeyframeRequest(*sim));
}

void moho::REJOIN_PrepareRestore(SWldSessionInfo& sessionInfo)
{
  if (sRestoreFile.get() == nullptr) {
    return;
  }

  LaunchInfoBase* const launchInfo = sessionInfo.mLaunchInfo.get();
  boost::shared_ptr<LaunchInfoLoad> loadInfo;
  (void)boost::ConstructSharedLaunchInfoLoadFromRaw(&loadInfo, new LaunchInfoLoad());
  loadInfo->mGameRules = launchInfo->mGameRules;
  loadInfo->mMap = launchInfo->mMap;
  launchInfo->mMap = nullptr;
  loadInfo->mGameMods = launchInfo->mGameMods;
  loadInfo->mScenarioInfo = launchInfo->mScenarioInfo;
  loadInfo->mArmyLaunchInfo = launchInfo->mArmyLaunchInfo;
  loadInfo->mCommandSources = launchInfo->mCommandSources;
  loadInfo->mLanguage = launchInfo->mLanguage;
  loadInfo->mCheatsEnabled = launchInfo->mCheatsEnabled;
  loadInfo->mReadArchive = gpg::CreateBinaryReadArchive(sRestoreFile);
  sRestoreFile.reset();

  SIM_BeginKeyframeRestore(sRestoreHeader);
  // Unlike a replay's, this session's clients already count in the game's own beats.
  gSimBeatOrigin.store(0);
  sessionInfo.mLaunchInfo = boost::static_pointer_cast<LaunchInfoBase>(loadInfo);
  gpg::Logf(
    "REJOIN: loading the save of beat %u, %.1f s after starting", sRestoreHeader.beat,
    std::chrono::duration<double>(std::chrono::steady_clock::now() - sRejoinStart).count()
  );
}

std::unique_ptr<gpg::Stream> moho::REJOIN_WrapRecording(std::unique_ptr<gpg::Stream> sink)
{
  return std::make_unique<CRecordingTee>(std::move(sink));
}

void moho::REJOIN_SealRecordingHeader(gpg::Stream* const stream)
{
  if (auto* const tee = dynamic_cast<CRecordingTee*>(stream)) {
    tee->Seal();

    // This client's replay of a game it loaded from a save starts where the game did.
    for (CMessage& message : sReplayHistory) {
      tee->VirtWrite(message.mBuff.start_, message.mBuff.Size());
    }
    sReplayHistory.clear();
  }
}

namespace
{
  /// Sends `bytes` as backlog messages, in pieces a message can hold.
  void SendBacklogBytes(CNetClient& peer, const std::uint8_t index, const char* const bytes, const std::size_t size)
  {
    constexpr std::size_t kChunkBytes = 60000u;
    for (std::size_t sent = 0; sent < size;) {
      const std::size_t piece = std::min(kChunkBytes, size - sent);
      CMessage backlog(EClientMsg::CLIMSG_PeerFeatures);
      CMessageStream stream(backlog);
      stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinBacklog));
      stream.Write(index);
      stream.Write(bytes + sent, piece);
      peer.Process(backlog);
      sent += piece;
    }
  }

  /// Everything queued and not yet run, and this client's report, to `peer`.
  void SendBacklog(CClientManagerImpl& manager, CNetClient& peer)
  {
    // A restarted peer has forgotten what this client supports.
    manager.mPeerFeatures->AnnounceTo(manager, peer);

    // A dead client's unfinished beat is dropped: nobody can have run it, and it
    // starts that beat again. Other clients' unfinished beats stay here and are
    // not sent: each of them sends its own, and this client's orders go with its
    // whole beats.
    for (CClientBase* const client : manager.mClients) {
      std::vector<CMessage> queued;
      std::size_t whole = 0;
      client->mPipe.VirtFlush();
      while (client->mPipe.GetLength() != 0u) {
        CMessage message{};
        if (!message.ReadMessage(&client->mPipe)) {
          break;
        }
        const bool endsBeat = message.GetType().raw() == static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance);
        queued.push_back(message);
        if (endsBeat) {
          whole = queued.size();
        }
      }
      const std::size_t keep = client == &peer ? whole : queued.size();
      const std::size_t send = client == manager.mLocalClient ? queued.size() : whole;

      std::vector<char> bytes;
      for (std::size_t index = 0; index < queued.size(); ++index) {
        CMessage& message = queued[index];
        if (index < keep) {
          client->mPipe.VirtWrite(message.mBuff.start_, message.mBuff.Size());
        }
        if (index < send) {
          bytes.insert(bytes.end(), message.mBuff.start_, message.mBuff.start_ + message.mBuff.Size());
        }
      }
      SendBacklogBytes(peer, static_cast<std::uint8_t>(client->GetIndex()), bytes.data(), bytes.size());
    }

    CMessage info(EClientMsg::CLIMSG_PeerFeatures);
    CMessageStream infoStream(info);
    infoStream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinInfo));
    infoStream.Write(static_cast<std::int32_t>(manager.mDispatchedBeat));
    for (CClientBase* const client : manager.mClients) {
      infoStream.Write(static_cast<std::int32_t>(client->mQueuedBeat));
    }
    // Issue #275: where each client's backlog above starts. After a multi-beat Advance a
    // client's stream is past the dispatched beat, and its copy holds none of those beats.
    for (CClientBase* const client : manager.mClients) {
      infoStream.Write(static_cast<std::int32_t>(client->mDispatchedBeat));
    }
    peer.Process(info);

    // This client's books as the peer last heard them may be far behind.
    for (CClientBase* const client : manager.mClients) {
      CMessage ack(EClientMsg::CLIMSG_Ack);
      CMessageStream ackStream(ack);
      ackStream.Write(static_cast<std::uint8_t>(client->GetIndex()));
      ackStream.Write(static_cast<std::int32_t>(client->mQueuedBeat));
      peer.Process(ack);
    }
  }
} // namespace

namespace
{
  void WriteRefusal(INetConnection& link, const ERejoinRefusal why)
  {
    CMessage refusal(EClientMsg::CLIMSG_PeerFeatures);
    CMessageStream stream(refusal);
    stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinRefused));
    stream.Write(static_cast<std::uint8_t>(why));
    NetDataSpan span{
      reinterpret_cast<std::uint8_t*>(refusal.mBuff.start_),
      reinterpret_cast<std::uint8_t*>(refusal.mBuff.end_),
    };
    link.Write(&span);
  }

  /**
   * A connection from a seat's old address that has not proved it is that seat's player. It is
   * not the seat's link: nothing of the game reaches it, nothing it says counts as the seat's, and
   * the link it hopes to replace stays. It gets a challenge to sign, and only then takes the seat.
   */
  class CRejoinCandidate final : public IMessageReceiver
  {
  public:
    enum class EState
    {
      Waiting,
      Proven,
      Failed,
    };

    CRejoinCandidate(CClientManagerImpl& manager, CNetClient& seat, INetConnection* const link)
      : mManager(manager)
      , mSeat(seat)
      , mLink(link)
      , mDeadline(std::chrono::steady_clock::now() + kProofWait)
    {
      auto* const dispatcher = static_cast<CMessageDispatcher*>(mLink);
      dispatcher->PushReceiver(MSGTYPE_SimBase, MSGTYPE_SimEnd, this);
      dispatcher->PushReceiver(MSGTYPE_ClientBase, MSGTYPE_ClientEnd, this);
      dispatcher->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
    }

    void ReceiveMessage(CMessage* const message, CMessageDispatcher* const) override
    {
      std::scoped_lock lock(mManager.mLock);
      if (mState == EState::Proven) {
        // Its link is about to become the seat's: this is the seat talking.
        mAfterProof.push_back(*message);
      } else if (mState == EState::Waiting && IsPeerMessage(*message, EPeerMessageKind::RejoinInfo)) {
        TakeRequest(*message);
      } else if (mState == EState::Waiting && IsPeerMessage(*message, EPeerMessageKind::RejoinProof)) {
        TakeProof(*message);
      }
    }

    [[nodiscard]] CClientManagerImpl& Manager() const { return mManager; }
    [[nodiscard]] CNetClient& Seat() const { return mSeat; }
    [[nodiscard]] EState State() const { return mState; }
    [[nodiscard]] bool Expired() const { return std::chrono::steady_clock::now() >= mDeadline; }
    [[nodiscard]] const SPendingServe& Serve() const { return mServe; }
    [[nodiscard]] std::vector<CMessage>& AfterProof() { return mAfterProof; }

    void Refuse(const ERejoinRefusal why)
    {
      WriteRefusal(*mLink, why);
      mState = EState::Failed;
    }

    /// Takes this candidate off its link, which goes to the seat or is closed.
    [[nodiscard]] INetConnection* Release()
    {
      auto* const dispatcher = static_cast<CMessageDispatcher*>(mLink);
      dispatcher->RemoveReceiver(MSGTYPE_SimBase, MSGTYPE_SimEnd, this);
      dispatcher->RemoveReceiver(MSGTYPE_ClientBase, MSGTYPE_ClientEnd, this);
      dispatcher->RemoveReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, this);
      return mLink;
    }

  private:
    static constexpr std::chrono::seconds kProofWait{30};

    void TakeRequest(CMessage& message)
    {
      std::int32_t value = 0;
      if (message.GetMessageSize() < static_cast<int>(kKindBytes + sizeof(value))) {
        return;
      }
      std::memcpy(&value, message.mBuff.start_ + 3 + kKindBytes, sizeof(value));
      if (value >= 0) {
        return;
      }
      if (mSeat.mEjectPending || mSeat.mEjected) {
        gpg::Logf("REJOIN: client %d asked for a seat this player voted to eject", mSeat.GetIndex());
        Refuse(ERejoinRefusal::Ejected);
        return;
      }
      CPeerFeatures& features = *mManager.mPeerFeatures;
      if (!features.HasRejoinKey(mSeat.GetIndex())) {
        gpg::Warnf("REJOIN: client %d's seat was asked for, and this client has no key for it", mSeat.GetIndex());
        Refuse(ERejoinRefusal::Key);
        return;
      }

      // After the value, the build the client can load a save from, if it wants one.
      const std::size_t idOffset = 3 + kKindBytes + sizeof(value);
      const std::size_t idBytes = static_cast<std::size_t>(message.GetMessageSize()) - (kKindBytes + sizeof(value));
      const std::string id(message.mBuff.start_ + idOffset, strnlen(message.mBuff.start_ + idOffset, idBytes));
      const bool wantKeyframe = value == kRequestWithRecording && net_RejoinKeyframes != 0 && id == KeyframeBuildId();
      mServe = SPendingServe{&mSeat, value == kRequestWithRecording, wantKeyframe};
      mHasRequest = true;

      const SRejoinNonce nonce = features.StartRejoinChallenge(mSeat.GetIndex());
      CMessage challenge(EClientMsg::CLIMSG_PeerFeatures);
      CMessageStream stream(challenge);
      stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinChallenge));
      stream.Write(reinterpret_cast<const char*>(nonce.data()), nonce.size());
      NetDataSpan span{
        reinterpret_cast<std::uint8_t*>(challenge.mBuff.start_),
        reinterpret_cast<std::uint8_t*>(challenge.mBuff.end_),
      };
      mLink->Write(&span);
    }

    void TakeProof(CMessage& message)
    {
      SRejoinSignature signature{};
      if (!mHasRequest || message.GetMessageSize() < static_cast<int>(kKindBytes + signature.size())) {
        return;
      }
      std::memcpy(signature.data(), message.mBuff.start_ + 3 + kKindBytes, signature.size());
      if (mManager.mPeerFeatures->CheckRejoinProof(mSeat.GetIndex(), mManager.mLocalClient->GetIndex(), signature)) {
        gpg::Logf("REJOIN: client %d proved its seat", mSeat.GetIndex());
        mState = EState::Proven;
      } else {
        gpg::Warnf("REJOIN: client %d's proof failed; it gets nothing of the game", mSeat.GetIndex());
        Refuse(ERejoinRefusal::Key);
      }
    }

    CClientManagerImpl& mManager;
    CNetClient& mSeat;
    INetConnection* mLink;
    std::chrono::steady_clock::time_point mDeadline;
    EState mState{EState::Waiting};
    bool mHasRequest{false};
    SPendingServe mServe{};
    std::vector<CMessage> mAfterProof;
  };

  std::vector<std::unique_ptr<CRejoinCandidate>> sCandidates;

  /// A candidate has had its answer, or its time: it takes the seat, or its link closes.
  void SettleCandidates(CClientManagerImpl& manager)
  {
    for (std::size_t index = 0; index < sCandidates.size();) {
      CRejoinCandidate& candidate = *sCandidates[index];
      if (&candidate.Manager() != &manager) {
        // Left from a session that has ended, whose connector took the link with it.
        (void)sCandidates[index].release();
        sCandidates.erase(sCandidates.begin() + static_cast<std::ptrdiff_t>(index));
        continue;
      }
      // The vote came between its proof and now: the seat is no longer there to take.
      if (candidate.State() == CRejoinCandidate::EState::Proven && (candidate.Seat().mEjectPending || candidate.Seat().mEjected)) {
        candidate.Refuse(ERejoinRefusal::Ejected);
      }
      const auto state = candidate.State();
      if (state == CRejoinCandidate::EState::Waiting && !candidate.Expired()) {
        ++index;
        continue;
      }

      INetConnection* const link = candidate.Release();
      if (state == CRejoinCandidate::EState::Proven) {
        CNetClient& seat = candidate.Seat();
        seat.ReplaceConnection(link);
        // Asking for a save says this client runs this build.
        if (candidate.Serve().wantKeyframe) {
          WidenRejoinLink(link);
        }
        manager.mPeerFeatures->NoteRejoinStarted(seat.GetIndex());
        gpg::Logf("REJOIN: client %d:%s came back on a new link", seat.GetIndex(), seat.GetNickname().c_str());
        sPendingServes.push_back(candidate.Serve());
        for (CMessage& message : candidate.AfterProof()) {
          seat.ReceiveMessage(&message, nullptr);
        }
      } else {
        link->ScheduleDestroy();
      }
      sCandidates.erase(sCandidates.begin() + static_cast<std::ptrdiff_t>(index));
    }
  }
} // namespace

bool moho::REJOIN_BacklogPending(const CNetClient& seat)
{
  return std::any_of(sPendingServes.begin(), sPendingServes.end(), [&seat](const SPendingServe& pending) {
    return pending.peer == &seat;
  });
}

void moho::REJOIN_NoteSeatEjected(CClientManagerImpl& manager, CNetClient& seat)
{
  INetConnection& link = *seat.mConnection;
  manager.mPeerFeatures->NoteRejoinEjected(seat.GetIndex(), static_cast<std::uint32_t>(link.GetAddr()), static_cast<std::uint16_t>(link.GetPort()));

  const ERejoinStage stage = manager.mPeerFeatures->RejoinStatus(seat.GetIndex()).stage;
  if (stage == ERejoinStage::Transfer || stage == ERejoinStage::Loading || stage == ERejoinStage::CatchingUp) {
    WriteRefusal(link, ERejoinRefusal::Ejected);
  }
}

void moho::REJOIN_ServeRestartedPeers(CClientManagerImpl& manager)
{
  SettleCandidates(manager);

  INetConnector* const connector = manager.mConnector;
  u_long address = 0;
  u_short port = 0;
  while (connector->FindNextAddress(address, port)) {
    CNetClient* peer = nullptr;
    for (CClientBase* const client : manager.mClients) {
      auto* const net = dynamic_cast<CNetClient*>(client);
      if (net != nullptr && net->mConnection != nullptr && !net->mEjectPending && !net->mEjected &&
          net->mConnection->GetAddr() == address && net->mConnection->GetPort() == port) {
        peer = net;
        break;
      }
    }
    if (peer == nullptr) {
      // Voted out here: the seat's link is gone, and its player is told so rather than left to wait.
      const int ejected = manager.mPeerFeatures->FindEjectedSeat(static_cast<std::uint32_t>(address), static_cast<std::uint16_t>(port));
      peer = ejected >= 0 ? dynamic_cast<CNetClient*>(manager.mClients[static_cast<std::size_t>(ejected)]) : nullptr;
    }
    if (peer == nullptr) {
      connector->Reject(address, port);
      continue;
    }

    INetConnection* const link = connector->Accept(address, port);
    if (link == nullptr) {
      connector->Reject(address, port);
      continue;
    }
    // A newer attempt from that address takes the place of one still waiting.
    for (std::size_t index = 0; index < sCandidates.size(); ++index) {
      if (&sCandidates[index]->Seat() == peer) {
        sCandidates[index]->Release()->ScheduleDestroy();
        sCandidates.erase(sCandidates.begin() + static_cast<std::ptrdiff_t>(index));
        break;
      }
    }
    sCandidates.push_back(std::make_unique<CRejoinCandidate>(manager, *peer, link));
    gpg::Logf("REJOIN: client %d:%s is asked to prove its seat", peer->GetIndex(), peer->GetNickname().c_str());
  }

  for (std::size_t index = 0; index < sPendingServes.size();) {
    const SPendingServe pending = sPendingServes[index];
    // Voted out since it asked: its link is gone, and the save would go nowhere.
    if (pending.peer->mEjectPending || pending.peer->mEjected) {
      sPendingServes.erase(sPendingServes.begin() + static_cast<std::ptrdiff_t>(index));
      continue;
    }
    if (pending.wantRecording) {
      std::vector<char> bytes;
      int beats = 0;
      if (!CopyRecording(bytes, beats)) {
        gpg::Warnf("REJOIN: client %d asked for the recording, and this client has none", pending.peer->GetIndex());
      } else if (beats < manager.mDispatchedBeat) {
        // The sim thread is still writing the beat it dispatched last.
        ++index;
        continue;
      } else if (pending.wantKeyframe && !KeyframeReady()) {
        ++index;
        continue;
      } else {
        std::vector<char> keyframe;
        if (pending.wantKeyframe) {
          std::scoped_lock lock(sKeyframeLock);
          keyframe = std::move(sKeyframeBytes);
          sKeyframeBytes.clear();
          sKeyframeState = EKeyframeState::None;
        }
        // The save is at or behind the recording, which this copy has to reach.
        if (!CopyRecording(bytes, beats)) {
          bytes.clear();
        }
        if (sSavedSendRate == 0) {
          sSavedSendRate = net_MaxSendRate;
          net_MaxSendRate = std::max(net_MaxSendRate, net_RejoinSendRate);
          sSavedBacklog = net_MaxBacklog;
          net_MaxBacklog = std::max(net_MaxBacklog, kRejoinBacklog);
        }
        CMessage size(EClientMsg::CLIMSG_PeerFeatures);
        CMessageStream sizeStream(size);
        sizeStream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinRecordingSize));
        sizeStream.Write(static_cast<std::int32_t>(bytes.size() + keyframe.size()));
        pending.peer->Process(size);
        SendBacklogBytes(*pending.peer, kRecordingBacklog, bytes.data(), bytes.size());
        SendBacklogBytes(*pending.peer, kKeyframeBacklog, keyframe.data(), keyframe.size());
        gpg::Logf(
          "REJOIN: sending client %d the recording: %d beats, %u bytes, and a save of %u bytes", pending.peer->GetIndex(),
          beats, static_cast<unsigned int>(bytes.size()), static_cast<unsigned int>(keyframe.size())
        );
      }
    }
    SendBacklog(manager, *pending.peer);
    gpg::Logf(
      "REJOIN: client %d:%s served: dispatched to beat %d, its data held to beat %u", pending.peer->GetIndex(),
      pending.peer->GetNickname().c_str(), manager.mDispatchedBeat, pending.peer->mQueuedBeat
    );
    sPendingServes.erase(sPendingServes.begin() + static_cast<std::ptrdiff_t>(index));
  }
}

void moho::REJOIN_HandlePeerMessage(CClientManagerImpl& manager, CNetClient& peer, CMessage& msg)
{
  std::int32_t value = 0;
  if (msg.GetMessageSize() < static_cast<int>(kKindBytes + sizeof(value))) {
    return;
  }
  std::memcpy(&value, msg.mBuff.start_ + 3 + kKindBytes, sizeof(value));
  if (value < 0) {
    // After the value, the build the client can load a save from, if it wants one.
    const std::size_t idOffset = 3 + kKindBytes + sizeof(value);
    const std::size_t idBytes = static_cast<std::size_t>(msg.GetMessageSize()) - (kKindBytes + sizeof(value));
    const std::string id(msg.mBuff.start_ + idOffset, strnlen(msg.mBuff.start_ + idOffset, idBytes));
    (void)id;
    // A seat is asked for on a candidate's link (CRejoinCandidate), never on the seat's own.
    gpg::Warnf("REJOIN: ignoring a request for its seat from client %d, which is connected", peer.GetIndex());
    return;
  }

  if (!manager.mPeerFeatures->RejoinProven(peer.GetIndex())) {
    gpg::Warnf("REJOIN: ignoring a report from client %d, which has not proved its seat", peer.GetIndex());
    return;
  }

  // The peer sends this once it holds everything, so the rate can go back.
  if (sPendingServes.empty() && sSavedSendRate != 0) {
    net_MaxSendRate = sSavedSendRate;
    sSavedSendRate = 0;
    net_MaxBacklog = sSavedBacklog;
    sSavedBacklog = 0;
  }
  ApplyCut(manager, peer, value);
}

namespace
{
  // What `REJOIN_BeginSetup` leaves for `REJOIN_PollSetup`. One game per process.
  struct SSetupPeer
  {
    int source{-1};
    u_long address{0};
    u_short port{0};
    INetConnection* link{nullptr};
    CBootReceiver receiver;
  };

  struct SSetup
  {
    // The first holds the recording this client asks for.
    std::vector<std::unique_ptr<SSetupPeer>> list;
    INetConnector* connector{nullptr};
    int localSource{0};
    std::string peers;
    std::chrono::steady_clock::time_point deadline{};
    std::chrono::steady_clock::time_point reportedAt{};
    std::size_t receivedBytes{0};
  };

  std::unique_ptr<SSetup> sSetup;
} // namespace

bool moho::REJOIN_BeginSetup(
  const char* const peers,
  const int localSource,
  const unsigned short localPort,
  fa::string* const failureReason
)
{
  const auto refuse = [failureReason](const char* const reason) {
    if (failureReason != nullptr) {
      *failureReason = reason;
    }
    return false;
  };

  if (!REJOIN_LoadKey()) {
    return refuse("This computer holds no key for that seat, so its game can't be rejoined from here.");
  }

  sRejoinStart = std::chrono::steady_clock::now();
  auto setup = std::make_unique<SSetup>();
  setup->localSource = localSource;
  setup->peers = peers;
  const std::string written = peers;
  for (std::size_t begin = 0; begin < written.size();) {
    const std::size_t end = std::min(written.find(',', begin), written.size());
    const std::string entry = written.substr(begin, end - begin);
    const std::size_t equals = entry.find('=');
    if (equals == std::string::npos) {
      return refuse("A peer is not written address:port=source.");
    }
    auto peer = std::make_unique<SSetupPeer>();
    peer->source = std::atoi(entry.c_str() + equals + 1);
    // In native mode the launcher knows players, not the addresses the game gives their links.
    std::string address = entry.substr(0, equals);
    if (!address.empty() && address.find_first_not_of("0123456789") == std::string::npos) {
      address = faf::netlink::EngineAddressText(std::atoll(address.c_str()));
    }
    if (!NET_GetAddrInfo(address.c_str(), 0, false, peer->address, peer->port) || peer->port == 0) {
      return refuse("A peer's address could not be read.");
    }
    setup->list.push_back(std::move(peer));
    begin = end + 1;
  }
  if (setup->list.empty()) {
    return refuse("No peer was given.");
  }

  setup->connector = NET_MakeUDPConnector(localPort, boost::weak_ptr<INetNATTraversalProvider>{});
  if (setup->connector == nullptr) {
    return refuse("The game port could not be opened.");
  }

  // Nothing is known about the game until the first peer has said it.
  for (std::size_t index = 0; index < setup->list.size(); ++index) {
    SSetupPeer& peer = *setup->list[index];
    peer.link = setup->connector->Connect(peer.address, peer.port);
    // A peer of another build sends no save, and keeps to its own 32 packets.
    WidenRejoinLink(peer.link);
    peer.receiver.SetProofTarget(peer.link, localSource, peer.source);
    auto* const dispatcher = static_cast<CMessageDispatcher*>(peer.link);
    dispatcher->PushReceiver(MSGTYPE_SimBase, MSGTYPE_SimEnd, &peer.receiver);
    dispatcher->PushReceiver(MSGTYPE_ClientBase, MSGTYPE_ClientEnd, &peer.receiver);
    dispatcher->PushReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, &peer.receiver);

    CMessage request(EClientMsg::CLIMSG_PeerFeatures);
    CMessageStream stream(request);
    stream.Write(static_cast<std::uint8_t>(EPeerMessageKind::RejoinInfo));
    stream.Write(index == 0 ? kRequestWithRecording : kRequestWithoutRecording);
    const std::string buildId = net_RejoinKeyframes != 0 ? KeyframeBuildId() : std::string{};
    stream.Write(buildId.c_str(), buildId.size() + 1u);
    NetDataSpan span{
      reinterpret_cast<std::uint8_t*>(request.mBuff.start_),
      reinterpret_cast<std::uint8_t*>(request.mBuff.end_),
    };
    peer.link->Write(&span);
  }

  constexpr std::chrono::seconds kWait{90};
  setup->deadline = std::chrono::steady_clock::now() + kWait;
  sSetup = std::move(setup);
  return true;
}

bool moho::REJOIN_SetupPending()
{
  return sSetup != nullptr;
}

float moho::REJOIN_SetupProgress()
{
  return sSetup != nullptr ? sSetup->list.front()->receiver.RecordingProgress() : -1.0f;
}

fa::auto_ptr<SWldSessionInfo> moho::REJOIN_PollSetup(fa::string* const failureReason, bool* const failed)
{
  SSetup& setup = *sSetup;
  INetConnector* const connector = setup.connector;
  const auto& list = setup.list;

  const auto refuse = [&](const char* const reason) {
    if (reason != nullptr && failureReason != nullptr) {
      *failureReason = reason;
    }
    *failed = true;
    connector->Destroy();
    sSetup.reset();
    return fa::auto_ptr<SWldSessionInfo>();
  };

  const auto now = std::chrono::steady_clock::now();
  constexpr std::chrono::seconds kReportInterval{1};
  if (now - setup.reportedAt >= kReportInterval) {
    setup.reportedAt = now;
    CMessage report = MakeStatusMessage(ERejoinStage::Transfer, list.front()->receiver.RecordingProgress());
    for (const auto& peer : list) {
      NetDataSpan span{
        reinterpret_cast<std::uint8_t*>(report.mBuff.start_),
        reinterpret_cast<std::uint8_t*>(report.mBuff.end_),
      };
      peer->link->Write(&span);
    }
  }

  connector->Pull();
  connector->Push();
  bool complete = true;
  for (const auto& peer : list) {
    if (peer->receiver.Refused()) {
      return refuse(
        peer->receiver.Refusal() == ERejoinRefusal::Ejected
          ? "A player voted to eject you, so you cannot take your seat back."
          : "The other players did not accept this computer's key for that seat. If the seat is yours, its key file has changed or gone."
      );
    }
    complete = complete && peer->receiver.Reported();
  }
  if (!complete) {
    // A long game takes as long as it takes to send, as long as it is coming.
    constexpr std::chrono::seconds kWait{90};
    const std::size_t received = list.front()->receiver.ReceivedBytes();
    if (received != setup.receivedBytes) {
      setup.receivedBytes = received;
      setup.deadline = now + kWait;
    }
    // Any peer that lets clients back answers within a round trip once its link is up. A link
    // whose first attempt fails takes up to 15 s of checks and 5 s before the next offer, and
    // a relay one longer (issue #275, two-machine runs fx1 and fx7): room for a second attempt.
    constexpr std::chrono::seconds kSilentPeerWait{60};
    const bool silentPeer = now - sRejoinStart >= kSilentPeerWait && std::any_of(list.begin(), list.end(), [](const auto& peer) {
      return !peer->receiver.Heard();
    });
    if (silentPeer || now >= setup.deadline) {
      return refuse(
        "Not every player answered. The game may be over, a player may have left it, or the players may not allow coming back to a game."
      );
    }
    return fa::auto_ptr<SWldSessionInfo>();
  }

  const std::vector<char>& bytes = list.front()->receiver.Recording();
  gpg::Logf(
    "REJOIN: received the recording from the first peer, %u bytes, %.1f s after starting",
    static_cast<unsigned int>(bytes.size()),
    std::chrono::duration<double>(std::chrono::steady_clock::now() - sRejoinStart).count()
  );
  std::unique_ptr<gpg::Stream> recording;
  fa::auto_ptr<SWldSessionInfo> sessionInfo = VCR_SetupReplaySessionFromStream(
    std::make_unique<gpg::MemBufferStream>(gpg::CopyMemBuffer(bytes.data(), bytes.size())), "the peer's recording",
    failureReason, &recording
  );
  if (sessionInfo.get() == nullptr) {
    return refuse(nullptr);
  }

  // A rejoin loads a save: playing the whole game again could take as long as the game did.
  // Only with net_RejoinKeyframes off does this client replay the recording.
  int skipBeats = 0;
  const std::vector<char>& packed = list.front()->receiver.Keyframe();
  std::uint64_t rawSize = 0;
  if (packed.size() > kPackedHeaderBytes) {
    std::memcpy(&rawSize, packed.data() + 1, sizeof(rawSize));
    std::vector<unsigned char> raw(static_cast<std::size_t>(rawSize));
    boost::shared_ptr<std::FILE> file = OpenScratchFile();
    const char* const body = packed.data() + kPackedHeaderBytes;
    const std::size_t bodySize = packed.size() - kPackedHeaderBytes;
    bool unpacked = false;
    if (static_cast<ERejoinPacking>(packed[0]) == ERejoinPacking::Zstd) {
      unpacked = ZSTD_decompress(raw.data(), raw.size(), body, bodySize) == raw.size();
    } else {
      uLongf unpackedSize = static_cast<uLongf>(raw.size());
      unpacked = uncompress(raw.data(), &unpackedSize, reinterpret_cast<const Bytef*>(body), static_cast<uLong>(bodySize)) == Z_OK;
    }
    if (unpacked && std::fwrite(raw.data(), raw.size(), 1u, file.get()) == 1u && std::fflush(file.get()) == 0 &&
        std::fseek(file.get(), 0, SEEK_SET) == 0 && SIM_ReadKeyframeHeader(file.get(), sRestoreHeader)) {
      sRestoreFile = file;
      skipBeats = static_cast<int>(sRestoreHeader.beat) - 1;
      gpg::Logf("REJOIN: received a save of beat %u, %llu bytes", sRestoreHeader.beat, static_cast<unsigned long long>(rawSize));
    } else {
      gpg::Warnf("REJOIN: the save that came could not be read");
      return refuse("The save of the game could not be read.");
    }
  } else if (net_RejoinKeyframes != 0) {
    gpg::Warnf("REJOIN: no save of the game came from the peer");
    return refuse("No save of the game came from the other player. Their game may be a different build.");
  }

  const int localSource = setup.localSource;
  LaunchInfoBase* const launchInfo = sessionInfo->mLaunchInfo.get();
  const auto& sources = launchInfo->mCommandSources.mSrcs;
  const int sourceCount = static_cast<int>(sources.size());
  bool sourcesFit = localSource >= 0 && localSource < sourceCount;
  for (const auto& peer : list) {
    sourcesFit = sourcesFit && peer->source >= 0 && peer->source < sourceCount && peer->source != localSource;
  }
  if (!sourcesFit) {
    return refuse("A command source given does not fit the recorded game.");
  }

  // As `CLobby::LaunchGame` sets up this client's session.
  for (std::size_t army = 0; army < launchInfo->mArmyLaunchInfo.size(); ++army) {
    if (launchInfo->mArmyLaunchInfo[army].mUnitSources.Contains(static_cast<unsigned int>(localSource))) {
      launchInfo->mCommandSources.mOriginalSource = static_cast<std::int32_t>(army);
      break;
    }
  }
  sessionInfo->mIsBeingRecorded = true;
  sessionInfo->mIsReplay = false;
  sessionInfo->mIsMultiplayer = true;
  sessionInfo->mSourceId = static_cast<std::uint32_t>(localSource);

  CClientManagerImpl* const manager = CLIENT_CreateClientManager(sources.size(), connector, 0, true);
  for (int client = 0; client < sourceCount; ++client) {
    const char* const name = sources[static_cast<std::size_t>(client)].mName.c_str();
    SSetupPeer* peer = nullptr;
    for (const auto& entry : list) {
      if (entry->source == client) {
        peer = entry.get();
      }
    }
    if (client == localSource) {
      manager->CreateLocalClient(name, client, client, static_cast<std::uint32_t>(client));
    } else if (peer != nullptr) {
      auto* const dispatcher = static_cast<CMessageDispatcher*>(peer->link);
      dispatcher->RemoveReceiver(MSGTYPE_SimBase, MSGTYPE_SimEnd, &peer->receiver);
      dispatcher->RemoveReceiver(MSGTYPE_ClientBase, MSGTYPE_ClientEnd, &peer->receiver);
      dispatcher->RemoveReceiver(MSGTYPE_LobbyBase, MSGTYPE_LobbyEnd, &peer->receiver);
      manager->CreateNetClient(name, client, client, static_cast<std::uint32_t>(client), peer->link);
    } else {
      manager->CreateNullClient(name, client, client, static_cast<std::uint32_t>(client));
    }
  }
  manager->mRejoinFeed =
    std::make_unique<CRejoinFeed>(*manager, std::move(recording), 0, true, list.front()->source, skipBeats);
  for (const auto& peer : list) {
    auto& client = *static_cast<CNetClient*>(manager->mClients[static_cast<std::size_t>(peer->source)]);
    for (CMessage& message : peer->receiver.Held()) {
      (void)manager->mRejoinFeed->TakeIncoming(client, message);
    }
  }
  sessionInfo->mClientManager = manager;
  gpg::Logf("REJOIN: taking source %d back from peers %s", localSource, setup.peers.c_str());
  sSetup.reset();
  return sessionInfo;
}
