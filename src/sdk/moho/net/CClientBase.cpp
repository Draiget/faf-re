#include "CClientBase.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>

#include "CClientManagerImpl.h"
#include "CMessage.h"
#include "EClientMsg.h"
#include "ECmdStreamOp.h"
#include "ELobbyMsg.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Logging.h"
#include "IClientMgrUIInterface.h"
using namespace moho;

namespace
{
  constexpr std::size_t kMessageHeaderSize = 3;
} // namespace

/**
 * Address: 0x0053B930 (FUN_0053B930)
 */
BVIntSet* CClientBase::GetValidCommandSources()
{
  return &mValidCommandSources;
}

/**
 * Address: 0x0053BE30 (FUN_0053BE30)
 */
CClientBase::~CClientBase() = default;

/**
 * Address: 0x0053B910 (FUN_0053B910)
 */
void CClientBase::Open() {}

/**
 * Address: 0x0053CDF0 (FUN_0053CDF0)
 */
void CClientBase::Debug()
{
  gpg::Logf("      mNickname=\"%s\"", mNickname.c_str());
  gpg::Logf("      mIndex=%d", mIndex);

  msvc8::string validSources;
  for (auto value = mValidCommandSources.GetNext(std::numeric_limits<unsigned>::max());
       value < mValidCommandSources.Max();
       value = mValidCommandSources.GetNext(value)) {
    if (!validSources.empty()) {
      validSources = validSources + ",";
    }
    validSources += gpg::STR_Printf("%d", value);
  }
  gpg::Logf("      mValidCommandSources={%s}", validSources.c_str());

  gpg::Logf("      mCommandSource=%d", mCommandSourceId);
  gpg::Logf("      mReady=%s", mReady ? "true" : "false");
  gpg::Logf("      mPipe.GetLength()=%d", static_cast<int>(mPipe.GetLength()));
  gpg::Logf("      mQueuedBeat=%d", mQueuedBeat);
  gpg::Logf("      mDispatchedBeat=%d", mDispatchedBeat);
  gpg::Logf("      mAvailableBeatRemote=%d", mAvailableBeatRemote);

  msvc8::string ackList;
  for (size_t i = 0; i < mLatestAckReceived.size(); ++i) {
    if (!ackList.empty()) {
      ackList = ackList + ",";
    }
    ackList += gpg::STR_Printf("%d", mLatestAckReceived[i]);
  }
  gpg::Logf("      mLatestAckReceived=[%s]", ackList.c_str());
  gpg::Logf("      mLatestBeatDispatchedRemote=%d", mLatestBeatDispatchedRemote);
  gpg::Logf("      mEjectPending=%s", mEjectPending ? "true" : "false");
  gpg::Logf("      mEjected=%s", mEjected ? "true" : "false");
  gpg::Logf("      mEjectRequests.size()=%d", static_cast<int>(mEjectRequests.size()));

  for (size_t i = 0; i < mEjectRequests.size(); ++i) {
    const auto& req = mEjectRequests[i];
    const int requesterIdx = req.mRequester ? req.mRequester->mIndex : -1;
    const char* requesterName = req.mRequester ? req.mRequester->mNickname.c_str() : "<null>";

    gpg::Logf("      mEjectRequests[%d]:", static_cast<int>(i));
    gpg::Logf("        mRequester=%d [\"%s\"]", requesterIdx, requesterName);
    gpg::Logf("        mAfterBeat=%d", req.mAfterBeat);
  }
}

/**
 * Address: 0x0053BF30 (FUN_0053BF30)
 * Address: 0x101297E0 (sub_101297E0)
 *
 * What it does:
 * Out-of-line body for pure-virtual slot 7 (`Process`) in `CClientBase`;
 * Handles client-control/lifecycle message ids (`50..57`, `202`, `203`),
 * updates ACK/beat/eject state, and appends non-client traffic into `mPipe`.
 */
void CClientBase::Process(CMessage& msg)
{
  CMessageStream stream(msg, CMessageStream::Access::kReadOnly);
  gpg::BinaryReader reader(&stream);

  const uint8_t msgType = msg.GetType().raw();
  if (msgType < static_cast<uint8_t>(EClientMsg::CLIMSG_Ack)) {
    if (msgType == static_cast<uint8_t>(ECmdStreamOp::CMDST_Advance)) {
      int32_t beatDelta = 0;
      reader.ReadExact(beatDelta);
      mQueuedBeat += static_cast<uint32_t>(beatDelta);

      CMessage ackMessage(EClientMsg::CLIMSG_Ack);
      CMessageStream ackStream(ackMessage, CMessageStream::Access::kReadWrite);
      const auto senderIndex = static_cast<uint8_t>(mIndex);
      ackStream.Write(senderIndex);
      ackStream.Write(mQueuedBeat);
      mManager->ProcessClients(ackMessage);
    }

    const size_t wireBytes = msg.mBuff.Size();
    if (wireBytes > static_cast<size_t>(mPipe.mWriteEnd - mPipe.mWriteHead)) {
      mPipe.VirtWrite(msg.mBuff.start_, wireBytes);
    } else {
      std::memcpy(mPipe.mWriteHead, msg.mBuff.start_, wireBytes);
      mPipe.mWriteHead += wireBytes;
    }
    return;
  }

  switch (msgType) {
  case static_cast<uint8_t>(EClientMsg::CLIMSG_Ack): {
    const auto ackClientIndex = reader.ReadExact<uint8_t>();
    int32_t ackBeat = 0;
    reader.ReadExact(ackBeat);

    if (ackClientIndex < mLatestAckReceived.size()) {
      const int32_t previousAck = mLatestAckReceived[ackClientIndex];
      if (ackBeat > previousAck) {
        mLatestAckReceived[ackClientIndex] = ackBeat;
      } else {
        gpg::Logf(
          "CClientBase::Process(): ignoring out of sequence ACK from client %d for %d (beat=%d, prevack=%d)",
          mIndex,
          static_cast<int>(ackClientIndex),
          ackBeat,
          previousAck
        );
      }
    } else {
      gpg::Logf(
        "CClientBase::Process(): ignoring ACK from client %d for invalid client %d.",
        mIndex,
        static_cast<int>(ackClientIndex)
      );
    }
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_Dispatched): {
    int32_t remoteDispatchedBeat = 0;
    reader.ReadExact(remoteDispatchedBeat);

    const int32_t previousBeat = mLatestBeatDispatchedRemote;
    if (remoteDispatchedBeat >= previousBeat) {
      mLatestBeatDispatchedRemote = remoteDispatchedBeat;
    } else {
      gpg::Logf(
        "CClientBase::Process(): ignoring out of sequence DISPATCHED message from client %d (beat=%d, prev=%d)",
        mIndex,
        remoteDispatchedBeat,
        previousBeat
      );
    }
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_Available): {
    int32_t remoteAvailableBeat = 0;
    reader.ReadExact(remoteAvailableBeat);

    const int32_t previousBeat = static_cast<int32_t>(mAvailableBeatRemote);
    if (remoteAvailableBeat >= previousBeat) {
      mAvailableBeatRemote = static_cast<uint32_t>(remoteAvailableBeat);
    } else {
      gpg::Logf(
        "CClientBase::Process(): ignoring out of sequence AVAILABLE message from client %d (beat=%d, prev=%d)",
        mIndex,
        remoteAvailableBeat,
        previousBeat
      );
    }
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_Ready):
    mReady = true;
    return;

  case static_cast<uint8_t>(EClientMsg::CLIMSG_Eject): {
    const auto requesterClientIndex = reader.ReadExact<uint8_t>();
    int32_t afterBeat = 0;
    reader.ReadExact(afterBeat);
    HandleIncomingEjectRequest(requesterClientIndex, afterBeat);
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_ReceiveChat): {
    const auto payloadBytes = static_cast<size_t>(msg.GetMessageSize());
    const auto payload = gpg::CopyMemBuffer(msg.mBuff.start_ + kMessageHeaderSize, payloadBytes);
    mManager->mInterface->ReceiveChat(this, payload);
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_AdjustSimSpeed): {
    int32_t gameSpeedClock = 0;
    int32_t requestedSimRate = 0;
    reader.ReadExact(gameSpeedClock);
    reader.ReadExact(requestedSimRate);

    if (mManager->mAdjustableGameSpeed) {
      ApplyIncomingGameSpeedRequest(gameSpeedClock, requestedSimRate);
    }
    return;
  }

  case static_cast<uint8_t>(EClientMsg::CLIMSG_IntParam):
    reader.ReadExact(mSimRate);
    return;

  case static_cast<uint8_t>(ELobbyMsg::LOBMSG_ConnLostErrored):
  case static_cast<uint8_t>(ELobbyMsg::LOBMSG_ConnLostEof):
    Eject();
    mManager->mInterface->NoteDisconnect(this);
    return;

  default:
    gpg::Logf("CClientBase::Queue(): Ignoring message type %d", static_cast<int>(msgType));
    return;
  }
}

/**
 * Address: 0x0053F440 (FUN_0053F440)
 * Address: 0x1012C6E0 (sub_1012C6E0)
 *
 * What it does:
 * Resolves requester index to a client pointer, records the eject request,
 * and notifies UI for non-local targets.
 */
void CClientBase::HandleIncomingEjectRequest(const uint8_t requesterClientIndex, const int32_t afterBeat)
{
  if (requesterClientIndex < mManager->mClients.size()) {
    const auto* requester = mManager->mClients[requesterClientIndex];
    AddOrUpdateEjectRequest(requester, afterBeat);

    if (this != mManager->mLocalClient) {
      mManager->mInterface->NoteEjectRequest(requester, this);
    }
    return;
  }

  gpg::Logf(
    "Ignoring eject request from %s for invalid client index %u",
    mNickname.c_str(),
    static_cast<unsigned int>(requesterClientIndex)
  );
}

/**
 * Address: 0x0053E810 (FUN_0053E810)
 * Address: 0x1012BB50 (sub_1012BB50)
 *
 * What it does:
 * Applies inbound adjustable-speed arbitration. Newer clocks win; ties are
 * broken by lower requester index.
 */
void CClientBase::ApplyIncomingGameSpeedRequest(const int32_t speedClock, const int32_t requestedSimRate)
{
  if ((mManager->mGameSpeedClock < speedClock) ||
      ((mManager->mGameSpeedClock == speedClock) &&
       (static_cast<uint32_t>(mIndex) < static_cast<uint32_t>(mManager->mGameSpeedRequester)))) {
    mManager->mGameSpeedClock = speedClock;
    mManager->mGameSpeedRequester = mIndex;
    mManager->mGameSpeed = requestedSimRate;
    mManager->mInterface->NoteGameSpeedChanged();
  }
}

/**
 * Address: 0x0053C550 (FUN_0053C550, Moho::CClientBase::UpdateState)
 *
 * What it does:
 * Pumps queued per-client command-stream data up to `beat`, enforces
 * command-source ownership, and forwards authorized packets to output pipe.
 */
void CClientBase::UpdateState(const int beat, CMarshaller* const update, gpg::PipeStream* const outPipe)
{
  static constexpr uint32_t kInvalidCommandSource = 0xFFu;

  if (mEjected) {
    return;
  }

  bool hasCommandSource = mCommandSourceId != kInvalidCommandSource;
  if (hasCommandSource) {
    update->SetCommandSource(mCommandSourceId);
  }

  CMessage message{};
  mPipe.VirtFlush();

  while (static_cast<int32_t>(mDispatchedBeat - static_cast<uint32_t>(beat)) < 0) {
    if (mEjectPending) {
      int earliestEjectBeat = static_cast<int>(mQueuedBeat);
      for (const SEjectRequest& request : mEjectRequests) {
        if (request.mAfterBeat < earliestEjectBeat) {
          earliestEjectBeat = request.mAfterBeat;
        }
      }

      if (static_cast<int32_t>(mDispatchedBeat - static_cast<uint32_t>(earliestEjectBeat)) >= 0) {
        CMessage terminateSourceMessage{ECmdStreamOp::CMDST_CommandSourceTerminated};
        for (unsigned int source = mValidCommandSources.GetNext(std::numeric_limits<unsigned int>::max());
             source < mValidCommandSources.Max();
             source = mValidCommandSources.GetNext(source)) {
          update->SetCommandSource(source);
          outPipe->Write(terminateSourceMessage.mBuff.start_, terminateSourceMessage.mBuff.Size());
        }

        mValidCommandSources = BVIntSet{};
        mEjected = true;
        break;
      }
    }

    while (true) {
      if (!message.ReadMessage(&mPipe)) {
        return;
      }

      CMessageStream stream(message, CMessageStream::Access::kReadOnly);
      const ECmdStreamOp op = static_cast<ECmdStreamOp>(message.GetType().raw());

      if (op == ECmdStreamOp::CMDST_Advance) {
        gpg::BinaryReader reader(&stream);
        int32_t beatDelta = 0;
        reader.ReadExact(beatDelta);
        mDispatchedBeat += static_cast<uint32_t>(beatDelta);
        break;
      }

      if (op == ECmdStreamOp::CMDST_SetCommandSource) {
        gpg::BinaryReader reader(&stream);
        uint8_t claimedSource = 0;
        reader.ReadExact(claimedSource);

        if (!mValidCommandSources.Contains(claimedSource)) {
          gpg::Logf(
            "Client %d:%s claiming command source %d, but not authorized for it.",
            mIndex,
            mNickname.c_str(),
            claimedSource
          );
          hasCommandSource = false;
          mCommandSourceId = kInvalidCommandSource;
        } else {
          mCommandSourceId = claimedSource;
          update->SetCommandSource(claimedSource);
          hasCommandSource = true;
        }

        continue;
      }

      if (hasCommandSource) {
        outPipe->Write(message.mBuff.start_, message.mBuff.Size());

        if (op == ECmdStreamOp::CMDST_CommandSourceTerminated) {
          mValidCommandSources.Remove(mCommandSourceId);
          mValidCommandSources.Finalize();
          hasCommandSource = false;
          mCommandSourceId = kInvalidCommandSource;
        }
      }
    }
  }
}

/**
 * Address: 0x0053C960 (FUN_0053C960)
 */
bool CClientBase::NoEjectionPending()
{
  std::scoped_lock lock(mManager->mLock);
  return !mEjectPending;
}

/**
 * Address: 0x0053CA60 (FUN_0053CA60)
 */
const msvc8::vector<int32_t>* CClientBase::GetLatestAcksVector()
{
  std::scoped_lock lock(mManager->mLock);
  return &mLatestAckReceived;
}

/**
 * Address: 0x0053CA90 (FUN_0053CA90)
 */
void CClientBase::GetLatestBeatDispatchedRemote(uint32_t& out)
{
  std::scoped_lock lock(mManager->mLock);
  out = static_cast<uint32_t>(mLatestBeatDispatchedRemote);
}

/**
 * Address: 0x0053CAD0 (FUN_0053CAD0)
 */
void CClientBase::GetAvailableBeatRemote(uint32_t& out)
{
  std::scoped_lock lock(mManager->mLock);
  out = mAvailableBeatRemote;
}

/**
 * Address: 0x0053C9A0 (FUN_0053C9A0)
 */
void CClientBase::ReceiveChat(gpg::MemBuffer<const char> data)
{
  CMessage msg(EClientMsg::CLIMSG_ReceiveChat);
  msg.Append(data, data.Size());
  Process(msg);
}

/**
 * Address: 0x0053CA20 (FUN_0053CA20)
 */
void CClientBase::GetQueuedBeat(uint32_t& out)
{
  std::scoped_lock lock(mManager->mLock);
  out = mQueuedBeat;
}

/**
 * Address: 0x0053CB10 (FUN_0053CB10)
 */
void CClientBase::Eject()
{
  std::scoped_lock lock(mManager->mLock);
  if (mEjectPending) {
    return;
  }

  mEjectPending = true;
  mReady = true;
  Open();
  ProcessEject(mManager, mQueuedBeat);
}

/**
 * Address: 0x0053CC60 (FUN_0053CC60)
 */
void CClientBase::CollectPendingIds(msvc8::vector<int>& out)
{
  std::scoped_lock lock(mManager->mLock);

  out.clear();
  out.reserve(mEjectRequests.size());
  for (const SEjectRequest& request : mEjectRequests) {
    const auto ptr = reinterpret_cast<std::uintptr_t>(request.mRequester);
    out.push_back(static_cast<int>(ptr));
  }
}

/**
 * Address: 0x0053CDC0 (FUN_0053CDC0)
 */
int32_t CClientBase::GetSimRate()
{
  std::scoped_lock lock(mManager->mLock);
  return mSimRate;
}

/**
 * Address: 0x0053BD40 (FUN_0053BD40)
 */
CClientBase::CClientBase(
  int clientIndex,
  CClientManagerImpl* manager,
  const char* name,
  const int32_t ownerId,
  BVIntSet& commandSources,
  uint32_t sourceId
)
  : IClient(name, clientIndex, ownerId)
  , mManager(manager)
  , mUnknown2C(0)
  , mValidCommandSources(commandSources)
  , mCommandSourceId(sourceId)
  , mReady(false)
  , mPipe()
  , mQueuedBeat(0)
  , mDispatchedBeat(0)
  , mAvailableBeatRemote(0)
  , mLatestAckReceived()
  , mLatestBeatDispatchedRemote(0)
  , mEjectPending(false)
  , mEjected(false)
  , mEjectRequests()
  , mSimRate(50)
{
  const size_t clientCount = mManager ? mManager->NumberOfClients() : 0;
  mLatestAckReceived.resize(clientCount, 0);
}

/**
 * Address: 0x0053CBB0 (FUN_0053CBB0)
 */
void CClientBase::AddOrUpdateEjectRequest(const CClientBase* requester, const int afterBeat)
{
  for (SEjectRequest& request : mEjectRequests) {
    if (request.mRequester == requester) {
      if (afterBeat < request.mAfterBeat) {
        request.mAfterBeat = afterBeat;
      }
      return;
    }
  }

  mEjectRequests.push_back(SEjectRequest{requester, afterBeat});
}

/**
 * Address: 0x0053CC20 (FUN_0053CC20)
 */
void CClientBase::GetMostExpiredEjectRequest(int& outBeat) const
{
  outBeat = static_cast<int>(mQueuedBeat);
  for (const SEjectRequest& request : mEjectRequests) {
    if (request.mAfterBeat < outBeat) {
      outBeat = request.mAfterBeat;
    }
  }
}

/**
 * Address: 0x0053CD50 (FUN_0053CD50)
 */
void CClientBase::RemoveEjectRequestsByRequester(const CClientBase* requester)
{
  if (mEjectRequests.empty()) {
    return;
  }

  for (auto it = mEjectRequests.begin(); it != mEjectRequests.end();) {
    if (it->mRequester == requester) {
      it = mEjectRequests.erase(it);
      continue;
    }
    ++it;
  }
}

/**
 * Address: 0x0053C3E0 (FUN_0053C3E0)
 */
bool CClientBase::IsReadyForBeat(const int beat) const
{
  if (mEjected || mEjectPending || mManager == nullptr) {
    return true;
  }

  const size_t ackCount = mLatestAckReceived.size();
  if (ackCount == 0) {
    return true;
  }

  for (size_t idx = 0; idx < ackCount; ++idx) {
    auto* peer = static_cast<CClientBase*>(mManager->GetClient(static_cast<int>(idx)));
    if (peer == nullptr || peer->mEjected) {
      continue;
    }

    bool blocksBeat = !peer->mEjectPending;
    if (peer->mEjectPending) {
      int mostExpiredBeat = beat;
      peer->GetMostExpiredEjectRequest(mostExpiredBeat);
      blocksBeat = beat < mostExpiredBeat;
    }

    if (blocksBeat && mLatestAckReceived[idx] < beat) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x0053F2C0 (FUN_0053F2C0)
 */
void CClientBase::ProcessEject(CClientManagerImpl* manager, const uint32_t beat) const
{
  CMessage msg(EClientMsg::CLIMSG_Eject);
  CMessageStream s(msg, CMessageStream::Access::kReadWrite);
  const auto requesterIndex = static_cast<uint8_t>(mIndex);
  s.Write(requesterIndex);
  s.Write(beat);
  manager->ProcessClients(msg);

  for (CClientBase* client : manager->mClients) {
    if (client != nullptr) {
      client->RemoveEjectRequestsByRequester(this);
    }
  }
}
