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

  /**
   * Address: 0x0053C4B0 (FUN_0053C4B0, func_WriteSetCommandSource)
   *
   * What it does:
   * Emits one `CMDST_SetCommandSource` message only when source ownership
   * changed from the last emitted source lane.
   */
  void WriteSetCommandSourceMessage(
    const std::uint8_t sourceId,
    gpg::PipeStream* const outPipe,
    std::uint8_t* const lastEmittedSource
  )
  {
    if (outPipe == nullptr || lastEmittedSource == nullptr || sourceId == *lastEmittedSource) {
      return;
    }

    CMessage message{ECmdStreamOp::CMDST_SetCommandSource};
    CMessageStream stream(message);
    stream.Write(sourceId);
    outPipe->Write(message.mBuff.start_, message.mBuff.Size());
    *lastEmittedSource = sourceId;
  }

  /**
   * Address: 0x00540A70 (FUN_00540A70)
   *
   * What it does:
   * Reads one 32-bit integer value from a `BinaryReader` lane and returns it
   * by value.
   */
  [[maybe_unused]] int ReadClientMessageInt32Raw(gpg::BinaryReader* const reader)
  {
    int value = 0;
    reader->Read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
  }
} // namespace

/**
 * Address: 0x0053B8D0 (FUN_0053B8D0)
 *
 * What it does:
 * Initializes one eject-request record from requester and beat fields.
 */
SEjectRequest::SEjectRequest(const CClientBase* const requester, const int afterBeat)
  : mRequester(requester)
  , mAfterBeat(afterBeat)
{}

/**
 * Address: 0x0053B930 (FUN_0053B930)
 */
BVIntSet* CClientBase::GetValidCommandSources()
{
  return &mValidCommandSources;
}

/**
 * Address: 0x0053B8E0 (FUN_0053B8E0)
 *
 * What it does:
 * Returns the owning client-manager pointer lane.
 */
CClientManagerImpl* CClientBase::GetManager() const
{
  return mManager;
}

/**
 * Address: 0x0053B900 (FUN_0053B900)
 *
 * What it does:
 * Returns the readiness bit lane for this client.
 */
bool CClientBase::IsReady() const
{
  return mReady;
}

/**
 * Address: 0x0053B920 (FUN_0053B920)
 *
 * What it does:
 * Returns the raw sim-rate lane tracked by this client.
 */
int32_t CClientBase::GetSimRateRaw() const
{
  return mSimRate;
}

/**
 * Address: 0x0053BE50 (FUN_0053BE50, Moho::CClientBase::~CClientBase)
 * Address: 0x0053BE30 (FUN_0053BE30, dtor thunk)
 *
 * What it does:
 * Defaulted source owner for base-client teardown; compiler-emitted member
 * destruction matches the binary non-deleting destructor lane.
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
 * Address: 0x0053B6B0 (FUN_0053B6B0)
 *
 * IDA signature:
 * std::string* __userpurge FormatBottleneckLabel@<eax>(
 *     std::string* out@<eax>, const SClientBottleneckInfo* info);
 *
 * What it does:
 * Formats one bottleneck record into `out`:
 *   "<type> <mVal>[ (<members>)][ <mFloat>ms]".
 * The type token is selected by `mType`; the member set (when non-empty) is
 * comma-joined from `mSubobj`; the trailing millisecond field is appended only
 * when `mType != Nothing`.
 */
msvc8::string& moho::FormatBottleneckLabel(const SClientBottleneckInfo& info, msvc8::string& out)
{
  // Type token (switch on mType, 0..3) -> assignment (0x0053B703..0x0053B71F).
  switch (info.mType) {
    case SClientBottleneckInfo::Nothing:
      out = "nothing";
      break;
    case SClientBottleneckInfo::Readiness:
      out = "readiness";
      break;
    case SClientBottleneckInfo::Data:
      out = "data";
      break;
    case SClientBottleneckInfo::Ack:
      out = "ack";
      break;
  }

  // " %u" of mVal (0x0053B724..0x0053B744). Binary passes the raw dword as
  // unsigned; reproduce that exactly.
  out += gpg::STR_Printf(" %u", static_cast<unsigned int>(info.mVal));

  // Member set, comma-joined inside "( ... )", only when non-empty
  // (0x0053B766..0x0053B853).
  if (info.mSubobj.Count() != 0) {
    out += " (";
    // GetNext walks values strictly greater than the argument; start at
    // 0xFFFFFFFF so the first present value is returned, and stop at Max()
    // (== 32 * (mFirstWordIndex + wordCount)), matching the binary's
    // manually-computed end sentinel.
    const unsigned int end = info.mSubobj.Max();
    unsigned int value = info.mSubobj.GetNext(std::numeric_limits<unsigned int>::max());
    if (value != end) {
      // First member: "%d" (0x0053B791).
      out += gpg::STR_Printf("%d", value);
      value = info.mSubobj.GetNext(value);
      // Subsequent members: ",%d" (0x0053B7EB).
      while (value != end) {
        out += gpg::STR_Printf(",%d", value);
        value = info.mSubobj.GetNext(value);
      }
    }
    out += ")";
  }

  // " %.1fms" of mFloat, only when mType != Nothing (0x0053B85C..0x0053B88B).
  if (info.mType != SClientBottleneckInfo::Nothing) {
    out += gpg::STR_Printf(" %.1fms", info.mFloat);
  }

  return out;
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

    // The binary does NOT route this append through `VirtWrite`. At 0x0053C0A6
    // it uses the inlined `Stream::Write` fast path: raw loads of `mWriteHead`
    // (0x0053C0AB) and `mWriteEnd` (0x0053C0AE), a `memcpy` (0x0053C0BF), and a
    // non-atomic `mWriteHead += n` (0x0053C0C7), falling back to the locking
    // virtual (vtable +0x1C) only when the message does not fit the chunk.
    //
    // An earlier note here claimed that shortcut races the dispatch thread and
    // can walk off a retired 4KB chunk. That race cannot occur: every path into
    // this function already holds `mManager->mLock`, which is also held across
    // the `UpdateState` drain loop in `CClientManagerImpl::UpdateStates`.
    // Verified in the binary, not just in this tree -- `CNetClient::
    // ReceiveMessage` (0x0053DE70) loads `mManager` from `this+0x28`, takes
    // `mManager+0x40C` at 0x0053DEA5, calls this function at 0x0053DEF5, and
    // releases at 0x0053DF04; `CLocalClient::Process` (0x0053D190) and
    // `CReplayClient::Process` (0x0053D900) have the same shape. The mutex is
    // recursive, so the marshaller's re-entrant `ProcessClients` during
    // `Dispatch` is covered too.
    //
    // `VirtWrite` is kept because, under that lock, it is behaviourally
    // identical to the inlined form and the lock makes the difference
    // unobservable. Do not cite the stale race note as evidence of a
    // sim-dispatch/issue-thread data race -- it was not one.
    mPipe.VirtWrite(msg.mBuff.start_, msg.mBuff.Size());
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
 * IDA signature (decompile byte-verified against bin/2025.7.1/
 * ForgedAlliance.exe, sha256
 * 0ad6cd638cb0542cb17668efe3e9cd911994eb60cb98a112cf806590b4ee01e9):
 * void __stdcall sub_53C550(Moho::CClientBase *a1, int arg4,
 *                           Moho::CMarshaller *arg8, gpg::PipeStream *a4);
 *
 * What it does:
 * Pumps queued per-client command-stream data up to `beat`, enforces
 * command-source ownership, and forwards authorized packets to output pipe.
 *
 * Deviations from the binary, each tagged [NOT-IN-BINARY] at its site:
 *
 *  1. `lastEmittedSource` is ours. The binary has no such local -- it forwards
 *     its own third parameter (`arg8`) straight to `sub_53C4B0`, whose
 *     verified decompile is
 *       void __usercall sub_53C4B0(int a1@<ebx>, _DWORD *a2@<edi>, _DWORD *arg0)
 *     reading `*arg0` and writing `*arg0 = a1`. The third parameter is
 *     therefore a caller-owned `uint32_t*` last-emitted-source slot, NOT a
 *     `CMarshaller*` -- IDA mistyped it in the outer signature. Because the
 *     caller owns it, the binary's dedup spans every client in one
 *     `UpdateStates` pass while ours restarts per client per call, so we emit
 *     redundant `CMDST_SetCommandSource` ops the binary suppresses. The sim
 *     treats them identically, but a replay we record is not byte-equal to
 *     one the original engine records. Not corrected: `CClientManagerImpl::
 *     UpdateStates` (0x0053F010) tail-jumps to 0x0128FFE0, outside the export,
 *     so where the binary keeps that slot is unverified and guessing would be
 *     more invention.
 *
 *  2. The `ReadMessage` result is tested here; the binary discards it
 *     (decompile line 131, bare `Moho::CMessage::ReadMessage(&a2,
 *     &a1->mPipe);`, no test at 0x0053C658). Unreachable in practice -- a beat
 *     is only counted once a full `CMDST_Advance` has been queued, so the pipe
 *     always holds a whole beat -- so behaviour is identical and the guard is
 *     kept as a safety net.
 *
 *  3. `mValidCommandSources = BVIntSet{}` replaces the binary's open-coded
 *     reset (decompile lines 115-123: `v0 = 0`, free the heap buffer when it
 *     is not the inline one, repoint start/end_of_storage at the inline
 *     buffer, `finish = start`). Same resulting set; ours additionally zeroes
 *     `mReservedMetaWord`, which the binary leaves untouched.
 *
 *  4. The eject-request minimum uses `a < b`; the binary uses the wrap-safe
 *     `(int)(a - b) < 0` (decompile line 71). Differs only on signed overflow
 *     of the beat counter.
 *
 * Invented here previously and now REMOVED, recorded so it is not re-added: a
 * `hasCommandSource = true;` in the authorized `CMDST_SetCommandSource` branch
 * (the binary's `v30` is set once at decompile line 48 and only ever cleared
 * at line 162), and a `WriteSetCommandSourceMessage` call ahead of the payload
 * append. The first silently repaired a real engine defect and hid it from
 * anyone reading this file; see the block comments at both sites.
 */
void CClientBase::UpdateState(const int beat, CMarshaller* const update, gpg::PipeStream* const outPipe)
{
  static constexpr uint32_t kInvalidCommandSource = 0xFFu;
  // [NOT-IN-BINARY] deviation 1: `update` is really the caller's
  // `uint32_t* lastEmittedSource`, which the binary hands to every
  // `sub_53C4B0` call. We ignore it and use the local below instead.
  (void)update;

  if (mEjected) {
    return;
  }

  // [NOT-IN-BINARY] deviation 1: the binary has no local for this.
  std::uint8_t lastEmittedSource = static_cast<std::uint8_t>(kInvalidCommandSource);
  // Decompile line 48: `v30 = mCommandSource != 255;`. Set here and nowhere
  // else -- see the authorized branch below.
  bool hasCommandSource = mCommandSourceId != kInvalidCommandSource;
  if (hasCommandSource) {
    WriteSetCommandSourceMessage(static_cast<std::uint8_t>(mCommandSourceId), outPipe, &lastEmittedSource);
  }

  CMessage message{};
  mPipe.VirtFlush();

  while (static_cast<int32_t>(mDispatchedBeat - static_cast<uint32_t>(beat)) < 0) {
    if (mEjectPending) {
      int earliestEjectBeat = static_cast<int>(mQueuedBeat);
      for (const SEjectRequest& request : mEjectRequests) {
        // [NOT-IN-BINARY] deviation 4: decompile line 71 is the wrap-safe
        // `if (*p_mAfterBeat - mQueuedBeat < 0)`. Differs only on overflow.
        if (request.mAfterBeat < earliestEjectBeat) {
          earliestEjectBeat = request.mAfterBeat;
        }
      }

      if (static_cast<int32_t>(mDispatchedBeat - static_cast<uint32_t>(earliestEjectBeat)) >= 0) {
        CMessage terminateSourceMessage{ECmdStreamOp::CMDST_CommandSourceTerminated};
        for (unsigned int source = mValidCommandSources.GetNext(std::numeric_limits<unsigned int>::max());
             source < mValidCommandSources.Max();
             source = mValidCommandSources.GetNext(source)) {
          WriteSetCommandSourceMessage(static_cast<std::uint8_t>(source), outPipe, &lastEmittedSource);
          outPipe->Write(terminateSourceMessage.mBuff.start_, terminateSourceMessage.mBuff.Size());
        }

        // [NOT-IN-BINARY] deviation 3: the binary open-codes this reset at
        // decompile lines 115-123 instead of assigning a fresh set.
        mValidCommandSources = BVIntSet{};
        mEjected = true;
        break;
      }
    }

    while (true) {
      // [NOT-IN-BINARY] deviation 2: the binary ignores the result (decompile
      // line 131; no test after the call at 0x0053C658). Kept as a safety net
      // -- unreachable, since a beat is only counted once a whole
      // `CMDST_Advance` has been queued.
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
          // `hasCommandSource` is deliberately NOT restored here, and that is
          // not a recovery slip. The binary's authorized branch
          // (0x0053C705..0x0053C72E) writes `mCommandSourceId` at 0x0053C711,
          // emits the message at 0x0053C714, then jumps straight to the next
          // message. It never touches the flag's stack slot, [esp+0x16]. That
          // slot is written non-zero exactly once, at entry (0x0053C598, from
          // `mCommandSourceId != kInvalidCommandSource`); the only other writes
          // to it anywhere in the function clear it (0x0053C7CC).
          //
          // The consequence is a real engine defect. Once a
          // `CMDST_CommandSourceTerminated` clears the flag and parks
          // `mCommandSourceId` at 0xFF, the `if (hasCommandSource)` gate below
          // silently discards every payload op that follows -- no log line,
          // nothing, unlike the neighbouring "not authorized" case.
          //
          // How MANY beats that costs is not fixed, and this is the part that
          // matters. The outer beat loop drains as far as `beat`: 0x0053C825
          // (`js 0x53c5f6`) jumps back to the loop BODY top, not to the entry,
          // and the flag's only non-zero write is at 0x0053C598, outside the
          // loop. So a call that is several beats behind processes them all
          // under one stale flag, and every beat after the terminate in that
          // batch is dropped. If the terminate lands in the batch's final beat,
          // the call ends with `mCommandSourceId` at 0xFF and the whole of the
          // next call drops too. Only a call that starts with a valid
          // `mCommandSourceId` recovers.
          //
          // Batch depth is dispatch lag, which is a property of the machine and
          // its load. Two clients replaying the same stream therefore need not
          // lose the same commands. That makes this a timing-dependent,
          // per-machine divergence in what the sim is even told about -- not
          // merely in when it is told. It is distinct from beat pacing, where
          // the beat stamp travels with the command and the command still
          // arrives.
          //
          // Live sessions never see it: each player owns a `CClientBase`, so a
          // terminate only poisons the leaver's object, and the leaver issues
          // nothing afterwards. A replay funnels every command source through
          // the single `CReplayClient` that `CClientManagerImpl::
          // CreateReplayClient` installs at `mClients[0]`, so the beat after
          // any player's departure also loses everyone else's commands. That is
          // the long-standing "replay desyncs one tick after someone leaves".
          //
          // Do not "fix" this by restoring the flag. Doing so stops the engine
          // reproducing a playback divergence we are actively measuring against.
          mCommandSourceId = claimedSource;
          WriteSetCommandSourceMessage(claimedSource, outPipe, &lastEmittedSource);
        }

        continue;
      }

      if (hasCommandSource) {
        // No `WriteSetCommandSourceMessage` here: 0x0053C756 falls straight
        // through to the pipe append. The source was already emitted either at
        // entry or by the branch above, so the dedup made the extra call a
        // no-op -- but it is not in the binary.
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
void CClientBase::CollectEjecters(msvc8::vector<const CClientBase*>& out)
{
  std::scoped_lock lock(mManager->mLock);

  out.clear();
  out.reserve(mEjectRequests.size());
  for (const SEjectRequest& request : mEjectRequests) {
    out.push_back(request.mRequester);
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

  mEjectRequests.push_back(SEjectRequest(requester, afterBeat));
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
