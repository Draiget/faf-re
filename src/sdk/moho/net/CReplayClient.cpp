#include "CReplayClient.h"

#include <cstdint>
#include <mutex>
#include <new>

#include "CClientManagerImpl.h"
#include "EClientMsg.h"
#include "ECmdStreamOp.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x004134A0 (FUN_004134A0)
   *
   * What it does:
   * Replaces replay worker thread pointer and destroys the previous thread object.
   */
  void ReplaceReplayThread(boost::thread*& slot, boost::thread* replacement)
  {
    boost::thread* const previous = slot;
    slot = replacement;

    if (previous != nullptr) {
      delete previous;
    }
  }

  void SignalCurrentEventIfManagerIdle(CClientManagerImpl* const manager)
  {
    if (manager == nullptr) {
      return;
    }

    if (manager->mCurrentEvent != nullptr && manager->mMarshaller.mClientManager == nullptr) {
      SetEvent(manager->mCurrentEvent);
    }
  }
} // namespace

/**
 * Address: 0x0053BA50 (FUN_0053BA50)
 */
CReplayClient::CReplayClient(CClientManagerImpl* const manager, BVIntSet& commandSources, gpg::Stream*& replayStream)
  : CClientBase(0, manager, "Replay", -1, commandSources, 0xFFu)
  , mReplayStream(replayStream)
{
  replayStream = nullptr;
}

/**
 * Address: 0x0053BB40 (FUN_0053BB40)
 */
CReplayClient::~CReplayClient()
{
  DestroyNonDeleting();
}

/**
 * Address: 0x0053D240 (FUN_0053D240)
 */
void CReplayClient::DestroyNonDeleting()
{
  if (mReplayThread != nullptr) {
    {
      std::scoped_lock lock(mManager->mLock);
      mReplayThreadStopRequested = true;
      mReplayWorkerCondition.notify_all();
    }

    try {
      mReplayThread->join();
    } catch (...) {
      // Boost 1.34 does not expose joinable(); preserve best-effort shutdown.
    }
  }

  delete mReplayThread;
  mReplayThread = nullptr;

  mReplayMessage.Clear();

  delete mReplayStream;
  mReplayStream = nullptr;
}

/**
 * Address: 0x0053BB20 (FUN_0053BB20)
 */
float CReplayClient::GetStatusMetricA()
{
  return 0.0f;
}

/**
 * Address: 0x0053BB30 (FUN_0053BB30)
 */
float CReplayClient::GetStatusMetricB()
{
  return 0.0f;
}

/**
 * Address: 0x0053D900 (FUN_0053D900)
 */
void CReplayClient::Process(CMessage& msg)
{
  std::scoped_lock lock(mManager->mLock);

  CMessageStream input(msg, CMessageStream::Access::kReadOnly);
  gpg::BinaryReader reader(&input);

  switch (msg.GetType().raw()) {
  case static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance): {
    std::int32_t beatDelta = 0;
    reader.ReadExact(beatDelta);

    CMessage ackMessage(EClientMsg::CLIMSG_Ack);
    CMessageStream ackStream(ackMessage);

    const auto localClientIndex = static_cast<std::uint8_t>(mIndex);
    ackStream.Write(localClientIndex);

    std::int32_t ackBeat = beatDelta;
    if (static_cast<std::size_t>(localClientIndex) < mLatestAckReceived.size()) {
      ackBeat += mLatestAckReceived[localClientIndex];
    }
    ackStream.Write(ackBeat);

    CClientBase::Process(ackMessage);
    Start();
    break;
  }

  case static_cast<std::uint8_t>(EClientMsg::CLIMSG_Dispatched):
    Start();
    break;

  case static_cast<std::uint8_t>(EClientMsg::CLIMSG_Available): {
    CClientBase::Process(msg);

    std::int32_t dispatchedBeat = 0;
    reader.ReadExact(dispatchedBeat);

    CMessage dispatchedMessage(EClientMsg::CLIMSG_Dispatched);
    CMessageStream dispatchedStream(dispatchedMessage);
    dispatchedStream.Write(dispatchedBeat);
    CClientBase::Process(dispatchedMessage);
    break;
  }

  case static_cast<std::uint8_t>(EClientMsg::CLIMSG_Ready):
    CClientBase::Process(msg);
    break;

  default:
    break;
  }

  SignalCurrentEventIfManagerIdle(mManager);
}

/**
 * Address: 0x0053D360 (FUN_0053D360)
 */
void CReplayClient::Start()
{
  if (mReplayPollRequested || mReplayStream == nullptr ||
      static_cast<std::int32_t>(mQueuedBeat - mDispatchedBeat) > 0) {
    return;
  }

  while (mReplayMessage.Read(mReplayStream)) {
    const std::uint8_t replayType = mReplayMessage.GetType().raw();
    if (replayType == 1u) {
      CMessageStream stream(mReplayMessage, CMessageStream::Access::kReadOnly);
      gpg::BinaryReader reader(&stream);

      std::uint8_t sourceId = 0;
      reader.ReadExact(sourceId);
      mCurrentSourceAllowed = mValidCommandSources.Contains(sourceId);
    }

    if (replayType != static_cast<std::uint8_t>(ECmdStreamOp::CMDST_Advance)) {
      if (mCurrentSourceAllowed) {
        CClientBase::Process(mReplayMessage);
      }
    } else {
      CClientBase::Process(mReplayMessage);

      CMessage ackMessage(EClientMsg::CLIMSG_Ack);
      CMessageStream ackStream(ackMessage);
      const auto localClientIndex = static_cast<std::uint8_t>(mIndex);
      ackStream.Write(localClientIndex);
      ackStream.Write(static_cast<std::int32_t>(mQueuedBeat));
      CClientBase::Process(ackMessage);
    }

    mReplayMessage.Clear();

    if (static_cast<std::int32_t>(mQueuedBeat - mDispatchedBeat) > 0) {
      return;
    }
  }

  if (mReplayStream->mReadHead == mReplayStream->mReadEnd && mReplayStream->VirtAtEnd()) {
    delete mReplayStream;
    mReplayStream = nullptr;

    CMessage endGameMessage(ECmdStreamOp::CMDST_EndGame);
    CClientBase::Process(endGameMessage);

    CMessage emptyAdvance(ECmdStreamOp::CMDST_Advance);
    CMessageStream advanceStream(emptyAdvance);
    const std::int32_t beatDelta = 0;
    advanceStream.Write(beatDelta);
    CClientBase::Process(emptyAdvance);

    Eject();
    return;
  }

  if (mReplayThread == nullptr) {
    auto* const worker = new (std::nothrow) boost::thread([this]() {
      ReplayThreadMain(this);
    });
    ReplaceReplayThread(mReplayThread, worker);
  }

  mReplayPollRequested = true;
  mReplayWorkerCondition.notify_all();
}

/**
 * Address: 0x0053D7A0 (FUN_0053D7A0, func_ReplayThread)
 */
void CReplayClient::ReplayThreadMain(CReplayClient* const self)
{
  if (self == nullptr || self->mManager == nullptr) {
    return;
  }

  boost::recursive_mutex::scoped_lock lock(self->mManager->mLock);

  while (!self->mReplayThreadStopRequested) {
    if (self->mReplayPollRequested) {
      gpg::Stream* const stream = self->mReplayStream;
      if (stream == nullptr) {
        self->mReplayPollRequested = false;
        SignalCurrentEventIfManagerIdle(self->mManager);
        continue;
      }

      bool hasReplayData = false;
      if (stream->mReadHead != stream->mReadEnd) {
        const int byteValue = static_cast<signed char>(*stream->mReadHead);
        ++stream->mReadHead;
        gpg::UnGetByteChecked(*stream, byteValue);
        hasReplayData = true;
      } else {
        char byteValue = 0;
        if (stream->ReadNonBlocking(&byteValue, 1u) == 1u) {
          gpg::UnGetByteChecked(*stream, static_cast<signed char>(byteValue));
          hasReplayData = true;
        } else if (stream->mReadHead == stream->mReadEnd && stream->VirtAtEnd()) {
          hasReplayData = true;
        }
      }

      if (hasReplayData) {
        self->mReplayPollRequested = false;
        SignalCurrentEventIfManagerIdle(self->mManager);
      } else {
        lock.unlock();
        ::SleepEx(100u, TRUE);
        lock.lock();
      }
      continue;
    }

    self->mReplayWorkerCondition.wait(lock);
  }
}

/**
 * Address: 0x0053DC00 (FUN_0053DC00)
 */
void CReplayClient::Debug()
{
  gpg::Logf("    CReplayClient 0x%08x:", this);
  CClientBase::Debug();
  gpg::Logf("      mReplayBeat=%d", mReplayBeat);
}
