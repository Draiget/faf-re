#include "CReplayClient.h"

#include <boost/bind.hpp>

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

  /**
   * Address: 0x00540A90 (FUN_00540A90) - callback construction
   *          0x00540AA0 (FUN_00540AA0) - boost::function0<void> converting ctor
   *          0x00540D60 (FUN_00540D60) - bind_t construction from the bound arg
   *          0x00540D70 (FUN_00540D70) - member-pointer capture
   *          0x00540DB0 (FUN_00540DB0) - boost::function0<void>::assign_to
   *
   * What it does:
   * Builds the callable handed to the replay worker thread.
   *
   * The stored functor's exact type is not inferred: the functor manager at
   * 0x005412A0 publishes `stru_F65DC8` as its `type_info`, and the name bytes
   * at 0x00F65DC8 read
   *   ".?AV?$bind_t@XV?$mf0@XVCReplayClient@Moho@@@_mfi@boost@@
   *     V?$list1@V?$value@PAVCReplayClient@Moho@@@_bi@boost@@@_bi@3@@_bi@boost@@"
   * i.e. `boost::_bi::bind_t<void, boost::_mfi::mf0<void, Moho::CReplayClient>,
   * boost::_bi::list1<boost::_bi::value<Moho::CReplayClient*>>>` - a bound
   * *member* pointer, 8 bytes of payload `{ &CReplayClient::ReplayThread, this }`.
   * The invoker at 0x00541290 loads +0x04 into ECX and tail-jumps +0x00, which is
   * why the worker entry is a nullary __thiscall member and not a free function.
   *
   * An earlier reconstruction modelled this as a `void (*)(CReplayClient*)` /
   * self-pointer pair, which has the same size but the wrong call shape.
   */
  [[nodiscard]] boost::function0<void> MakeReplayThreadCallback(CReplayClient* const self)
  {
    return boost::function0<void>(boost::bind(&CReplayClient::ReplayThread, self));
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
    const std::int32_t beatDelta = 1;
    advanceStream.WriteInt32(beatDelta);
    CClientBase::Process(emptyAdvance);

    Eject();
    return;
  }

  if (mReplayThread == nullptr) {
    auto* const worker = new (std::nothrow) boost::thread(MakeReplayThreadCallback(this));
    ReplaceReplayThread(mReplayThread, worker);
  }

  mReplayPollRequested = true;
  mReplayWorkerCondition.notify_all();
}

/**
 * Address: 0x0053D7A0 (FUN_0053D7A0, func_ReplayThread)
 */
void CReplayClient::ReplayThread()
{
  if (mManager == nullptr) {
    return;
  }

  boost::recursive_mutex::scoped_lock lock(mManager->mLock);

  while (!mReplayThreadStopRequested) {
    if (mReplayPollRequested) {
      gpg::Stream* const stream = mReplayStream;
      if (stream == nullptr) {
        mReplayPollRequested = false;
        SignalCurrentEventIfManagerIdle(mManager);
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
        mReplayPollRequested = false;
        SignalCurrentEventIfManagerIdle(mManager);
      } else {
        lock.unlock();
        ::SleepEx(100u, TRUE);
        lock.lock();
      }
      continue;
    }

    mReplayWorkerCondition.wait(lock);
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
