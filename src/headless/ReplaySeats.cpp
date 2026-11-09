#include "headless/ReplaySeats.h"

#include <utility>

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ECmdStreamOp.h"

namespace faf::headless
{
  namespace
  {
    constexpr std::uint32_t kNoCommandSource = 0xFFu;
  } // namespace

  CReplaySeatFeed::CReplaySeatFeed(
    const moho::LaunchInfoBase& launchInfo, std::unique_ptr<gpg::Stream> recording, moho::CClientManagerImpl*& manager
  )
  {
    const auto& sources = launchInfo.mCommandSources.mSrcs;
    const std::size_t seatCount = sources.size();
    mOps.resize(seatCount);
    mNext.resize(seatCount, 0u);

    // As `CReplayClient::Start` reads it: a source is named when it changes.
    moho::CMessage message;
    std::size_t current = seatCount;
    while (message.Read(recording.get())) {
      moho::CMessageStream stream(message, moho::CMessageStream::Access::kReadOnly);
      gpg::BinaryReader reader(&stream);
      const std::uint8_t type = message.GetType().raw();
      if (type == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_Advance)) {
        std::int32_t beats = 0;
        reader.ReadExact(beats);
        mLastBeat += beats;
      } else if (type == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_SetCommandSource)) {
        std::uint8_t source = 0xFFu;
        if (message.GetMessageSize() >= 1) {
          reader.ReadExact(source);
        }
        current = source < seatCount ? source : seatCount;
      } else if (current < seatCount) {
        mOps[current].push_back(SOp{mLastBeat, message});
      }
      message.Clear();
    }

    // What a replay's manager is, with the replay's one client split up. Rate and adjustable as
    // `VCR_SetupReplaySession` has them. Sources before the server's client: the order that
    // `UpdateStates` merges them in, and a recording's order within a beat.
    manager = moho::CLIENT_CreateClientManager(seatCount + 1u, nullptr, 0, true);
    for (std::size_t index = 0; index < seatCount; ++index) {
      const auto seatIndex = static_cast<std::int32_t>(index);
      remote::CServerClient& seat = remote::CServerClient::Create(
        *manager, sources[index].mName.c_str(), seatIndex, seatIndex, static_cast<std::uint32_t>(index)
      );
      seat.SetBeatHook([this](remote::CServerClient& beatSeat, const std::int32_t beat) { Deliver(beatSeat, beat); });
      seat.MarkLoaded();
      mSeats.push_back(&seat);
    }
    const auto serverIndex = static_cast<std::int32_t>(seatCount);
    manager->CreateLocalClient("Server", serverIndex, serverIndex, kNoCommandSource);
  }

  void CReplaySeatFeed::Deliver(remote::CServerClient& seat, const std::int32_t beat)
  {
    const auto index = static_cast<std::size_t>(seat.GetIndex());
    std::vector<SOp>& ops = mOps[index];
    std::size_t& next = mNext[index];

    for (; next < ops.size() && ops[next].beat <= beat; ++next) {
      moho::CMessage& message = ops[next].message;
      const auto op = static_cast<moho::ECmdStreamOp>(message.GetType().raw());
      if (seat.mEjectPending) {
        mLostToEject.fetch_add(1u, std::memory_order_relaxed);
      } else if (op == moho::ECmdStreamOp::CMDST_CommandSourceTerminated) {
        seat.Eject();
        mEjected.fetch_add(1u, std::memory_order_relaxed);
      } else if (op == moho::ECmdStreamOp::CMDST_VerifyChecksum) {
        // Players report these in a lockstep game, and the server makes its own. The recording's
        // are what this run is checked against. As `CClientBase::UpdateState` for a replay, the
        // opening stretch's reports aren't compared.
        if (beat > 0) {
          seat.AppendFromServer(message);
          mFromServer.fetch_add(1u, std::memory_order_relaxed);
        }
      } else if (op == moho::ECmdStreamOp::CMDST_EndGame) {
        seat.AppendFromServer(message);
        mEndSent = true;
      } else if (seat.ReceiveCommand(message)) {
        mAccepted.fetch_add(1u, std::memory_order_relaxed);
      } else {
        // A real server's sim wouldn't get this. The recorded game did, and the checksums come from it.
        seat.AppendFromServer(message);
        if (const auto slot = static_cast<std::size_t>(op); slot < mRefused.size()) {
          mRefused[slot].fetch_add(1u, std::memory_order_relaxed);
        }
      }
    }

    // As `CReplayClient::Start` at the end of its stream, from the last seat left, after the others' last commands.
    if (beat < mLastBeat || mEndSent || seat.mEjectPending) {
      return;
    }
    for (std::size_t later = index + 1u; later < mSeats.size(); ++later) {
      if (!mSeats[later]->mEjectPending) {
        return;
      }
    }
    mEndSent = true;
    moho::CMessage endGame(moho::ECmdStreamOp::CMDST_EndGame);
    seat.AppendFromServer(endGame);
  }

  std::string CReplaySeatFeed::Report() const
  {
    std::string report = "seats: " + std::to_string(mSeats.size()) + ", " + std::to_string(mAccepted.load()) + " commands taken, "
                       + std::to_string(mFromServer.load()) + " checksums, " + std::to_string(mEjected.load()) + " ejected, "
                       + std::to_string(mLostToEject.load()) + " lost to an ejection, refused:";
    bool anyRefused = false;
    for (std::size_t op = 0; op < mRefused.size(); ++op) {
      if (const std::uint64_t count = mRefused[op].load(); count != 0u) {
        report += " op " + std::to_string(op) + " x" + std::to_string(count);
        anyRefused = true;
      }
    }
    return report + (anyRefused ? " (delivered anyway, to keep the recorded game)" : " none");
  }
} // namespace faf::headless
