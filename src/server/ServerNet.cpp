#include "server/ServerNet.h"

#include <chrono>
#include <utility>

#include "remote/ServerClient.h"
#include "remote/net/Datagram.h"

namespace faf::server
{
  namespace
  {
    // How long the thread sleeps with nothing arriving: the time a beat's news and a resend can wait.
    constexpr int kWaitMilliseconds = 5;
    // A stream message: type, 2 bytes of whole size, payload (moho/net/CMessage.h). The intake takes it from here.
    constexpr std::size_t kCommandHeaderBytes = 3;
    // About a minute of a big game's views: past this a player isn't keeping up, and holds memory for nothing.
    constexpr std::uint64_t kMaxUnackedViewBytes = 16u * 1024u * 1024u;

    [[nodiscard]] std::uint64_t NowUs() noexcept
    {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }
  } // namespace

  CServerNet::CServerNet(const SServerNetConfig& config)
    : mConfig(config)
  {}

  CServerNet::~CServerNet()
  {
    Stop();
  }

  void CServerNet::AddSeat(const std::int32_t uid, const char* const name, const std::string& token, remote::CServerClient& seat)
  {
    SSeat& entry = mSeats[uid];
    entry.name = name;
    entry.seat = &seat;
    mIntake.AddSeat(uid, seat);
    mLinks.AddPlayer(uid, remote::net::MakeToken(token));
  }

  bool CServerNet::Start(std::string& error)
  {
    if (!mLinks.Open(mConfig.listen, error)) {
      return false;
    }
    mStartUs = NowUs();
    mThread = std::thread([this] { Run(); });
    return true;
  }

  void CServerNet::Stop()
  {
    mStop.store(true, std::memory_order_relaxed);
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  void CServerNet::Run()
  {
    while (!mStop.load(std::memory_order_relaxed)) {
      mNowUs = NowUs();
      // Time since the start, as a cookie's period counts from 0.
      mLinks.Pump(mNowUs - mStartUs, *this);
      SendViews();
      Tick(mNowUs);
      mLinks.Wait(kWaitMilliseconds);
    }
  }

  void CServerNet::QueueView(const std::int32_t uid, std::vector<std::uint8_t> message)
  {
    const std::scoped_lock lock(mViewLock);
    mViewQueue[uid].push_back(std::move(message));
  }

  void CServerNet::SendViews()
  {
    for (auto& [uid, seat] : mSeats) {
      if (const remote::net::ChannelStats* const stats = mLinks.StatsOf(uid); stats != nullptr) {
        seat.bytesSeen = stats->bytesSent < seat.bytesSeen ? 0u : seat.bytesSeen;
        mBytesSent.fetch_add(stats->bytesSent - seat.bytesSeen, std::memory_order_relaxed);
        seat.bytesSeen = stats->bytesSent;
      }
      // Before the player has a channel the messages wait, as the first of them make the rest readable.
      if (!seat.joinedEver && !seat.gone) {
        continue;
      }
      mViewSending.clear();
      {
        const std::scoped_lock lock(mViewLock);
        const auto queue = mViewQueue.find(uid);
        if (queue != mViewQueue.end()) {
          mViewSending.swap(queue->second);
        }
      }
      if (seat.gone || seat.lost || seat.viewBroken) {
        continue;
      }
      for (const std::vector<std::uint8_t>& message : mViewSending) {
        (void)mLinks.SendReliable(uid, message.data(), message.size());
      }
      if (mLinks.ReliableUnacked(uid) > kMaxUnackedViewBytes) {
        Remove(uid, seat, "can't keep up with the game");
      }
    }
  }

  void CServerNet::Tick(const std::uint64_t nowUs)
  {
    if (const std::int32_t beat = mBeat.load(std::memory_order_relaxed); beat != mBeatSent) {
      mBeatSent = beat;
      std::vector<std::uint8_t> message;
      remote::net::ByteWriter writer(message);
      writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::Beat));
      writer.Varint(static_cast<std::uint64_t>(beat));
      mLinks.SendUnreliableToAll(message.data(), message.size());
    }

    const auto reconnectUs = static_cast<std::uint64_t>(mConfig.reconnectSeconds * 1e6);
    for (auto& [uid, seat] : mSeats) {
      if (!seat.gone && seat.lost && nowUs - seat.lostAtUs >= reconnectUs) {
        Remove(uid, seat, "didn't come back in time");
      }
    }

    for (const std::int32_t uid : mToUnlink) {
      mLinks.RemovePlayer(uid);
    }
    mToUnlink.clear();

    if (!mJoinWaitOver && nowUs - mStartUs >= static_cast<std::uint64_t>(mConfig.joinSeconds * 1e6)) {
      mJoinWaitOver = true;
      bool anyone = false;
      for (auto& [uid, seat] : mSeats) {
        anyone = anyone || seat.joinedEver;
        if (!seat.gone && !seat.joinedEver) {
          Remove(uid, seat, "never joined");
        }
      }
      if (!anyone && !mSeats.empty()) {
        mNobodyCame.store(true, std::memory_order_relaxed);
      }
    }
  }

  void CServerNet::Remove(const std::int32_t uid, SSeat& seat, const std::string& why)
  {
    seat.gone = true;
    seat.lost = false;
    seat.seat->Eject();
    mIntake.Forget(uid);
    mToUnlink.push_back(uid);
    {
      const std::scoped_lock lock(mNewsLock);
      mGone.push_back(uid);
    }
    Say(seat.name + " is out of the game: " + why);
  }

  void CServerNet::Say(std::string line)
  {
    const std::scoped_lock lock(mNewsLock);
    mNews.push_back(std::move(line));
  }

  std::vector<std::int32_t> CServerNet::TakeGone()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mGone, {});
  }

  std::vector<std::string> CServerNet::TakeNews()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mNews, {});
  }

  void CServerNet::OnJoined(const std::int32_t uid, const remote::net::SEndpoint& from, const bool returning)
  {
    const auto found = mSeats.find(uid);
    if (found == mSeats.end()) {
      return;
    }
    SSeat& seat = found->second;
    seat.joinedEver = true;
    seat.lost = false;
    seat.viewBroken = seat.viewBroken || returning;
    Say(seat.name + (returning ? " is back, from " : " joined, from ") + from.Text() + (returning ? "; its view isn't resent yet" : ""));
  }

  void CServerNet::OnLost(const std::int32_t uid)
  {
    const auto found = mSeats.find(uid);
    if (found == mSeats.end() || found->second.gone) {
      return;
    }
    SSeat& seat = found->second;
    seat.lost = true;
    seat.lostAtUs = mNowUs;
    Say(seat.name + " lost the connection: " + std::to_string(static_cast<int>(mConfig.reconnectSeconds)) + " s to come back");
  }

  void CServerNet::OnMessage(const std::int32_t uid, const std::vector<std::uint8_t>& message)
  {
    const auto found = mSeats.find(uid);
    if (found == mSeats.end() || found->second.gone || message.empty()) {
      return;
    }
    SSeat& seat = found->second;

    switch (static_cast<remote::net::ESeatMessage>(message[0])) {
    case remote::net::ESeatMessage::Command: {
      // The whole of a stream message after the kind, with its own size matching.
      if (message.size() < 1u + kCommandHeaderBytes) {
        ++mBadMessages;
        return;
      }
      const std::uint8_t* const body = message.data() + 1;
      const std::size_t bodySize = message.size() - 1u;
      const std::size_t declared = static_cast<std::size_t>(body[1]) | (static_cast<std::size_t>(body[2]) << 8);
      if (declared != bodySize) {
        ++mBadMessages;
        return;
      }
      if (!mIntake.Push(uid, body, bodySize)) {
        Remove(uid, seat, "sends commands faster than a game can");
      }
      return;
    }
    case remote::net::ESeatMessage::Loaded:
      if (!seat.loaded) {
        seat.loaded = true;
        seat.seat->MarkLoaded();
        Say(seat.name + " has loaded the game");
      }
      return;
    case remote::net::ESeatMessage::Leaving:
      Remove(uid, seat, "left");
      return;
    case remote::net::ESeatMessage::Beat:
    case remote::net::ESeatMessage::View:
    case remote::net::ESeatMessage::GameInfo:
    case remote::net::ESeatMessage::CommandAnswer:
      break; // the server's own to send
    }
    ++mBadMessages;
  }
} // namespace faf::server
