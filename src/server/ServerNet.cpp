#include "server/ServerNet.h"

#include <chrono>
#include <iterator>
#include <span>
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
    mLobby.AddParticipant(uid);
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
      if (mLobby.Open() && mCloseLobby.load(std::memory_order_relaxed)) {
        mLobby.Close();
      }
      mLinks.Pump(mNowUs - mStartUs, *this);
      SendLobby();
      SendViews();
      Tick(mNowUs);
      mLinks.Wait(kWaitMilliseconds);
    }
  }

  void CServerNet::QueueView(const std::int32_t uid, std::vector<std::uint8_t> message, const bool fresh)
  {
    const std::scoped_lock lock(mViewLock);
    if (!message.empty()
        && (message[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::GameInfo)
            || message[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::LaunchInfo))) {
      mStartMessages[uid].push_back(message);
    }
    if (!message.empty() && message[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables)) {
      mTableLogs[uid].push_back(message);
    }
    mViewQueue[uid].push_back(SQueuedMessage{std::move(message), fresh});
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
      if (!seat.joinedEver && !seat.gone && mConfig.holdViewsForJoin) {
        continue;
      }
      mViewSending.clear();
      std::vector<std::vector<std::uint8_t>> startMessages;
      std::vector<std::vector<std::uint8_t>> tableLog;
      {
        const std::scoped_lock lock(mViewLock);
        const auto queue = mViewQueue.find(uid);
        if (queue != mViewQueue.end()) {
          mViewSending.swap(queue->second);
        }
        if (seat.viewBroken) {
          if (const auto info = mStartMessages.find(uid); info != mStartMessages.end()) {
            startMessages = info->second;
          }
          if (const auto log = mTableLogs.find(uid); log != mTableLogs.end()) {
            tableLog = log->second; // with the queue's: they were taken together
          }
        }
      }
      if (seat.gone || seat.lost) {
        continue;
      }
      std::size_t first = 0;
      if (seat.viewBroken) {
        // Back from a lost connection: what's encoded against frames it no longer holds goes nowhere, up to a fresh view.
        while (first < mViewSending.size() && !mViewSending[first].fresh) {
          ++first;
        }
        if (first == mViewSending.size()) {
          continue;
        }
        seat.viewBroken = false;
        for (const std::vector<std::uint8_t>& message : startMessages) {
          (void)mLinks.SendReliable(uid, message.data(), message.size());
        }
        // The session tables again from the first record, less those still to go after the fresh view in the queue.
        std::size_t queuedTables = 0;
        for (std::size_t i = first; i < mViewSending.size(); ++i) {
          const std::vector<std::uint8_t>& bytes = mViewSending[i].bytes;
          queuedTables += !bytes.empty() && bytes[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables) ? 1u : 0u;
        }
        const std::uint8_t reset[] = {static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables), 0u, 1u};
        (void)mLinks.SendReliable(uid, reset, sizeof(reset));
        for (std::size_t i = 0; i + queuedTables < tableLog.size(); ++i) {
          (void)mLinks.SendReliable(uid, tableLog[i].data(), tableLog[i].size());
        }
        Say(seat.name + " has their view again, from beat " + std::to_string(mBeat.load(std::memory_order_relaxed)));
      }
      for (std::size_t i = first; i < mViewSending.size(); ++i) {
        (void)mLinks.SendReliable(uid, mViewSending[i].bytes.data(), mViewSending[i].bytes.size());
      }
      if (mLinks.ReliableUnacked(uid) > kMaxUnackedViewBytes) {
        Remove(uid, seat, "can't keep up with the game");
      }
    }
  }

  std::vector<CServerNet::SLobbyMessage> CServerNet::TakeLobbyMessages()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mLobbyIn, {});
  }

  std::vector<std::int32_t> CServerNet::TakeLobbyLeft()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mLobbyLeft, {});
  }

  std::vector<std::int32_t> CServerNet::TakeLobbyJoined()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mLobbyJoined, {});
  }

  void CServerNet::QueueLobbyFromServer(const std::int32_t uid, const std::vector<std::uint8_t>& message)
  {
    const std::scoped_lock lock(mViewLock);
    mLobbyOut.push_back(SLobbyMessage{uid, CLobbyRelay::FrameFromServer(message)});
  }

  void CServerNet::SendLobby()
  {
    std::vector<SLobbyMessage> sending;
    {
      const std::scoped_lock lock(mViewLock);
      sending.swap(mLobbyOut);
    }
    std::vector<SLobbyMessage> waiting;
    for (SLobbyMessage& frame : sending) {
      const auto found = mSeats.find(frame.from);
      if (found == mSeats.end() || found->second.gone) {
        continue;
      }
      // Before the participant's first join there's no channel: the frame waits, in order with the rest.
      if (!found->second.joinedEver || !waiting.empty()) {
        waiting.push_back(std::move(frame));
        continue;
      }
      (void)mLinks.SendReliable(frame.from, frame.message.data(), frame.message.size());
    }
    if (!waiting.empty()) {
      const std::scoped_lock lock(mViewLock);
      mLobbyOut.insert(mLobbyOut.begin(), std::make_move_iterator(waiting.begin()), std::make_move_iterator(waiting.end()));
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
    mLobby.RemoveParticipant(uid);
    seat.seat->Eject();
    mIntake.Forget(uid);
    mToUnlink.push_back(uid);
    {
      const std::scoped_lock lock(mNewsLock);
      mGone.push_back(uid);
      mLobbyLeft.push_back(uid);
      mPresence.push_back(SPresence{uid, false});
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

  std::string CServerNet::LinkReport() const
  {
    const remote::net::SGameLinkStats& stats = mLinks.Stats();
    return "network: " + std::to_string(stats.datagramsIn) + " datagrams in; dropped: " + std::to_string(stats.strangersDropped) + " not a player's, " +
           std::to_string(stats.unlistedDropped) + " from unlisted addresses past their budget, " + std::to_string(stats.addressLimited) +
           " handshakes past their address's limit, " + std::to_string(stats.handshakesLimited) + " past the server's, " + std::to_string(stats.badCookies) +
           " with a bad cookie; " + std::to_string(stats.refused) + " refused; " + std::to_string(mViewMismatches) +
           " views reported damaged; lobby: " + std::to_string(mLobby.Count(ELobbyRelayVerdict::Forward)) + " relayed (" +
           std::to_string(mLobbyUndelivered) + " to no channel), " + std::to_string(mLobby.Count(ELobbyRelayVerdict::ToServer)) +
           " for the server, dropped " + std::to_string(mLobby.Count(ELobbyRelayVerdict::TooFast)) + " too fast, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::TooLarge)) + " too large, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::Closed)) + " after launch, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::UnknownSender) + mLobby.Count(ELobbyRelayVerdict::UnknownTarget) +
                          mLobby.Count(ELobbyRelayVerdict::Malformed)) +
           " malformed or misaddressed";
  }

  std::vector<std::int32_t> CServerNet::TakeReturned()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mReturned, {});
  }

  std::vector<CServerNet::SPresence> CServerNet::TakePresence()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mPresence, {});
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
    if (!std::exchange(seat.joinedEver, true) && mLobby.Open()) {
      const std::scoped_lock lock(mNewsLock);
      mLobbyJoined.push_back(uid);
    }
    const bool wasLost = std::exchange(seat.lost, false);
    if (returning) {
      seat.viewBroken = true;
      const std::scoped_lock lock(mNewsLock);
      mReturned.push_back(uid);
      if (wasLost) {
        mPresence.push_back(SPresence{uid, false});
      }
    }
    Say(seat.name + (returning ? " is back, from " : " joined, from ") + from.Text() + (returning ? "; their view comes whole with the next beat" : ""));
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
    {
      const std::scoped_lock lock(mNewsLock);
      mPresence.push_back(SPresence{uid, true});
    }
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
    case remote::net::ESeatMessage::ViewMismatch:
      // Plan WPR.30: the next view goes whole. At most one in `kResyncSeconds`, as each costs a whole frame.
      ++mViewMismatches;
      if (seat.viewBroken || (seat.lastResyncUs != 0u && mNowUs - seat.lastResyncUs < static_cast<std::uint64_t>(kResyncSeconds * 1e6))) {
        return;
      }
      seat.lastResyncUs = mNowUs;
      seat.viewBroken = true;
      {
        const std::scoped_lock lock(mNewsLock);
        mReturned.push_back(uid);
      }
      Say(seat.name + "'s view didn't match the server's check; it gets it whole with the next beat");
      return;
    case remote::net::ESeatMessage::Lobby: {
      // Plan WP2.13: to another participant with the sender written here, or to the server itself (uid 0).
      std::int32_t to = 0;
      std::span<const std::uint8_t> lobbyMessage;
      const ELobbyRelayVerdict verdict =
        mLobby.Take(uid, std::span<const std::uint8_t>(message).subspan(1), mNowUs, to, mLobbyFrame, lobbyMessage);
      if (verdict == ELobbyRelayVerdict::Forward) {
        if (!mLinks.SendReliable(to, mLobbyFrame.data(), mLobbyFrame.size())) {
          ++mLobbyUndelivered;
        }
      } else if (verdict == ELobbyRelayVerdict::ToServer) {
        const std::scoped_lock lock(mNewsLock);
        mLobbyIn.push_back(SLobbyMessage{uid, std::vector<std::uint8_t>(lobbyMessage.begin(), lobbyMessage.end())});
      }
      return; // the relay counts what it drops
    }
    case remote::net::ESeatMessage::Beat:
    case remote::net::ESeatMessage::View:
    case remote::net::ESeatMessage::GameInfo:
    case remote::net::ESeatMessage::LaunchInfo:
    case remote::net::ESeatMessage::LuaSync:
    case remote::net::ESeatMessage::SessionTables:
    case remote::net::ESeatMessage::CommandAnswer:
    case remote::net::ESeatMessage::ViewCheck:
      break; // the server's own to send
    }
    ++mBadMessages;
  }
} // namespace faf::server
