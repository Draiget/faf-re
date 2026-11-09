#include "server/ServerNet.h"
#include "remote/SpeedLimit.h"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <span>
#include <utility>

#include "moho/net/ELobbyMsg.h"
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
    // Plan WPR.50: a participant counted away is heard again once something came this recently (keepalives: 0.25 s).
    constexpr std::uint64_t kHeardAgainUs = 1'000'000u;
    // Plan WP11.4: how often the roster is looked at, and how often ping and quiet time alone send it again.
    constexpr std::uint64_t kRosterCheckUs = 100'000u;
    constexpr std::uint64_t kRosterTimesUs = 1'000'000u;

    [[nodiscard]] std::string Hex(const std::uint64_t value)
    {
      static constexpr char kDigits[] = "0123456789abcdef";
      std::string text(16u, '0');
      for (int i = 15; i >= 0; --i) {
        text[static_cast<std::size_t>(i)] = kDigits[(value >> (4u * static_cast<unsigned>(15 - i))) & 0xFu];
      }
      return text;
    }

    [[nodiscard]] std::uint64_t NowUs() noexcept
    {
      return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    }
  } // namespace

  CServerNet::CServerNet(const SServerNetConfig& config)
    : mConfig(config)
    , mLinks([&config] {
      remote::net::ChannelConfig channel;
      channel.congestionControl = config.congestionControl; // plan WP10.7
      return channel;
    }())
  {
    mLobby.SetControl(config.lobbyControl);
  }

  CServerNet::~CServerNet()
  {
    Stop();
  }

  void CServerNet::AddSeat(const std::int32_t uid, const char* const name, const std::string& token, remote::CServerClient& seat)
  {
    SSeat& entry = mSeats[uid];
    entry.name = name;
    entry.seat = &seat;
    entry.clientIndex = seat.GetIndex();
    const moho::BVIntSet* const sources = seat.GetValidCommandSources();
    for (unsigned int value = sources->GetNext(~0u); value != sources->Max(); value = sources->GetNext(value)) {
      if (entry.sources.size() < remote::wire::SRosterEntry::kMaxSources) {
        entry.sources.push_back(static_cast<std::uint8_t>(value));
      }
    }
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
      mLobby.SetHost(mLobbyHost.load(std::memory_order_relaxed));
      {
        const std::scoped_lock lock(mNewsLock);
        if (mPinsIn) {
          mLobby.PinOptions(std::move(*mPinsIn)); // plan WP17.2: the organiser's options from now on
          mPinsIn.reset();
        }
      }
      if (mLobby.Open() && mCloseLobby.load(std::memory_order_relaxed)) {
        mLobby.Close();
      }
      mLinks.Pump(mNowUs - mStartUs, *this);
      if (!mContentKnown) {
        {
          const std::scoped_lock lock(mNewsLock);
          mContentKnown = mContentSet;
          mContentMode = mContentModeIn;
          mContentExpected = mContentExpectedIn;
        }
        if (mContentKnown) {
          for (auto& [uid, seat] : mSeats) {
            JudgeContent(uid, seat);
            JudgeMods(uid, seat);
          }
        }
      }
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
        if (!startMessages.empty()) {
          seat.startSent = true;
          seat.rosterOwed = true; // its game starts again: the roster with the rest
        }
        // The session tables again from the first record, less those still to go after the fresh view in the queue.
        std::size_t queuedTables = 0;
        for (std::size_t i = first; i < mViewSending.size(); ++i) {
          const std::vector<std::uint8_t>& bytes = mViewSending[i].bytes;
          queuedTables += !bytes.empty() && bytes[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables) ? 1u : 0u;
        }
        seat.viewBytesQueued = 0; // plan WP10.7: a new channel; its acked prefix starts again
        seat.viewEnds.clear();
        const std::uint8_t reset[] = {static_cast<std::uint8_t>(remote::net::ESeatMessage::SessionTables), 0u, 1u};
        (void)mLinks.SendReliable(uid, reset, sizeof(reset));
        for (std::size_t i = 0; i + queuedTables < tableLog.size(); ++i) {
          (void)mLinks.SendReliable(uid, tableLog[i].data(), tableLog[i].size());
        }
        Say(seat.name + " has their view again, from beat " + std::to_string(mBeat.load(std::memory_order_relaxed)));
      }
      for (std::size_t i = first; i < mViewSending.size(); ++i) {
        const std::vector<std::uint8_t>& bytes = mViewSending[i].bytes;
        (void)mLinks.SendReliable(uid, bytes.data(), bytes.size());
        // Plan WP10.7: where this view ends in the stream, to tell how many beats the player's link is behind.
        seat.viewBytesQueued += bytes.size();
        if (!bytes.empty() && bytes[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::View)) {
          remote::net::ByteReader reader(bytes.data() + 1, bytes.size() - 1u);
          const auto beat = static_cast<std::uint32_t>(reader.Varint());
          if (reader.Ok()) {
            seat.viewEnds.push_back(SSeat::SViewEnd{seat.viewBytesQueued, beat, mNowUs});
            seat.lastViewBeat = beat;
          }
        }
        if (!bytes.empty() && bytes[0] == static_cast<std::uint8_t>(remote::net::ESeatMessage::LaunchInfo)) {
          seat.startSent = true;
          seat.rosterOwed = true;
        }
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

  std::vector<CServerNet::SPresence> CServerNet::TakeLobbyPresence()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mLobbyPresence, {});
  }

  void CServerNet::NoteLobbyPresence(const std::int32_t uid, SSeat& seat, const bool away)
  {
    seat.lobbyAway = away;
    {
      const std::scoped_lock lock(mNewsLock);
      mLobbyPresence.push_back(SPresence{uid, away});
    }
    Say(seat.name + (away ? " has gone quiet in the lobby" : " is heard again in the lobby"));
  }

  void CServerNet::WatchLobbyPresence(const std::uint64_t nowUs)
  {
    if (!mLobby.Open() || mConfig.lobbyAwaySeconds <= 0.0) {
      return;
    }
    const auto awayUs = static_cast<std::uint64_t>(mConfig.lobbyAwaySeconds * 1e6);
    for (auto& [uid, seat] : mSeats) {
      if (!seat.joinedEver || seat.gone || seat.lost) {
        continue; // a lost channel counts as away already (`OnLost`)
      }
      const std::uint64_t silentUs = mLinks.SilentUs(uid, nowUs - mStartUs);
      if (!seat.lobbyAway && silentUs >= awayUs) {
        NoteLobbyPresence(uid, seat, true);
      } else if (seat.lobbyAway && silentUs < kHeardAgainUs) {
        NoteLobbyPresence(uid, seat, false);
      }
    }
  }

  void CServerNet::SetContentCheck(const remote::EContentCheck mode, const remote::SContentReport& expected)
  {
    const std::scoped_lock lock(mNewsLock);
    mContentSet = true;
    mContentModeIn = mode;
    mContentExpectedIn = expected;
  }

  void CServerNet::JudgeContent(const std::int32_t uid, SSeat& seat)
  {
    if (!mContentKnown || mContentMode == remote::EContentCheck::Off || seat.gone || seat.contentJudged) {
      return;
    }
    if (!seat.reported && !seat.loaded) {
      return; // nothing to judge yet
    }
    seat.contentJudged = true;
    const remote::EContentVerdict verdict = remote::JudgeContent(mContentExpected, seat.reported ? &seat.report : nullptr);
    seat.contentVerdict = verdict == remote::EContentVerdict::Same ? "same" : (verdict == remote::EContentVerdict::Differs ? "differs" : "missing");
    NoteJudged(uid, seat);
    if (verdict == remote::EContentVerdict::Same) {
      Say(seat.name + "'s game content is the server's");
      return;
    }
    const std::string what = verdict == remote::EContentVerdict::Missing
                             ? std::string("loaded without reporting its game content")
                             : "its game content isn't the server's (blueprints " + Hex(seat.report.blueprints) + ", mods " + Hex(seat.report.mods) +
                                 "; the server's " + Hex(mContentExpected.blueprints) + ", " + Hex(mContentExpected.mods) + ")";
    if (remote::RefusesPlayer(mContentMode, verdict)) {
      Remove(uid, seat, what);
    } else {
      Say(seat.name + ": " + what + "; the match only warns");
    }
  }

  void CServerNet::JudgeMods(const std::int32_t uid, SSeat& seat)
  {
    if (!mConfig.uiModsAllowed || !mContentKnown || mContentMode == remote::EContentCheck::Off || seat.gone || seat.modsJudged) {
      return;
    }
    if (!seat.modsReported && !seat.loaded) {
      return; // nothing to judge yet
    }
    seat.modsJudged = true;
    std::string what;
    const std::vector<std::string> outside = seat.modsReported ? remote::UiModsOutside(seat.mods, *mConfig.uiModsAllowed) : std::vector<std::string>{};
    seat.modsVerdict = !seat.modsReported ? "missing" : (outside.empty() ? "allowed" : "outside");
    NoteJudged(uid, seat);
    if (!seat.modsReported) {
      what = "loaded without reporting its mods";
    } else if (!outside.empty()) {
      what = "runs UI mods the match doesn't allow:";
      for (const std::string& mod : outside) {
        what += " " + mod;
      }
    } else {
      const auto ui = std::count_if(seat.mods.begin(), seat.mods.end(), [](const remote::SModEntry& mod) { return mod.ui; });
      Say(seat.name + "'s UI mods are the match's to allow (" + std::to_string(ui) + ")");
      return;
    }
    if (mContentMode == remote::EContentCheck::Refuse) {
      Remove(uid, seat, what);
    } else {
      Say(seat.name + ": " + what + "; the match only warns");
    }
  }

  void CServerNet::QueueLobbyFromServer(const std::int32_t uid, const std::vector<std::uint8_t>& message)
  {
    const std::scoped_lock lock(mViewLock);
    mLobbyOut.push_back(SLobbyMessage{uid, CLobbyRelay::FrameFromServer(message)});
  }

  void CServerNet::QueueLobbyAs(const std::int32_t uid, const std::int32_t from, const std::vector<std::uint8_t>& message)
  {
    const std::scoped_lock lock(mViewLock);
    mLobbyOut.push_back(SLobbyMessage{uid, CLobbyRelay::FrameFrom(from, message)});
  }

  bool CServerNet::RequestSubstitute(const std::int32_t uid, const std::string& token, std::string name)
  {
    const std::scoped_lock lock(mNewsLock);
    const bool known = std::any_of(mSeatStates.begin(), mSeatStates.end(), [uid](const SSeatState& seat) { return seat.uid == uid && !seat.gone; });
    if (known) {
      mSubstitutes.push_back(SSubstitute{uid, token, std::move(name)});
    }
    return known;
  }

  void CServerNet::RequestPins(SPinnedOptions pinned)
  {
    const std::scoped_lock lock(mNewsLock);
    mPinsIn = std::move(pinned);
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

  std::vector<CServerNet::SSeatState> CServerNet::Seats()
  {
    const std::scoped_lock lock(mNewsLock);
    return mSeatStates;
  }

  bool CServerNet::RequestEject(const std::int32_t uid, std::string reason)
  {
    const std::scoped_lock lock(mNewsLock);
    const bool known = std::any_of(mSeatStates.begin(), mSeatStates.end(), [uid](const SSeatState& seat) { return seat.uid == uid && !seat.gone; });
    if (known) {
      mEjects.emplace_back(uid, std::move(reason));
    }
    return known;
  }

  void CServerNet::RequestAddress(const std::uint32_t ip, const bool allow)
  {
    const std::scoped_lock lock(mNewsLock);
    mAddressChanges.emplace_back(ip, allow);
  }

  void CServerNet::Tick(const std::uint64_t nowUs)
  {
    WatchLobbyPresence(nowUs);

    // Plan WP17.2: the organiser's ejects and allowlist changes, and the seats as the control API reports them.
    std::vector<std::pair<std::int32_t, std::string>> ejects;
    std::vector<std::pair<std::uint32_t, bool>> addresses;
    std::vector<SSubstitute> substitutes;
    {
      const std::scoped_lock lock(mNewsLock);
      ejects.swap(mEjects);
      addresses.swap(mAddressChanges);
      substitutes.swap(mSubstitutes);
    }
    for (SSubstitute& substitute : substitutes) {
      const auto found = mSeats.find(substitute.uid);
      if (found == mSeats.end() || found->second.gone) {
        continue;
      }
      SSeat& seat = found->second;
      // The old channel goes with the old token; the seat waits for its new player as for one who lost the connection.
      mLinks.RemovePlayer(substitute.uid);
      mLinks.AddPlayer(substitute.uid, remote::net::MakeToken(substitute.token));
      const std::string before = seat.name;
      seat.name = std::move(substitute.name);
      seat.lost = true;
      seat.lostAtUs = nowUs;
      seat.substituted = true; // its next join is a return: launch info, game info and a whole view then (OnJoined)
      seat.rosterOwed = true;
      {
        const std::scoped_lock lock(mNewsLock);
        mPresence.push_back(SPresence{substitute.uid, true});
      }
      Say(seat.name + " takes " + before + "'s seat (uid " + std::to_string(substitute.uid) + "): " +
          std::to_string(static_cast<int>(mConfig.reconnectSeconds)) + " s to join");
    }
    for (const auto& [ip, allow] : addresses) {
      if (allow) {
        mLinks.AllowAddress(ip);
      } else {
        mLinks.DisallowAddress(ip);
      }
    }
    for (const auto& [uid, reason] : ejects) {
      if (const auto found = mSeats.find(uid); found != mSeats.end() && !found->second.gone) {
        Remove(uid, found->second, reason);
      }
    }
    std::vector<SSeatState> states;
    states.reserve(mSeats.size());
    for (auto& [uid, seat] : mSeats) {
      SSeatState state;
      state.uid = uid;
      state.name = seat.name;
      state.joined = seat.joinedEver;
      state.loaded = seat.loaded;
      state.lost = seat.lost;
      state.gone = seat.gone;
      state.away = seat.lobbyAway;
      state.content = seat.contentVerdict;
      if (const std::optional<bool> ready = mLobby.ReadyOf(uid); ready) {
        state.ready = *ready ? "yes" : "no";
      }
      state.lobbySlot = mLobby.LobbySlotOf(uid);
      state.speedLimit = seat.gone ? std::nullopt : seat.speedLimit;
      state.cameraUpdates = seat.cameraUpdates;
      // Plan WP10.7: the views the peer has acked whole leave the list; the oldest left is the first it lacks.
      state.backlogBytes = seat.gone ? 0u : mLinks.ReliableUnacked(uid);
      const std::uint64_t acked = seat.viewBytesQueued > state.backlogBytes ? seat.viewBytesQueued - state.backlogBytes : 0u;
      while (!seat.viewEnds.empty() && seat.viewEnds.front().offset <= acked) {
        seat.viewEnds.pop_front();
      }
      state.behindBeats = seat.gone || seat.viewEnds.empty() ? 0u : seat.lastViewBeat - seat.viewEnds.front().beat + 1u;
      state.behindSeconds = seat.gone || seat.viewEnds.empty() || mNowUs < seat.viewEnds.front().queuedUs
                              ? 0.0
                              : static_cast<double>(mNowUs - seat.viewEnds.front().queuedUs) * 1e-6;
      state.load = seat.loaded ? "loaded" : (seat.reported ? "rules" : (mContentKnown && seat.joinedEver ? "loading" : ""));
      state.mods = seat.modsVerdict;
      for (const remote::SModEntry& mod : seat.mods) {
        if (mod.ui) {
          state.uiMods.push_back(mod.uid);
        }
      }
      if (const remote::net::ChannelStats* const stats = mLinks.StatsOf(uid); stats != nullptr && !seat.gone) {
        state.pingMs = static_cast<std::uint32_t>(stats->rttSmoothedUs / 1000u);
      }
      states.push_back(std::move(state));
    }
    {
      const std::vector<std::pair<std::int32_t, bool>> readyChanges = mLobby.TakeReadyChanges();
      const std::scoped_lock lock(mNewsLock);
      mSeatStates.swap(states);
      mReadyNews.insert(mReadyNews.end(), readyChanges.begin(), readyChanges.end());
    }

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

    SendRosters(nowUs);

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

  remote::wire::SRoster CServerNet::BuildRoster(const std::uint64_t nowUs) const
  {
    // The players' seats; the server's own client is no player and isn't listed.
    remote::wire::SRoster roster{};
    for (const auto& [uid, seat] : mSeats) {
      if (seat.clientIndex < 0 || static_cast<std::size_t>(seat.clientIndex) >= remote::wire::SRoster::kMaxEntries) {
        continue;
      }
      remote::wire::SRosterEntry entry{};
      entry.index = static_cast<std::uint8_t>(seat.clientIndex);
      entry.name = seat.name.size() > remote::wire::SRosterEntry::kMaxNameBytes ? seat.name.substr(0, remote::wire::SRosterEntry::kMaxNameBytes) : seat.name;
      entry.ownerId = uid;
      entry.sources = seat.sources;
      // Milliseconds, whole: what changes by less isn't worth a message.
      if (seat.lost) {
        entry.quiet = static_cast<float>((nowUs - seat.lostAtUs) / 1000u);
      } else if (seat.joinedEver && !seat.gone) {
        if (const remote::net::ChannelStats* const stats = mLinks.StatsOf(uid); stats != nullptr) {
          entry.ping = static_cast<float>(stats->rttSmoothedUs / 1000u);
        }
        entry.quiet = static_cast<float>(mLinks.SilentUs(uid, nowUs - mStartUs) / 1000u);
      }
      entry.connected = !seat.gone;
      roster.entries.push_back(std::move(entry));
    }
    std::sort(roster.entries.begin(), roster.entries.end(), [](const auto& a, const auto& b) { return a.index < b.index; });
    return roster;
  }

  void CServerNet::SendRosters(const std::uint64_t nowUs)
  {
    bool owed = false;
    for (const auto& [uid, seat] : mSeats) {
      owed = owed || (seat.rosterOwed && seat.startSent && !seat.gone && !seat.lost);
    }
    if (!owed && nowUs - mRosterCheckedUs < kRosterCheckUs) {
      return;
    }
    mRosterCheckedUs = nowUs;
    remote::wire::SRoster roster = BuildRoster(nowUs);
    const bool changed = !mRosterSentEver || !remote::SameBesidesTimes(roster, mRosterSent);
    const bool timesDue = mRosterSentEver && nowUs - mRosterSentUs >= kRosterTimesUs && !(roster == mRosterSent);
    const bool everyone = changed || timesDue;
    if (!everyone && !owed) {
      return;
    }
    bool anySent = false;
    for (auto& [uid, seat] : mSeats) {
      if (!seat.startSent || seat.gone || seat.lost || (!everyone && !seat.rosterOwed)) {
        continue;
      }
      roster.localIndex = seat.clientIndex;
      const std::vector<std::uint8_t> message = remote::EncodeRosterMessage(roster);
      if (mLinks.SendReliable(uid, message.data(), message.size())) {
        ++mRostersSent;
        seat.rosterOwed = false;
        anySent = true;
      }
    }
    if (everyone && anySent) {
      roster.localIndex = -1;
      mRosterSent = std::move(roster);
      mRosterSentEver = true;
      mRosterSentUs = nowUs;
    }
  }

  void CServerNet::RelayChat(SSeat& from, const std::vector<std::uint8_t>& message)
  {
    int to = 0;
    std::span<const std::uint8_t> payload;
    if (!remote::DecodeChatMessage(message, to, payload)) {
      ++mBadMessages;
      return;
    }
    if (!from.startSent || !from.chatBudget.Take(mNowUs)) {
      ++mChatDropped;
      return;
    }
    for (auto& [uid, seat] : mSeats) {
      if (seat.clientIndex != to) {
        continue;
      }
      if (seat.gone || seat.lost || !seat.startSent) {
        break;
      }
      // The sender as the server knows it: no player names whom a line seems to come from.
      const std::vector<std::uint8_t> relayed = remote::EncodeChatMessage(from.clientIndex, payload);
      if (mLinks.SendReliable(uid, relayed.data(), relayed.size())) {
        ++mChatRelayed;
        return;
      }
      break;
    }
    ++mChatDropped;
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
      mPresence.push_back(SPresence{uid, false, true});
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
           std::to_string(mLobby.Count(ELobbyRelayVerdict::EjectIgnored)) + " ejects of participants, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::Locked)) + " players' changes refused and " +
           std::to_string(mLobby.PlayerOptionsLimited()) + " cut to Ready in an organised lobby, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::EjectForwarded)) + " ejects by a player host relayed, " +
           std::to_string(mLobby.Count(ELobbyRelayVerdict::UnknownSender) + mLobby.Count(ELobbyRelayVerdict::UnknownTarget) +
                          mLobby.Count(ELobbyRelayVerdict::Malformed)) +
           " malformed or misaddressed; " + std::to_string(mLobby.OptionsPinned()) + " relayed with the match's pinned options written back; " +
           std::to_string(mRostersSent) + " rosters sent; chat: " + std::to_string(mChatRelayed) + " relayed, " + std::to_string(mChatDropped) +
           " dropped; focus requests refused " + std::to_string(mFocusRefused) + ", camera updates dropped " + std::to_string(mCamerasDropped);
  }

  std::vector<std::int32_t> CServerNet::TakeReturned()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mReturned, {});
  }

  void CServerNet::NoteJudged(const std::int32_t uid, const SSeat& seat)
  {
    SSeatState state;
    state.uid = uid;
    state.name = seat.name;
    state.content = seat.contentVerdict;
    state.mods = seat.modsVerdict;
    for (const remote::SModEntry& mod : seat.mods) {
      if (mod.ui) {
        state.uiMods.push_back(mod.uid);
      }
    }
    const std::scoped_lock lock(mNewsLock);
    mJudged.push_back(std::move(state));
  }

  std::vector<std::pair<std::int32_t, bool>> CServerNet::TakeReadyChanges()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mReadyNews, {});
  }

  void CServerNet::SetFocusRule(const std::int32_t uid, const int ownArmy)
  {
    const std::scoped_lock lock(mNewsLock);
    mFocusRules[uid].ownArmy = ownArmy;
  }

  void CServerNet::FreeFocus(const std::int32_t uid)
  {
    const std::scoped_lock lock(mNewsLock);
    mFocusRules[uid].free = true;
  }

  std::optional<std::pair<int, std::int32_t>> CServerNet::SlowestSpeedLimit()
  {
    const std::scoped_lock lock(mNewsLock);
    std::optional<std::pair<int, std::int32_t>> slowest;
    for (const SSeatState& seat : mSeatStates) {
      if (seat.speedLimit && (!slowest || *seat.speedLimit < slowest->first)) {
        slowest.emplace(*seat.speedLimit, seat.uid);
      }
    }
    return slowest;
  }

  std::vector<CServerNet::SSeatState> CServerNet::TakeJudged()
  {
    const std::scoped_lock lock(mNewsLock);
    return std::exchange(mJudged, {});
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

  void CServerNet::OnJoined(const std::int32_t uid, const remote::net::SEndpoint& from, const bool linkReturning)
  {
    const auto found = mSeats.find(uid);
    if (found == mSeats.end()) {
      return;
    }
    SSeat& seat = found->second;
    // Plan WP15.4: a substitute's first join is the seat's return (the links see a new player: its record is new).
    const bool returning = linkReturning || std::exchange(seat.substituted, false);
    if (!std::exchange(seat.joinedEver, true) && mLobby.Open()) {
      const std::scoped_lock lock(mNewsLock);
      mLobbyJoined.push_back(uid);
    }
    const bool wasLost = std::exchange(seat.lost, false);
    if (returning && seat.lobbyAway && mLobby.Open()) {
      NoteLobbyPresence(uid, seat, false);
    }
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
    if (mLobby.Open() && !seat.lobbyAway) {
      NoteLobbyPresence(uid, seat, true);
    }
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
        JudgeContent(uid, seat); // plan WP2.6: one with no report counts once the server's content is known
        JudgeMods(uid, seat);
        if (seat.gone) {
          return;
        }
        seat.seat->MarkLoaded();
        Say(seat.name + " has loaded the game");
      }
      return;
    case remote::net::ESeatMessage::ContentReport: {
      remote::SContentReport report;
      if (!remote::DecodeContentReport(message, report)) {
        ++mBadMessages;
        return;
      }
      if (!seat.reported) { // the first counts
        seat.reported = true;
        seat.report = report;
        JudgeContent(uid, seat);
      }
      return;
    }
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
      if (verdict == ELobbyRelayVerdict::Forward || verdict == ELobbyRelayVerdict::EjectForwarded) {
        if (!mLinks.SendReliable(to, mLobbyFrame.data(), mLobbyFrame.size())) {
          ++mLobbyUndelivered;
        }
        // Plan WP17.1: a player-hosted lobby's host rejected a participant (`CLobby::KickPeer`): they're out of the match.
        // (`LOBMSG_DeletePeer` tells the others; it takes nobody out by itself.)
        if (verdict == ELobbyRelayVerdict::EjectForwarded && lobbyMessage[0] == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_Rejected)) {
          if (const auto ejected = mSeats.find(to); ejected != mSeats.end() && !ejected->second.gone) {
            Remove(to, ejected->second, "ejected by the lobby's host, " + seat.name);
          }
        }
      } else if (verdict == ELobbyRelayVerdict::ToServer) {
        const std::scoped_lock lock(mNewsLock);
        mLobbyIn.push_back(SLobbyMessage{uid, std::vector<std::uint8_t>(lobbyMessage.begin(), lobbyMessage.end())});
      }
      return; // the relay counts what it drops
    }
    case remote::net::ESeatMessage::Chat:
      RelayChat(seat, message); // plan WP11.4
      return;
    case remote::net::ESeatMessage::ModReport: {
      std::vector<remote::SModEntry> mods;
      if (!remote::DecodeModReport(message, mods)) {
        ++mBadMessages;
        return;
      }
      if (!seat.modsReported) { // the first counts
        seat.modsReported = true;
        seat.mods = std::move(mods);
        JudgeMods(uid, seat);
      }
      return;
    }
    case remote::net::ESeatMessage::SpeedLimit: {
      // Plan WP10.7: the player's game says how fast it keeps up; the server runs at the slowest playing seat's.
      const std::optional<int> limit = remote::DecodeSpeedLimit(message);
      if (!limit) {
        ++mBadMessages;
        return;
      }
      if (seat.speedLimit != limit) {
        seat.speedLimit = limit;
        Say(seat.name + "'s game keeps up with speed " + (*limit >= 0 ? "+" : "") + std::to_string(*limit));
      }
      return;
    }
    case remote::net::ESeatMessage::FocusArmy: {
      // Plan WP11.1: the UI's `SetFocusArmy`; the server answers with the army it grants.
      const std::optional<int> asked = remote::DecodeFocusArmy(message);
      if (!asked) {
        ++mBadMessages;
        return;
      }
      int granted = -1;
      {
        const std::scoped_lock lock(mNewsLock);
        const auto rule = mFocusRules.find(uid);
        granted = rule == mFocusRules.end() ? -1 : (rule->second.free ? *asked : rule->second.ownArmy);
      }
      if (granted != *asked) {
        ++mFocusRefused;
        Say(seat.name + " asked to focus on army " + std::to_string(*asked) + "; refused, they keep army " + std::to_string(granted));
      }
      QueueView(uid, remote::EncodeFocusArmy(granted));
      return;
    }
    case remote::net::ESeatMessage::Cameras: {
      // Plan WP11.1: what the player's cameras see, kept for camera-ordered work (WP8.2). A game sends four a second
      // (kCameraPeriodMs), but they arrive bunched (frame hitches, datagrams carrying two), so a bucket of tokens
      // refilled at eight a second and holding four takes them all and drops only a sustained flood.
      std::vector<remote::SCameraReport> cameras;
      if (!remote::DecodeCameras(message, cameras)) {
        ++mBadMessages;
        return;
      }
      constexpr double kCameraTokensPerSecond = 8.0;
      constexpr double kCameraBurst = 4.0;
      seat.cameraTokens = seat.camerasAtUs == 0u
                            ? kCameraBurst
                            : std::min(kCameraBurst, seat.cameraTokens + static_cast<double>(mNowUs - seat.camerasAtUs) * 1e-6 * kCameraTokensPerSecond);
      seat.camerasAtUs = mNowUs;
      if (seat.cameraTokens < 1.0) {
        ++mCamerasDropped;
        return;
      }
      seat.cameraTokens -= 1.0;
      seat.cameras = std::move(cameras);
      if (++seat.cameraUpdates == 1u) {
        Say(seat.name + "'s game sends its cameras");
      }
      return;
    }
    case remote::net::ESeatMessage::Roster:
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
