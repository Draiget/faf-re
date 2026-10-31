#include "netlink/Link.h"

#include <juice/juice.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <map>
#include <thread>
#include <random>
#include <shared_mutex>
#include <sstream>

namespace faf::netlink
{
  namespace
  {
    using namespace std::chrono_literals;

    // PeerIceModule / PeerConnectivityCheckerModule constants.
    constexpr auto kGatherTimeout = 5000ms;          // gatheringFuture cancel
    constexpr auto kAwaitCandidatesTimeout = 6000ms; // no answer to our candidates
    constexpr auto kCheckTimeout = 15000ms;          // startIce loop
    constexpr auto kRetryAfterFailure = 5000ms;      // offerer, attempt never connected
    constexpr auto kEchoInterval = 1000ms;           // ECHO_INTERVAL
    constexpr std::int64_t kEchoTimeoutMs = 10000;   // connection lost without echo answer
    constexpr auto kForceInterval = std::chrono::minutes(2); // FORCE_SRFLX_RELAY_INTERVAL
    constexpr std::uint32_t kForceSrflxCount = 1;
    constexpr std::uint32_t kForceRelayCount = 2;

    std::atomic<std::uint64_t> gCandidateIds{0}; // CandidateUtil.candidateIDFactory

    std::int64_t SteadyMs()
    {
      return std::chrono::duration_cast<std::chrono::milliseconds>(Link::Clock::now().time_since_epoch()).count();
    }

    std::int64_t SteadyMicros()
    {
      return std::chrono::duration_cast<std::chrono::microseconds>(Link::Clock::now().time_since_epoch()).count();
    }

    std::string RandomToken(const std::size_t length)
    {
      static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
      thread_local std::mt19937_64 rng{std::random_device{}()};
      std::uniform_int_distribution<int> pick(0, static_cast<int>(sizeof(kAlphabet) - 2));
      std::string s(length, 'a');
      for (char& c : s) {
        c = kAlphabet[pick(rng)];
      }
      return s;
    }

    std::string SdpAttribute(const std::string& sdp, const std::string_view name)
    {
      std::istringstream in(sdp);
      std::string line;
      const std::string prefix = "a=" + std::string(name) + ":";
      while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
          line.pop_back();
        }
        if (line.rfind(prefix, 0) == 0) {
          return line.substr(prefix.size());
        }
      }
      return {};
    }

    std::string Lower(std::string s)
    {
      for (char& ch : s) {
        ch = static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
      }
      return s;
    }
  } // namespace

  struct Link::Internals
  {
    // Written by libjuice's thread, read by Tick. This mutex is never held
    // while calling into libjuice, so a callback (which runs under libjuice's
    // registry lock) can always take it.
    std::mutex cbMutex;
    std::vector<Candidate> candidates;
    bool gatheringDone = false;
    int juiceState = JUICE_STATE_DISCONNECTED;
    bool juiceStateChanged = false;

    // Send (shared) against destroying the agent (exclusive).
    std::shared_mutex agentMutex;

    // Strings the current agent's configuration points into.
    std::vector<std::string> turnHosts, turnUsers, turnPasswords;
    std::vector<juice_turn_server_t> turnServers;
    std::string stunHost;
    std::string bindAddress;

    // libjuice callbacks; user_ptr is the Link.
    static void OnState(juice_agent_t* agent, juice_state_t state, void* user);
    static void OnCandidate(juice_agent_t* agent, const char* sdp, void* user);
    static void OnGatheringDone(juice_agent_t* agent, void* user);
    static void OnRecv(juice_agent_t* agent, const char* data, std::size_t size, void* user);
  };

  namespace
  {
    // Sends the delayed copies of issue #235 for every link: one thread, a
    // queue ordered by due time. Close cancels a link's copies and waits for
    // a send in progress, so no copy outlives its link.
    class DelayedSender
    {
    public:
      using Send = std::function<void(const std::string&)>;

      static DelayedSender& Get()
      {
        static DelayedSender instance;
        return instance;
      }

      void Schedule(const void* owner, const Link::Clock::time_point due, std::string bytes, Send send)
      {
        std::lock_guard lock(mMutex);
        mQueue.emplace(due, Item{owner, std::move(bytes), std::move(send)});
        if (!mThread.joinable()) {
          mThread = std::thread([this] { Loop(); });
        }
        mWake.notify_one();
      }

      void Cancel(const void* owner)
      {
        std::unique_lock lock(mMutex);
        for (auto it = mQueue.begin(); it != mQueue.end();) {
          it = it->second.owner == owner ? mQueue.erase(it) : std::next(it);
        }
        mIdle.wait(lock, [&] { return mBusy != owner; });
      }

      ~DelayedSender()
      {
        {
          std::lock_guard lock(mMutex);
          mStop = true;
          mWake.notify_one();
        }
        if (mThread.joinable()) {
          mThread.join();
        }
      }

    private:
      struct Item
      {
        const void* owner;
        std::string bytes;
        Send send;
      };

      void Loop()
      {
        std::unique_lock lock(mMutex);
        while (!mStop) {
          if (mQueue.empty()) {
            mWake.wait(lock);
            continue;
          }
          const auto due = mQueue.begin()->first;
          if (Link::Clock::now() < due) {
            mWake.wait_until(lock, due);
            continue;
          }
          Item item = std::move(mQueue.begin()->second);
          mQueue.erase(mQueue.begin());
          mBusy = item.owner;
          lock.unlock();
          item.send(item.bytes);
          lock.lock();
          mBusy = nullptr;
          mIdle.notify_all();
        }
      }

      std::mutex mMutex;
      std::condition_variable mWake;
      std::condition_variable mIdle;
      std::multimap<Link::Clock::time_point, Item> mQueue;
      const void* mBusy = nullptr;
      bool mStop = false;
      std::thread mThread;
    };
  } // namespace

  struct Link::Pending
  {
    std::vector<std::function<void()>> actions;
  };

  const char* LinkStateName(const LinkState state)
  {
    switch (state) {
      case LinkState::New: return "new";
      case LinkState::Gathering: return "gathering";
      case LinkState::AwaitingCandidates: return "awaitingCandidates";
      case LinkState::Checking: return "checking";
      case LinkState::Connected: return "connected";
      case LinkState::Disconnected: return "disconnected";
    }
    return "new";
  }

  Link::Link(LinkOptions options, LinkCallbacks callbacks)
    : mOptions(std::move(options)), mCallbacks(std::move(callbacks)), mIn(std::make_unique<Internals>())
  {}

  Link::~Link()
  {
    Close();
  }

  void Link::Run(Pending& p)
  {
    for (auto& action : p.actions) {
      action();
    }
    p.actions.clear();
  }

  void Link::Log(Pending& out, std::string text)
  {
    if (mCallbacks.onLog) {
      out.actions.push_back([this, t = std::move(text)] { mCallbacks.onLog(t); });
    }
  }

  void Link::SetStateLocked(Pending& out, const LinkState state)
  {
    mState = state;
    if (mCallbacks.onState) {
      out.actions.push_back([this, state] { mCallbacks.onState(state); });
    }
  }

  void Link::Start()
  {
    Pending p;
    {
      std::lock_guard lock(mMutex);
      if (mClosed || mState != LinkState::New) {
        return;
      }
      if (mOptions.offerer) {
        InitiateLocked(p, nullptr);
      }
    }
    Run(p);
  }

  void Link::OnSignal(const CandidatesMessage& remote)
  {
    std::lock_guard lock(mMutex);
    if (!mClosed) {
      mInbox.push_back(remote);
    }
  }

  void Link::SetGameEnded()
  {
    std::lock_guard lock(mMutex);
    mGameEnded = true;
  }

  LinkState Link::GetState() const
  {
    std::lock_guard lock(mMutex);
    return mState;
  }

  LinkStats Link::GetStats() const
  {
    std::lock_guard lock(mMutex);
    LinkStats s = mStats;
    s.dataReceived = mDataReceived.load();
    s.invalidReceived = mInvalidReceived.load();
    s.echoesAnswered = mEchoesAnswered.load();
    const std::int64_t rtt = mLastRttMicros.load();
    s.lastRttMs = rtt < 0 ? -1.0 : static_cast<double>(rtt) / 1000.0;
    return s;
  }

  std::uint32_t Link::AttemptsInLastTwoMinutesLocked(const Clock::time_point now) const
  {
    std::uint32_t n = 0;
    for (const Clock::time_point t : mAttemptTimes) {
      if (now - t < kForceInterval) {
        ++n;
      }
    }
    return n;
  }

  // CandidateUtil.isAllowedCandidate with PeerIceModule's flags.
  bool Link::AllowedLocked(const CandidateType type, const Clock::time_point now) const
  {
    const std::uint32_t previous = AttemptsInLastTwoMinutesLocked(now);
    const bool allowHost = previous < kForceSrflxCount && !mOptions.forceRelay;
    const bool allowReflexive = previous < kForceRelayCount && !mOptions.forceRelay;
    switch (type) {
      case CandidateType::Host: return allowHost;
      case CandidateType::ServerReflexive:
      case CandidateType::PeerReflexive: return allowReflexive;
      case CandidateType::Relayed: return true;
      default: return false;
    }
  }

  void Link::DestroyAgentLocked()
  {
    juice_agent* agent = nullptr;
    {
      std::unique_lock agentLock(mIn->agentMutex);
      agent = mAgent;
      mAgent = nullptr;
      mConnected = false;
    }
    if (agent != nullptr) {
      juice_destroy(agent); // joins libjuice's thread; never called from it
    }
  }

  void Link::InitiateLocked(Pending& out, const CandidatesMessage* remote)
  {
    // PeerIceModule.initiateIce: only from NEW or DISCONNECTED.
    if (mClosed || (mState != LinkState::New && mState != LinkState::Disconnected)) {
      return;
    }
    DestroyAgentLocked();
    {
      std::lock_guard cb(mIn->cbMutex);
      mIn->candidates.clear();
      mIn->gatheringDone = false;
      mIn->juiceState = JUICE_STATE_DISCONNECTED;
      mIn->juiceStateChanged = false;
    }

    // ICE servers: libjuice takes one STUN server and a list of TURN servers.
    mIn->turnHosts.clear();
    mIn->turnUsers.clear();
    mIn->turnPasswords.clear();
    mIn->stunHost.clear();
    std::uint16_t stunPort = 0;
    for (const IceServer& s : mOptions.iceServers) {
      if (s.kind == IceServer::Kind::Stun && mIn->stunHost.empty()) {
        mIn->stunHost = s.host;
        stunPort = s.port;
      }
    }
    std::vector<std::uint16_t> turnPorts;
    for (const IceServer& s : mOptions.iceServers) {
      if (s.kind == IceServer::Kind::Turn) {
        mIn->turnHosts.push_back(s.host);
        mIn->turnUsers.push_back(s.username);
        mIn->turnPasswords.push_back(s.credential);
        turnPorts.push_back(s.port);
        if (mIn->stunHost.empty()) { // a TURN server answers binding requests too
          mIn->stunHost = s.host;
          stunPort = s.port;
        }
      }
    }
    mIn->turnServers.clear();
    for (std::size_t i = 0; i < mIn->turnHosts.size(); ++i) {
      juice_turn_server_t t{};
      t.host = mIn->turnHosts[i].c_str();
      t.username = mIn->turnUsers[i].c_str();
      t.password = mIn->turnPasswords[i].c_str();
      t.port = turnPorts[i];
      mIn->turnServers.push_back(t);
    }
    mIn->bindAddress = mOptions.bindAddress;

    juice_config_t config{};
    config.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
    config.stun_server_host = mIn->stunHost.empty() ? nullptr : mIn->stunHost.c_str();
    config.stun_server_port = stunPort;
    config.turn_servers = mIn->turnServers.empty() ? nullptr : mIn->turnServers.data();
    config.turn_servers_count = static_cast<int>(mIn->turnServers.size());
    config.bind_address = mIn->bindAddress.empty() ? nullptr : mIn->bindAddress.c_str();
    config.local_port_range_begin = mOptions.portRangeBegin;
    config.local_port_range_end = mOptions.portRangeEnd;
    config.cb_state_changed = &Internals::OnState;
    config.cb_candidate = &Internals::OnCandidate;
    config.cb_gathering_done = &Internals::OnGatheringDone;
    config.cb_recv = &Internals::OnRecv;
    config.user_ptr = this;

    juice_agent_t* agent = juice_create(&config);
    if (agent == nullptr) {
      Log(out, "juice_create failed");
      SetStateLocked(out, LinkState::Disconnected);
      if (mOptions.offerer) {
        mRestartAt = Clock::now() + kRetryAfterFailure;
      }
      return;
    }
    if (!mOptions.ufragPrefix.empty()) {
      const std::size_t prefix = mOptions.ufragPrefix.size();
      const std::string ufrag = mOptions.ufragPrefix + RandomToken(prefix + 4 < 14 ? 14 - prefix : 4);
      juice_set_local_ice_attributes(agent, ufrag.c_str(), RandomToken(26).c_str());
    }
    {
      std::unique_lock agentLock(mIn->agentMutex);
      mAgent = agent;
    }

    SetStateLocked(out, LinkState::Gathering);
    const Clock::time_point now = Clock::now();
    mOurPeer = false;
    mOurPeerReported = false;
    mProbesSent = 0;
    if (remote != nullptr) {
      mRemoteUfrag = remote->ufrag;
      mRemoteMarked = !mOptions.ufragPrefix.empty() && mRemoteUfrag.rfind(mOptions.ufragPrefix, 0) == 0;
      // Answerer: the remote description goes in before gathering, so
      // libjuice takes the controlled role (the offerer controls, as
      // agent.setControlling(peer.isLocalOffer())).
      const std::string sdp = RemoteDescriptionLocked(*remote, now);
      if (juice_set_remote_description(agent, sdp.c_str()) < 0) {
        Log(out, "remote description rejected: " + sdp);
      }
      juice_set_remote_gathering_done(agent);
    }
    juice_gather_candidates(agent);
    mGatherDeadline = now + kGatherTimeout;
    mAwaitDeadline.reset();
    mCheckDeadline.reset();
    mRestartAt.reset();
    std::ostringstream log;
    log << "initiating ICE as " << (mOptions.offerer ? "offerer" : "answerer")
        << ", attempts in the last 2 minutes: " << AttemptsInLastTwoMinutesLocked(now);
    Log(out, log.str());
  }

  std::string Link::RemoteDescriptionLocked(const CandidatesMessage& remote, const Clock::time_point now) const
  {
    std::string sdp = "a=ice-ufrag:" + remote.ufrag + "\r\na=ice-pwd:" + remote.password + "\r\n";
    std::vector<Candidate> sorted = remote.candidates;
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const Candidate& a, const Candidate& b) { return a.priority > b.priority; });
    for (const Candidate& c : sorted) {
      // CandidateUtil.unpackCandidates: same generation, an address, an
      // allowed type; libjuice relays and connects over UDP only.
      if (c.generation != 0 || c.ip.empty() || c.port <= 0 || !AllowedLocked(c.type, now) ||
          Lower(c.protocol) != "udp") {
        continue;
      }
      sdp += CandidateToSdp(c) + "\r\n";
    }
    return sdp;
  }

  void Link::SendCandidatesLocked(Pending& out, const Clock::time_point now)
  {
    std::vector<Candidate> gathered;
    {
      std::lock_guard cb(mIn->cbMutex);
      gathered = mIn->candidates;
    }
    char sdp[JUICE_MAX_SDP_STRING_LEN] = {};
    juice_get_local_description(mAgent, sdp, sizeof(sdp));

    CandidatesMessage msg;
    msg.srcId = mOptions.localId;
    msg.destId = mOptions.remoteId;
    msg.ufrag = SdpAttribute(sdp, "ice-ufrag");
    msg.password = SdpAttribute(sdp, "ice-pwd");
    for (Candidate& c : gathered) {
      if (!AllowedLocked(c.type, now)) {
        continue;
      }
      c.generation = 0;
      c.id = std::to_string(gCandidateIds.fetch_add(1));
      msg.candidates.push_back(std::move(c));
    }
    // CandidatePacket.compareTo: highest priority first.
    std::stable_sort(msg.candidates.begin(), msg.candidates.end(),
                     [](const Candidate& a, const Candidate& b) { return a.priority > b.priority; });

    SetStateLocked(out, LinkState::AwaitingCandidates);
    std::ostringstream log;
    log << "sending " << msg.candidates.size() << " candidates";
    Log(out, log.str());
    if (mCallbacks.onSignal) {
      out.actions.push_back([this, m = std::move(msg)] { mCallbacks.onSignal(m); });
    }
    mAwaitDeadline = now + kAwaitCandidatesTimeout;
  }

  void Link::ApplyRemoteLocked(Pending& out, const CandidatesMessage& remote, const Clock::time_point now)
  {
    if (!mOptions.offerer) {
      // A new offer while busy: stop and answer it (PeerIceModule:303).
      if (mState != LinkState::New && mState != LinkState::Disconnected) {
        Log(out, "received new candidates/offer, stopping");
        ConnectionLostLocked(out, "new offer", now);
      }
      InitiateLocked(out, &remote);
      // Checking starts in Tick once our own candidates are gathered and sent.
      mPendingAnswer = mAgent != nullptr;
      return;
    }
    if (mState != LinkState::AwaitingCandidates || mAgent == nullptr) {
      Log(out, std::string("received candidates unexpectedly, state ") + LinkStateName(mState));
      return;
    }
    mRemoteUfrag = remote.ufrag;
    mRemoteMarked = !mOptions.ufragPrefix.empty() && mRemoteUfrag.rfind(mOptions.ufragPrefix, 0) == 0;
    const std::string sdp = RemoteDescriptionLocked(remote, now);
    if (juice_set_remote_description(mAgent, sdp.c_str()) < 0) {
      Log(out, "remote description rejected: " + sdp);
    }
    juice_set_remote_gathering_done(mAgent);
    mAwaitDeadline.reset();
    SetStateLocked(out, LinkState::Checking);
    mAttemptTimes.push_front(now);
    ++mStats.attempts;
    mCheckDeadline = now + kCheckTimeout;
  }

  void Link::ConnectionLostLocked(Pending& out, const char* reason, const Clock::time_point now)
  {
    if (mState == LinkState::Disconnected) {
      return;
    }
    const LinkState previous = mState;
    Log(out, std::string("connection lost: ") + reason + " (state " + LinkStateName(previous) + ")");
    const bool wasConnected = mConnected.exchange(false);
    if (wasConnected && mCallbacks.onConnected) {
      out.actions.push_back([this] { mCallbacks.onConnected(false); });
    }
    SetStateLocked(out, LinkState::Disconnected);
    DestroyAgentLocked();
    mGatherDeadline.reset();
    mAwaitDeadline.reset();
    mCheckDeadline.reset();
    mPendingAnswer = false;
    if (mClosed || mGameEnded) {
      return;
    }
    // Only the offerer starts again: at once after a lost connection, else
    // after 5 s.
    if (mOptions.offerer) {
      mRestartAt = previous == LinkState::Connected ? now : now + kRetryAfterFailure;
    }
  }

  void Link::Tick()
  {
    Pending p;
    {
      std::lock_guard lock(mMutex);
      if (mClosed) {
        return;
      }
      const Clock::time_point now = Clock::now();

      while (!mInbox.empty()) {
        CandidatesMessage m = std::move(mInbox.front());
        mInbox.pop_front();
        ApplyRemoteLocked(p, m, now);
      }

      bool gatheringDone = false;
      int juiceState = JUICE_STATE_DISCONNECTED;
      bool juiceStateChanged = false;
      {
        std::lock_guard cb(mIn->cbMutex);
        gatheringDone = mIn->gatheringDone;
        juiceState = mIn->juiceState;
        juiceStateChanged = mIn->juiceStateChanged;
        mIn->juiceStateChanged = false;
      }

      if (mState == LinkState::Gathering && mAgent != nullptr) {
        if (gatheringDone) {
          mGatherDeadline.reset();
          SendCandidatesLocked(p, now);
          if (mPendingAnswer) {
            // Answerer: PeerIceModule.onIceMessageReceived goes on to CHECKING
            // and startIce right after initiateIce sent our candidates.
            mPendingAnswer = false;
            mAwaitDeadline.reset();
            SetStateLocked(p, LinkState::Checking);
            mAttemptTimes.push_front(now);
            ++mStats.attempts;
            mCheckDeadline = now + kCheckTimeout;
          }
        } else if (mGatherDeadline && now >= *mGatherDeadline) {
          ConnectionLostLocked(p, "gathering candidates timed out", now);
        }
      }

      if (mState == LinkState::AwaitingCandidates && mAwaitDeadline && now >= *mAwaitDeadline) {
        ConnectionLostLocked(p, "no answer to our candidates", now);
      }

      if ((juiceStateChanged || mState == LinkState::Checking) && mAgent != nullptr) {
        if (juiceState == JUICE_STATE_FAILED && (mState == LinkState::Checking || mState == LinkState::Connected)) {
          ConnectionLostLocked(p, "ICE failed", now);
        } else if (mState == LinkState::Checking &&
                   (juiceState == JUICE_STATE_CONNECTED || juiceState == JUICE_STATE_COMPLETED)) {
          mCheckDeadline.reset();
          mConnected = true;
          char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN] = {};
          char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN] = {};
          if (juice_get_selected_candidates(mAgent, local, sizeof(local), remote, sizeof(remote)) == 0) {
            Log(p, std::string("connected, selected pair: ") + local + " <-> " + remote);
          }
          if (mCallbacks.onConnected) {
            p.actions.push_back([this] { mCallbacks.onConnected(true); });
          }
          SetStateLocked(p, LinkState::Connected);
          mNextEcho = now;
          mLastEchoReplyMs = SteadyMs();
          mNextProbe = now;
        }
      }

      if (mState == LinkState::Checking && mCheckDeadline && now >= *mCheckDeadline) {
        ConnectionLostLocked(p, "ICE checks timed out", now);
      }

      // PeerConnectivityCheckerModule: the offerer's echo and watchdog.
      if (mState == LinkState::Connected && mOptions.offerer) {
        if (now >= mNextEcho) {
          mNextEcho = now + kEchoInterval;
          char echo[9];
          echo[0] = 'e';
          const std::int64_t t = SteadyMicros();
          std::memcpy(echo + 1, &t, sizeof(t));
          std::shared_lock agentLock(mIn->agentMutex);
          if (mAgent != nullptr && juice_send(mAgent, echo, sizeof(echo)) == 0) {
            ++mStats.echoesSent;
          }
        }
        if (SteadyMs() - mLastEchoReplyMs.load() > kEchoTimeoutMs) {
          ConnectionLostLocked(p, "no echo answer for 10 s", now);
        }
      }

      // Issue #234: probe a marked peer, at most 5 times a second apart.
      if (mState == LinkState::Connected && mRemoteMarked && !mOurPeer.load() && mProbesSent < 5 &&
          now >= mNextProbe) {
        mNextProbe = now + std::chrono::seconds(1);
        ++mProbesSent;
        static constexpr char kProbe[] = "fnetlink-probe 1";
        SendFramed(kProbe, sizeof(kProbe) - 1);
      }
      if (mOurPeer.load() && !mOurPeerReported.exchange(true)) {
        Log(p, "the peer is ours (netlink probe answered)");
        if (mCallbacks.onOurPeer) {
          p.actions.push_back([this] { mCallbacks.onOurPeer(); });
        }
      }

      if (mState == LinkState::Disconnected && mRestartAt && now >= *mRestartAt) {
        mRestartAt.reset();
        InitiateLocked(p, nullptr);
      }
    }
    Run(p);
  }

  bool Link::Send(const void* data, const std::size_t size)
  {
    if (!mConnected.load()) {
      std::lock_guard lock(mMutex);
      ++mStats.dataDropped;
      return false;
    }
    // 'd' + datagram (PeerIceModule.onFaDataReceived).
    char buf[2048];
    if (size + 1 > sizeof(buf)) {
      return false;
    }
    buf[0] = 'd';
    std::memcpy(buf + 1, data, size);
    if (!SendFramed(buf, size + 1)) {
      return false;
    }
    if (mOptions.duplicateGapMs == 0) {
      SendFramed(buf, size + 1);
    } else if (mOptions.duplicateGapMs > 0) {
      DelayedSender::Get().Schedule(this, Clock::now() + std::chrono::milliseconds(mOptions.duplicateGapMs),
                                    std::string(buf, size + 1),
                                    [this](const std::string& b) { SendFramed(b.data(), b.size()); });
    }
    std::lock_guard lock(mMutex);
    ++mStats.dataSent;
    if (mOptions.duplicateGapMs >= 0) {
      ++mStats.duplicatesSent;
    }
    return true;
  }

  bool Link::SendFramed(const char* framed, const std::size_t size)
  {
    std::shared_lock agentLock(mIn->agentMutex);
    return mAgent != nullptr && juice_send(mAgent, framed, size) == 0;
  }

  void Link::Close()
  {
    if (mOptions.duplicateGapMs > 0) {
      DelayedSender::Get().Cancel(this); // before the agent goes
    }
    std::lock_guard lock(mMutex);
    if (mClosed) {
      return;
    }
    mClosed = true;
    mConnected = false;
    DestroyAgentLocked();
  }

  void Link::Internals::OnState(juice_agent_t* /*agent*/, const juice_state_t state, void* user)
  {
    Internals& in = *static_cast<Link*>(user)->mIn;
    std::lock_guard cb(in.cbMutex);
    in.juiceState = state;
    in.juiceStateChanged = true;
  }

  void Link::Internals::OnCandidate(juice_agent_t* /*agent*/, const char* sdp, void* user)
  {
    std::optional<Candidate> c = CandidateFromSdp(sdp);
    if (!c) {
      return;
    }
    Internals& in = *static_cast<Link*>(user)->mIn;
    std::lock_guard cb(in.cbMutex);
    in.candidates.push_back(std::move(*c));
  }

  void Link::Internals::OnGatheringDone(juice_agent_t* /*agent*/, void* user)
  {
    Internals& in = *static_cast<Link*>(user)->mIn;
    std::lock_guard cb(in.cbMutex);
    in.gatheringDone = true;
  }

  void Link::Internals::OnRecv(juice_agent_t* agent, const char* data, const std::size_t size, void* user)
  {
    auto* self = static_cast<Link*>(user);
    if (size == 0) {
      return;
    }
    if (data[0] == 'd') {
      self->mDataReceived.fetch_add(1);
      if (self->mCallbacks.onData) {
        const char* payload = data + 1;
        self->mCallbacks.onData(reinterpret_cast<const std::uint8_t*>(payload), size - 1);
      }
    } else if (data[0] == 'e') {
      if (self->mOptions.offerer) {
        if (size >= 9) {
          std::int64_t sent = 0;
          std::memcpy(&sent, data + 1, sizeof(sent));
          self->mLastRttMicros = SteadyMicros() - sent;
        }
        self->mEchoesAnswered.fetch_add(1);
        self->mLastEchoReplyMs = SteadyMs();
      } else {
        juice_send(agent, data, size); // turn around (PeerIceModule:539)
      }
    } else if (data[0] == 'f' && self->mRemoteMarked) {
      // Issue #234: only peers with our ufrag prefix send or get these.
      const std::string_view body(data + 1, size - 1);
      if (body.rfind("netlink-probe", 0) == 0) {
        static constexpr char kAck[] = "fnetlink-ack 1";
        juice_send(agent, kAck, sizeof(kAck) - 1);
        self->mOurPeer = true;
      } else if (body.rfind("netlink-ack", 0) == 0) {
        self->mOurPeer = true;
      }
    } else {
      self->mInvalidReceived.fetch_add(1);
    }
  }
} // namespace faf::netlink
