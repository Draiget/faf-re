#include "netlink/Link.h"
#include "netlink/WebRtc.h"
#include "remote/net/Datagram.h"
#include "remote/net/NetChannel.h"

#include <juice/juice.h>

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
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
    // What every link in this process has sent, with the lane's copies and echoes: GetWireTotals.
    std::atomic<std::uint64_t> sWirePackets{0};
    std::atomic<std::uint64_t> sWireBytes{0};

    constexpr auto kGatherTimeout = 5000ms;          // gatheringFuture cancel
    // libjuice tries a silent ICE server for 23.5 s. The offerer waits kAwaitCandidatesTimeout for
    // the answer, relayed both ways by the lobby server, so what was found by now goes out.
    constexpr auto kGatherSendFound = 4000ms;
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

    // Issue #240: whether a marked ufrag offers `tag` after the prefix (and an
    // optional "w+").
    bool OffersAfterPrefix(const std::string& ufrag, const std::string& prefix, const std::string_view tag)
    {
      std::string_view rest(ufrag);
      if (rest.rfind(prefix, 0) != 0) {
        return false;
      }
      rest.remove_prefix(prefix.size());
      if (rest.rfind("w+", 0) == 0) {
        rest.remove_prefix(2);
      }
      return rest.rfind(tag, 0) == 0;
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

    // Issue #322: the word after " typ " in an SDP candidate line, empty when there is none.
    std::string CandidateTypeOf(const std::string_view line)
    {
      const std::size_t at = line.find(" typ ");
      if (at == std::string_view::npos) {
        return {};
      }
      std::string_view rest = line.substr(at + 5);
      return std::string(rest.substr(0, rest.find(' ')));
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

    // Tests only (issue #242): when FAF_NETLINK_TEST_SHAPING names a file, every
    // link delays, drops or holds back what it sends as the file's one line
    // says: "<latency us> <jitter us> <loss 0-1> <blocked 0|1> [<burst> [<only>]]".
    // Burst: losses come in runs of this many sends, loss stays the long-run share.
    // Only: a player id; just the links to or from that player are shaped.
    // mpemu rewrites it when a scenario changes the link. Shaping each sender covers every
    // path a link may take (ICE through TURN or host to host, WebRTC), which a
    // TURN server alone cannot do when both players are on one machine.
    class TestShaping
    {
    public:
      static TestShaping& Get()
      {
        static TestShaping instance;
        return instance;
      }

      bool Enabled() const { return !mPath.empty(); }

      // False: lost on the way. Else `delay` is how long it stays in flight.
      bool Roll(Link::Clock::duration& delay, const std::int64_t localId, const std::int64_t remoteId)
      {
        std::lock_guard lock(mMutex);
        const Link::Clock::time_point now = Link::Clock::now();
        if (now >= mNextRead) {
          mNextRead = now + std::chrono::milliseconds(100);
          ReadLocked();
        }
        if (mOnlyId != 0 && localId != mOnlyId && remoteId != mOnlyId) {
          return true;
        }
        if (mBlocked) {
          return false;
        }
        int& burstLeft = mBurstLeft[remoteId];
        if (burstLeft > 0) {
          --burstLeft;
          return false;
        }
        if (mLoss > 0 && std::uniform_real_distribution<double>(0.0, 1.0)(mRng) < mLoss / mBurst) {
          burstLeft = mBurst - 1;
          return false;
        }
        std::int64_t us = mLatencyUs;
        if (mJitterUs > 0) {
          us += std::uniform_int_distribution<std::int64_t>(0, mJitterUs)(mRng);
        }
        delay = std::chrono::microseconds(us);
        return true;
      }

      // The setting just read, once after each change, for one link to log so
      // a run shows what every process applied.
      bool TakeChange(std::string& text)
      {
        std::lock_guard lock(mMutex);
        if (mChange.empty()) {
          return false;
        }
        text = std::move(mChange);
        mChange.clear();
        return true;
      }

    private:
      TestShaping()
      {
        if (const char* path = std::getenv("FAF_NETLINK_TEST_SHAPING"); path != nullptr) {
          mPath = path;
        }
      }

      void ReadLocked()
      {
        std::FILE* f = std::fopen(mPath.c_str(), "r");
        if (f == nullptr) {
          return; // keep the last setting
        }
        long long latency = 0;
        long long jitter = 0;
        double loss = 0;
        int blocked = 0;
        int burst = 1;
        long long only = 0;
        if (std::fscanf(f, "%lld %lld %lf %d %d %lld", &latency, &jitter, &loss, &blocked, &burst, &only) >= 4) {
          if (!mRead || latency != mLatencyUs || jitter != mJitterUs || loss != mLoss || (blocked != 0) != mBlocked) {
            char line[160];
            std::snprintf(line, sizeof(line), "test shaping (%s): %lld us + up to %lld us jitter, loss %.3f%s",
                          mPath.c_str(), latency, jitter, loss, blocked != 0 ? ", blocked" : "");
            mChange = line;
          }
          mRead = true;
          mLatencyUs = latency;
          mJitterUs = jitter;
          mLoss = loss;
          mBlocked = blocked != 0;
          mBurst = burst > 1 ? burst : 1;
          mOnlyId = only;
        }
        std::fclose(f);
      }

      std::string mPath;
      bool mRead = false;
      std::string mChange;
      std::mutex mMutex;
      Link::Clock::time_point mNextRead{};
      std::int64_t mLatencyUs = 0;
      std::int64_t mJitterUs = 0;
      double mLoss = 0;
      bool mBlocked = false;
      int mBurst = 1;
      std::int64_t mOnlyId = 0;
      std::map<std::int64_t, int> mBurstLeft;
      std::minstd_rand mRng{std::random_device{}()};
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

  void Link::OnSignalText(const std::string& json)
  {
    std::shared_ptr<WebRtcChannel> rtc;
    {
      Pending p;
      std::lock_guard lock(mMutex);
      if (mClosed || !mOptions.webrtc) {
        return;
      }
      if (!mRtc && !mOptions.offerer && !mWebRtcGaveUp) {
        StartWebRtcLocked(p); // the answerer's side starts with the offer
      }
      rtc = mRtc;
    }
    if (rtc) {
      rtc->OnSignal(json);
    }
  }

  void Link::StartWebRtcLocked(Pending& out)
  {
    WebRtcOptions o;
    o.localId = mOptions.localId;
    o.remoteId = mOptions.remoteId;
    o.offerer = mOptions.offerer;
    o.iceServers = mOptions.iceServers;
    o.forceRelay = mOptions.forceRelay || mChoice.mode == PathChoice::Mode::RelayOnly;
    o.bindAddress = mOptions.bindAddress;
    auto onLog = [this](const std::string& text) {
      if (mCallbacks.onLog) {
        mCallbacks.onLog(text);
      }
    };
    auto onData = [this](const std::uint8_t* data, const std::size_t size) {
      if (size > 0 && data[0] == remote::net::kDatagramTag && mOptions.redundancy > 0) {
        LaneDeliver(data, size); // issue #240
        return;
      }
      mDataReceived.fetch_add(1);
      if (mCallbacks.onData) {
        mCallbacks.onData(data, size);
      }
    };
    mRtc = std::make_shared<WebRtcChannel>(std::move(o), std::move(onData), std::move(onLog));
    Log(out, std::string("starting WebRTC as ") + (mOptions.offerer ? "offerer" : "answerer"));
    {
      std::lock_guard lock(mLaneRtcMutex);
      mLaneRtc = mRtc;
    }
    mRtc->Start();
  }

  void Link::DropWebRtcLocked(Pending& out)
  {
    if (!mRtc) {
      return;
    }
    // Closing joins libdatachannel's work; do it outside the lock.
    {
      std::lock_guard lock(mLaneRtcMutex);
      mLaneRtc.reset();
    }
    out.actions.push_back([rtc = std::move(mRtc)] { rtc->Close(); });
    mRtc.reset();
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
    remote::net::ChannelStats lane;
    bool haveLane = false;
    {
      std::lock_guard laneLock(mLaneMutex);
      if (mLane) {
        lane = mLane->Stats();
        haveLane = true;
      }
    }
    std::lock_guard lock(mMutex);
    LinkStats s = mStats;
    s.onLane = mLaneActive.load();
    if (haveLane) {
      s.laneRepeats = lane.redundantRepeats;
      s.laneUnacked = lane.redundantUnacked;
      s.laneDuplicates = lane.redundantDuplicates;
      s.laneLost = lane.datagramsLost;
      s.laneUnauthenticated = lane.unauthenticatedDropped;
      if (lane.rttSamples > 0) {
        s.laneRttMs = static_cast<double>(lane.rttSmoothedUs) / 1000.0;
      }
    }
    s.laneEncrypted = s.onLane && mLaneKeyed;
    s.localType = mLocalType;
    s.remoteType = mRemoteType;
    s.choice = mChoice;
    s.dataReceived = mDataReceived.load();
    s.invalidReceived = mInvalidReceived.load();
    s.echoesAnswered = mEchoesAnswered.load();
    const std::int64_t rtt = mLastRttMicros.load();
    s.lastRttMs = rtt < 0 ? -1.0 : static_cast<double>(rtt) / 1000.0;
    s.onWebRtc = mRtc && mRtc->IsOpen();
    s.webRtcSent = mWebRtcSent.load();
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
    // Issue #322: the player's pick in the network panel holds over the policy.
    // /nativenetrelay (forceRelay) still holds over "no relay".
    // Our own pick first, else what our peer picked for this attempt.
    const PathChoice::Mode mode = mChoice.mode != PathChoice::Mode::Auto ? mChoice.mode : mPeerMode;
    if (mode == PathChoice::Mode::RelayOnly) {
      return type == CandidateType::Relayed;
    }
    if (mode == PathChoice::Mode::NoRelay && !mOptions.forceRelay) {
      return type == CandidateType::Host || type == CandidateType::ServerReflexive ||
             type == CandidateType::PeerReflexive;
    }
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
    mLaneActive = false;
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
    // Issue #240: a new connection starts a new lane (lazily, under mLaneMutex).
    // After the agent is gone, so no late datagram of this connection makes the
    // next connection's lane before its keys are known (#289).
    {
      std::lock_guard laneLock(mLaneMutex);
      mLaneReset = true;
      if (mLaneKeys) {
        remote::net::WipeKey(mLaneKeys->send);
        remote::net::WipeKey(mLaneKeys->receive);
        mLaneKeys.reset();
      }
    }
    mLaneKeyed = false;
    mKeyPair.Clear();
    mLocalType.clear();
    mRemoteType.clear();
  }

  // Issue #322: our peer's player picked a path; follow it on this attempt. "auto"
  // starts the attempt policy afresh, as the pick did on the peer's side.
  void Link::NotePeerPathLocked(Pending& out, const std::string& path)
  {
    if (path == "relay") {
      mPeerMode = PathChoice::Mode::RelayOnly;
    } else if (path == "norelay") {
      mPeerMode = PathChoice::Mode::NoRelay;
    } else if (path == "auto") {
      mPeerMode = PathChoice::Mode::Auto;
      mAttemptTimes.clear();
    } else {
      return;
    }
    Log(out, "the peer picked the path " + path + " for this attempt");
  }

  void Link::NoteRemoteUfragLocked(Pending& out, const std::string& ufrag)
  {
    mRemoteUfrag = ufrag;
    mRemoteMarked = !mOptions.ufragPrefix.empty() && mRemoteUfrag.rfind(mOptions.ufragPrefix, 0) == 0;
    mRemoteWebRtc = mRemoteMarked && mRemoteUfrag.rfind(mOptions.ufragPrefix + "w+", 0) == 0;
    mRemoteLane = mRemoteMarked && OffersAfterPrefix(mRemoteUfrag, mOptions.ufragPrefix, "c+");
    // Issue #289: both sides decide the same way, each from the other's ufrag
    // and its own, so the lane is sealed on both or on neither.
    if (!mKeyPair.IsSet() || !mRemoteLane) {
      return;
    }
    const std::optional<LinkPublicKey> peerKey = KeyFromUfrag(mRemoteUfrag, mOptions.ufragPrefix);
    if (!peerKey) {
      Log(out, "the peer offers no lane key; the lane stays unencrypted");
      return;
    }
    std::optional<remote::net::ChannelKeys> keys = mKeyPair.Derive(*peerKey, mOptions.offerer);
    if (!keys) {
      Log(out, "the peer's lane key is unusable; the lane stays unencrypted");
      return;
    }
    {
      std::lock_guard laneLock(mLaneMutex);
      mLaneKeys = *keys;
    }
    remote::net::WipeKey(keys->send);
    remote::net::WipeKey(keys->receive);
    mLaneKeyed = true;
  }

  void Link::InitiateLocked(Pending& out, const CandidatesMessage* remote)
  {
    // PeerIceModule.initiateIce: only from NEW or DISCONNECTED.
    if (mClosed || (mState != LinkState::New && mState != LinkState::Disconnected)) {
      return;
    }
    DestroyAgentLocked();
    mPeerMode = PathChoice::Mode::Auto;
    if (remote != nullptr && !remote->fafPath.empty()) {
      NotePeerPathLocked(out, remote->fafPath); // before any candidate is filtered
    }
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
    // Issue #322: "relay via host:port" keeps that TURN server only, when it is in the list.
    bool chosenTurnListed = false;
    for (const IceServer& s : mOptions.iceServers) {
      chosenTurnListed = chosenTurnListed || (s.kind == IceServer::Kind::Turn && IceServerName(s) == mChoice.turnServer);
    }
    if (!mChoice.turnServer.empty() && !chosenTurnListed) {
      Log(out, "TURN server " + mChoice.turnServer + " is no longer in the list, using every TURN server");
    }
    for (const IceServer& s : mOptions.iceServers) {
      if (chosenTurnListed && IceServerName(s) != mChoice.turnServer) {
        continue;
      }
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
      // Issue #239: "w+" after the prefix offers WebRTC, and issue #240: "c+"
      // after that the redundant lane. A random token never holds '+', so
      // only a peer that offers them starts that way.
      const std::string mark =
        mOptions.ufragPrefix + (mOptions.webrtc ? "w+" : "") + (mOptions.redundancy > 0 ? "c+" : "");
      const std::size_t prefix = mark.size();
      std::string ufrag = mark + RandomToken(prefix + 4 < 14 ? 14 - prefix : 4);
      // Issue #289: a new key pair per attempt; its public key ends the ufrag
      // in place of the random token. Hex digits hold no '+', so the marks
      // before it read as they always have.
      if (mOptions.encrypt && mOptions.redundancy > 0) {
        if (mKeyPair.Generate()) {
          ufrag = mark + KeyMarkFor(mKeyPair.Public());
        } else {
          Log(out, "no random source for a lane key; the lane stays unencrypted");
        }
      }
      if (juice_set_local_ice_attributes(agent, ufrag.c_str(), RandomToken(26).c_str()) != JUICE_ERR_SUCCESS) {
        Log(out, "ufrag refused by libjuice: " + ufrag);
        mKeyPair.Clear();
      }
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
      NoteRemoteUfragLocked(out, remote->ufrag);
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

  // CandidateUtil.unpackCandidates: same generation, an address, an allowed type;
  // libjuice relays and connects over UDP only.
  bool Link::UsableRemoteLocked(const Candidate& c, const Clock::time_point now) const
  {
    return c.generation == 0 && !c.ip.empty() && c.port > 0 && AllowedLocked(c.type, now) && Lower(c.protocol) == "udp";
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
      if (!UsableRemoteLocked(c, now)) {
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
    if (mChoicePicked && mRemoteMarked) {
      msg.fafPath = mChoice.mode == PathChoice::Mode::RelayOnly ? "relay" :
                    mChoice.mode == PathChoice::Mode::NoRelay  ? "norelay" :
                                                                 "auto";
      // "auto" restarts the peer's policy once; later attempts escalate as usual.
      mChoicePicked = mChoice.mode != PathChoice::Mode::Auto;
    }
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
    NoteRemoteUfragLocked(out, remote.ufrag);
    if (!remote.fafPath.empty()) {
      NotePeerPathLocked(out, remote.fafPath);
    }
    // Issue #275: an answer with nothing this link may use can't connect, so start again
    // now (the retry waits kRetryAfterFailure) rather than after kCheckTimeout of checks
    // against nothing. A peer answers that way when its relay isn't there yet.
    const bool anyUsable = std::any_of(remote.candidates.begin(), remote.candidates.end(),
                                       [&](const Candidate& c) { return UsableRemoteLocked(c, now); });
    if (!anyUsable) {
      Log(out, "the answer holds no candidate this link may use (" + std::to_string(remote.candidates.size()) + " sent)");
      ConnectionLostLocked(out, "no usable candidates in the answer", now);
      return;
    }
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
    DropWebRtcLocked(out);
    mWebRtcGaveUp = false; // the next connection may try again
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

      if (TestShaping::Get().Enabled()) {
        std::string change;
        if (TestShaping::Get().TakeChange(change)) {
          Log(p, std::move(change)); // tests only (#242)
        }
      }

      while (!mInbox.empty()) {
        CandidatesMessage m = std::move(mInbox.front());
        mInbox.pop_front();
        ApplyRemoteLocked(p, m, now);
      }

      if (mReconnectAsked) {
        mReconnectAsked = false;
        if (mGameEnded) {
          Log(p, "reconnect not done: the game has ended");
        } else {
          if (mPendingChoice) {
            // A path the player picked: the attempt policy starts afresh.
            mChoice = *mPendingChoice;
            mPendingChoice.reset();
            mChoicePicked = true;
            mAttemptTimes.clear();
            Log(p, "path: " + PathChoiceText(mChoice));
          }
          ConnectionLostLocked(p, "reconnect asked", now);
          if (mOptions.offerer) {
            mRestartAt = now;
          }
        }
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
        if (!gatheringDone && mGatherDeadline && now >= *mGatherDeadline - kGatherTimeout + kGatherSendFound) {
          std::lock_guard cb(mIn->cbMutex);
          for (const Candidate& c : mIn->candidates) {
            if (AllowedLocked(c.type, now)) {
              Log(p, "an ICE server hasn't answered, going on with the candidates found");
              gatheringDone = true;
              break;
            }
          }
        }
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
            mLocalType = CandidateTypeOf(local);
            mRemoteType = CandidateTypeOf(remote);
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
          if (SendFramed(echo, sizeof(echo))) {
            ++mStats.echoesSent;
          }
        }
        if (SteadyMs() - mLastEchoReplyMs.load() > kEchoTimeoutMs) {
          ConnectionLostLocked(p, "no echo answer for 10 s", now);
        }
      }

      // Issue #234: probe a marked peer, 5 times a second apart, then every 5 s
      // until it answers. A reconnect can come up while the path still drops
      // what the link sends (ICE checks got through), and without an answer the
      // lane and its encryption (#289) would stay off for the whole connection.
      if (mState == LinkState::Connected && mRemoteMarked && !mOurPeer.load() && now >= mNextProbe) {
        mNextProbe = now + std::chrono::seconds(mProbesSent < 5 ? 1 : 5);
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

      // Issue #239: the offerer opens the data channel once the peer is ours
      // and offers WebRTC too; the answerer starts on its first signal.
      if (mState == LinkState::Connected && mOptions.offerer && mOptions.webrtc && mRemoteWebRtc && mOurPeer.load() &&
          !mRtc && !mWebRtcGaveUp) {
        StartWebRtcLocked(p);
      }
      if (mRtc) {
        for (std::string& signal : mRtc->TakeSignals()) {
          if (mCallbacks.onSignalText) {
            p.actions.push_back([this, signal = std::move(signal)] { mCallbacks.onSignalText(signal); });
          }
        }
        if (mRtc->HasFailed()) {
          Log(p, "WebRTC gave up; game datagrams stay on the ICE link");
          DropWebRtcLocked(p);
          mWebRtcGaveUp = true;
        }
      }

      // Issue #240: with a peer that is ours and offers it, game datagrams
      // move onto the redundant lane.
      if (mState == LinkState::Connected && mOptions.redundancy > 0 && mRemoteLane && mOurPeer.load() &&
          !mLaneActive.load()) {
        mLaneActive = true;
        Log(p, "game datagrams move onto the redundant lane, each repeated up to " +
                 std::to_string(mOptions.redundancy) + " times until acked" +
                 (mLaneKeyed ? ", encrypted" : ", not encrypted"));
      }

      if (mState == LinkState::Disconnected && mRestartAt && now >= *mRestartAt) {
        mRestartAt.reset();
        InitiateLocked(p, nullptr);
      }
    }
    Run(p);
    if (mLaneActive.load()) {
      LanePoll(); // acks, and repeats while the game is quiet
    }
  }

  bool Link::Send(const void* data, const std::size_t size)
  {
    if (!mConnected.load()) {
      std::lock_guard lock(mMutex);
      ++mStats.dataDropped;
      return false;
    }
    // On the lane the test drop takes the lane's own datagrams (LaneTransmit).
    if (mOptions.testDropPercent > 0 && !mLaneActive.load()) {
      thread_local std::minstd_rand rng{std::random_device{}()};
      if (static_cast<int>(rng() % 100) < mOptions.testDropPercent) {
        std::lock_guard lock(mMutex);
        ++mStats.dataSent; // as if it was lost on the way
        return true;
      }
    }
    // Issue #240: on the redundant lane once it is on.
    if (mLaneActive.load()) {
      std::vector<std::vector<std::uint8_t>> datagrams;
      bool queued = false;
      {
        std::lock_guard laneLock(mLaneMutex);
        remote::net::NetChannel& lane = LaneLocked();
        queued = lane.SendRedundant(data, size);
        lane.Poll(static_cast<std::uint64_t>(SteadyMicros()), datagrams);
      }
      LaneTransmit(datagrams);
      std::lock_guard lock(mMutex);
      if (queued) {
        ++mStats.dataSent;
      } else {
        ++mStats.dataDropped;
      }
      return queued;
    }
    // Issue #239: on the data channel while it is open, as the bare datagram.
    std::shared_ptr<WebRtcChannel> rtc;
    {
      std::lock_guard lock(mMutex);
      rtc = mRtc;
    }
    if (SendWebRtc(rtc, data, size)) {
      std::lock_guard lock(mMutex);
      ++mStats.dataSent;
      mWebRtcSent.fetch_add(1);
      return true;
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

  remote::net::NetChannel& Link::LaneLocked()
  {
    if (!mLane || mLaneReset.exchange(false)) {
      remote::net::ChannelConfig config;
      config.redundancy = static_cast<std::uint32_t>(mOptions.redundancy);
      // The link has its own liveness check (echoes); the lane never times out.
      config.timeoutUs = 24ull * 3600 * 1000 * 1000;
      config.keepaliveIntervalUs = 1'000'000;
      mLane = std::make_unique<remote::net::NetChannel>(config);
      // Issue #289: sealed from its first datagram, with this connection's keys.
      if (mLaneKeys) {
        (void)mLane->SetKeys(*mLaneKeys);
      }
    }
    return *mLane;
  }

  void Link::LaneDeliver(const std::uint8_t* const data, const std::size_t size)
  {
    if (mOptions.redundancy <= 0) {
      mInvalidReceived.fetch_add(1);
      return;
    }
    std::vector<std::vector<std::uint8_t>> messages;
    std::vector<std::vector<std::uint8_t>> datagrams;
    {
      std::lock_guard laneLock(mLaneMutex);
      remote::net::NetChannel& lane = LaneLocked();
      const auto now = static_cast<std::uint64_t>(SteadyMicros());
      lane.Receive(data, size, now);
      std::vector<std::uint8_t> m;
      while (lane.TakeUnreliable(m)) {
        messages.push_back(std::move(m));
      }
      lane.Poll(now, datagrams);
    }
    LaneTransmit(datagrams);
    for (const std::vector<std::uint8_t>& m : messages) {
      mDataReceived.fetch_add(1);
      if (mCallbacks.onData) {
        mCallbacks.onData(m.data(), m.size());
      }
    }
  }

  void Link::LanePoll()
  {
    std::vector<std::vector<std::uint8_t>> datagrams;
    {
      std::lock_guard laneLock(mLaneMutex);
      LaneLocked().Poll(static_cast<std::uint64_t>(SteadyMicros()), datagrams);
    }
    LaneTransmit(datagrams);
  }

  void Link::LaneTransmit(const std::vector<std::vector<std::uint8_t>>& datagrams)
  {
    if (datagrams.empty()) {
      return;
    }
    // Not mMutex: this runs on libjuice's poll thread, which holds libjuice's
    // registry lock, and Tick holds mMutex while starting WebRTC takes that lock.
    std::shared_ptr<WebRtcChannel> rtc;
    {
      std::lock_guard lock(mLaneRtcMutex);
      rtc = mLaneRtc;
    }
    for (const std::vector<std::uint8_t>& d : datagrams) {
      if (mOptions.testDropPercent > 0) {
        thread_local std::minstd_rand rng{std::random_device{}()};
        if (static_cast<int>(rng() % 100) < mOptions.testDropPercent) {
          continue; // tests only: lost on the way
        }
      }
      // On the data channel bare (its first byte is the channel's tag, which no
      // game packet starts with); on ICE behind a 'c'.
      if (SendWebRtc(rtc, d.data(), d.size())) {
        mWebRtcSent.fetch_add(1);
        continue;
      }
      char buf[2048];
      if (d.size() + 1 > sizeof(buf)) {
        continue;
      }
      buf[0] = 'c';
      std::memcpy(buf + 1, d.data(), d.size());
      SendFramed(buf, d.size() + 1);
    }
  }

  WireTotals GetWireTotals()
  {
    return {sWirePackets.load(std::memory_order_relaxed), sWireBytes.load(std::memory_order_relaxed)};
  }

  bool Link::SendFramed(const char* framed, const std::size_t size)
  {
    sWirePackets.fetch_add(1, std::memory_order_relaxed);
    sWireBytes.fetch_add(size, std::memory_order_relaxed);
    if (TestShaping::Get().Enabled()) {
      Clock::duration delay{};
      if (!TestShaping::Get().Roll(delay, mOptions.localId, mOptions.remoteId)) {
        return true; // tests only: lost on the way
      }
      if (delay > Clock::duration::zero()) {
        DelayedSender::Get().Schedule(this, Clock::now() + delay, std::string(framed, size),
                                      [this](const std::string& b) { SendFramedNow(b.data(), b.size()); });
        return true;
      }
    }
    return SendFramedNow(framed, size);
  }

  bool Link::SendFramedNow(const char* framed, const std::size_t size)
  {
    std::shared_lock agentLock(mIn->agentMutex);
    return mAgent != nullptr && juice_send(mAgent, framed, size) == 0;
  }

  bool Link::SendWebRtc(const std::shared_ptr<WebRtcChannel>& rtc, const void* data, const std::size_t size)
  {
    if (!rtc) {
      return false;
    }
    if (!TestShaping::Get().Enabled()) {
      return rtc->Send(data, size);
    }
    if (!rtc->IsOpen()) {
      return false;
    }
    Clock::duration delay{};
    if (!TestShaping::Get().Roll(delay, mOptions.localId, mOptions.remoteId)) {
      return true; // tests only: lost on the way
    }
    if (delay > Clock::duration::zero()) {
      DelayedSender::Get().Schedule(this, Clock::now() + delay,
                                    std::string(static_cast<const char*>(data), size),
                                    [rtc](const std::string& b) { rtc->Send(b.data(), b.size()); });
      return true;
    }
    return rtc->Send(data, size);
  }

  void Link::Close()
  {
    if (mOptions.duplicateGapMs > 0 || TestShaping::Get().Enabled()) {
      DelayedSender::Get().Cancel(this); // before the agent goes
    }
    std::lock_guard lock(mMutex);
    if (mClosed) {
      return;
    }
    mClosed = true;
    mConnected = false;
    mLaneActive = false;
    if (mRtc) {
      {
        std::lock_guard lock(mLaneRtcMutex);
        mLaneRtc.reset();
      }
      mRtc->Close();
      mRtc.reset();
    }
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
        // Turn around (PeerIceModule:539). Under test shaping the answer is
        // delayed and dropped like every other send, so the offerer's rtt
        // covers both directions.
        Clock::duration delay{};
        if (TestShaping::Get().Enabled() && !TestShaping::Get().Roll(delay, self->mOptions.localId, self->mOptions.remoteId)) {
          return; // tests only: lost on the way
        }
        if (delay > Clock::duration::zero()) {
          DelayedSender::Get().Schedule(self, Clock::now() + delay, std::string(data, size),
                                        [self](const std::string& b) { self->SendFramedNow(b.data(), b.size()); });
        } else {
          juice_send(agent, data, size);
        }
      }
    } else if (data[0] == 'c') {
      // Issue #240: a redundant-lane datagram.
      self->LaneDeliver(reinterpret_cast<const std::uint8_t*>(data + 1), size - 1);
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
