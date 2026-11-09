#include "moho/net/NetlinkPeers.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "boost/weak_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "moho/app/NetworkTray.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/NetConVars.h"
#include "moho/net/NetPeerTransport.h"
#include "netlink/EngineLinks.h"
#include "netlink/GameCounters.h"
#include "netlink/Json.h"
#include "netlink/Link.h"
#include "netlink/WebRtc.h"

namespace moho
{
  namespace
  {
    namespace nl = faf::netlink;

    // Issue #322: the game protocol's counts on one link, for the network panel.
    // Sends count on the game's thread, arrivals on libjuice's.
    struct PeerCounters
    {
      std::mutex mutex;
      nl::GameCounters counts;
    };

    // The game's datagrams to one peer go into its link.
    struct LinkTransport final : INetPeerTransport
    {
      std::shared_ptr<nl::Link> link;
      std::shared_ptr<PeerCounters> counters;

      void SendDatagram(const void* data, const std::size_t size) override
      {
        {
          std::lock_guard lock(counters->mutex);
          counters->counts.OnSent(static_cast<const unsigned char*>(data), size);
        }
        link->Send(data, size);
      }
    };

    struct EnginePeer
    {
      std::int64_t id = 0;
      std::string login;
      nl::EngineAddress address;
      std::shared_ptr<nl::Link> link;
      std::shared_ptr<PeerCounters> counters;
    };

    // Issue #322: the latest network log lines, for the network panel.
    class NetLogLines final : public gpg::LogTarget
    {
    public:
      static constexpr std::size_t kKeep = 200; // the panel's log tab scrolls through them

      NetLogLines() : gpg::LogTarget(true) {}

      void OnMessage(
        gpg::LogSeverity, const fa::string& message, const fa::vector<fa::string>&, int
      ) override
      {
        const std::string_view text(message.c_str(), message.size());
        if (text.rfind("NETLINK:", 0) != 0 && text.rfind("NET:", 0) != 0) {
          return;
        }
        std::lock_guard lock(mMutex);
        mLines.emplace_back(text);
        if (mLines.size() > kKeep) {
          mLines.pop_front();
        }
      }

      [[nodiscard]] std::vector<std::string> Lines()
      {
        std::lock_guard lock(mMutex);
        return {mLines.begin(), mLines.end()};
      }

    private:
      std::mutex mMutex;
      std::deque<std::string> mLines;
    };

    std::mutex gLogLinesMutex;
    NetLogLines* gLogLines = nullptr; // lives to the end of the process, as the log does

    class EngineLinks
    {
    public:
      ~EngineLinks() { Shutdown(); }

      void SetGpgNet(const boost::weak_ptr<CGpgNetInterface>& gpgnet)
      {
        std::lock_guard lock(mMutex);
        mGpgNet = gpgnet;
      }

      void Configure(const std::string& json)
      {
        std::string error;
        const std::optional<nl::JsonValue> config = nl::ParseJson(json, &error);
        if (!config || !config->IsObject()) {
          gpg::Logf("NETLINK: bad NetlinkConfig (%s)", error.c_str());
          return;
        }
        std::lock_guard lock(mMutex);
        mLocalId = config->Get("localId").AsInt();
        mIceServers = nl::ParseIceServers(config->Get("iceServers"));
        mForceRelay = config->Get("forceRelay").AsBool();
        mBindAddress = config->Get("bindAddress").AsString();
        mDuplicateGapMs = static_cast<int>(config->Get("duplicateMs").AsInt(-1));
        mWebRtc = config->Get("webrtc").AsBool();
        mRedundancy = static_cast<int>(config->Get("redundancy").AsInt(0));
        // Issue #289: an older bridge sends no "encrypt"; its links offered none.
        const nl::JsonValue* encrypt = config->Find("encrypt");
        mEncrypt = encrypt != nullptr && encrypt->AsBool();
        mTestDropPercent = static_cast<int>(config->Get("testDropPercent").AsInt(0));
        mConfigured = true;
        gpg::Logf(
          "NETLINK: configured, local id %lld, %d ICE server addresses%s", static_cast<long long>(mLocalId),
          static_cast<int>(mIceServers.size()), mForceRelay ? ", relay only" : ""
        );
        StartTickerLocked();
        NETTRAY_Start(); // issue #321
      }

      // Issue #274: native mode, the launcher talks to the game directly. Link
      // options come from the command line and the launcher's messages.
      void StartNative(
        const boost::weak_ptr<CGpgNetInterface>& gpgnet,
        const std::string& bindAddress,
        const bool forceRelay,
        const bool webrtc,
        const int redundancy,
        const bool encrypt
      )
      {
        std::lock_guard lock(mMutex);
        mNative = true;
        mGpgNet = gpgnet;
        mBindAddress = bindAddress;
        mForceRelay = forceRelay;
        mWebRtc = webrtc;
        mRedundancy = redundancy;
        mEncrypt = encrypt;
        StartTickerLocked();
        NETTRAY_Start(); // issue #321
      }

      [[nodiscard]] bool IsNative()
      {
        std::lock_guard lock(mMutex);
        return mNative;
      }

      // Issue #322: what the network panel shows. Statistics are read with the
      // links' own locks, outside mMutex.
      [[nodiscard]] SNetlinkSnapshot Snapshot()
      {
        SNetlinkSnapshot out;
        struct Entry
        {
          std::int64_t id;
          std::string login;
          std::shared_ptr<nl::Link> link;
          std::shared_ptr<PeerCounters> counters;
        };
        std::vector<Entry> entries;
        {
          std::lock_guard lock(mMutex);
          out.mode = mNative ? "native" : mConfigured ? "in-engine" : "";
          out.forceRelay = mForceRelay;
          for (const nl::IceServer& s : mIceServers) {
            (s.kind == nl::IceServer::Kind::Turn ? out.turnServers : out.stunServers).push_back(nl::IceServerName(s));
          }
          for (const auto& [id, peer] : mPeers) {
            entries.push_back({id, peer->login, peer->link, peer->counters});
          }
        }
        for (const Entry& e : entries) {
          const nl::LinkStats stats = e.link->GetStats();
          SNetlinkPeerInfo info;
          info.id = e.id;
          info.login = e.login;
          info.state = nl::LinkStateName(e.link->GetState());
          info.connected = e.link->IsConnected();
          info.localType = stats.localType;
          info.remoteType = stats.remoteType;
          // The offerer's echo, else the lane's own RTT (the answerer sends no echo).
          info.rttMs = stats.lastRttMs >= 0 ? stats.lastRttMs : stats.onLane ? stats.laneRttMs : -1;
          info.onLane = stats.onLane;
          info.laneEncrypted = stats.laneEncrypted;
          info.attempts = stats.attempts;
          info.choice = stats.choice;
          {
            std::lock_guard lock(e.counters->mutex);
            const nl::GameCounters& c = e.counters->counts;
            info.sent = c.sent;
            info.resends = c.dataResends;
            info.received = c.received;
            info.lost = c.lost;
            info.lossPercent = c.LossPercent();
          }
          out.peers.push_back(std::move(info));
        }
        return out;
      }

      bool Reconnect(const std::int64_t id, const nl::PathChoice* choice)
      {
        const std::shared_ptr<nl::Link> link = Find(id);
        if (!link) {
          return false;
        }
        gpg::Logf("NETLINK: peer %lld reconnect asked%s%s", static_cast<long long>(id), choice ? ", path " : "",
                  choice ? nl::PathChoiceText(*choice).c_str() : "");
        link->Reconnect(choice ? std::optional<nl::PathChoice>(*choice) : std::nullopt);
        return true;
      }

      void SetLocalId(const std::int64_t id)
      {
        std::lock_guard lock(mMutex);
        mLocalId = id;
      }

      // The launcher's IceServers: a list of {urls, username, credential}, or
      // the API's session object holding one under "servers" or "iceServers".
      void SetIceServers(const std::string& json)
      {
        std::string error;
        const std::optional<nl::JsonValue> parsed = nl::ParseJson(json, &error);
        if (!parsed) {
          gpg::Logf("NETLINK: bad IceServers (%s)", error.c_str());
          return;
        }
        const nl::JsonValue* list = &*parsed;
        if (parsed->IsObject()) {
          list = parsed->Find("servers");
          if (list == nullptr) {
            list = parsed->Find("iceServers");
          }
        }
        if (list == nullptr || !list->IsArray()) {
          gpg::Logf("NETLINK: IceServers holds no server list");
          return;
        }
        std::lock_guard lock(mMutex);
        mIceServers = nl::ParseIceServers(*list);
        gpg::Logf("NETLINK: %d ICE server addresses for new links", static_cast<int>(mIceServers.size()));
      }

      void RemoveAll()
      {
        std::vector<std::int64_t> ids;
        {
          std::lock_guard lock(mMutex);
          for (const auto& [id, peer] : mPeers) {
            ids.push_back(id);
          }
          mGameEnded = false;
        }
        for (const std::int64_t id : ids) {
          RemovePeer(id);
        }
      }

      void AddPeer(const std::int64_t id, const std::string& login, const bool offerer)
      {
        RemovePeer(id);
        nl::LinkOptions options;
        {
          std::lock_guard lock(mMutex);
          options.localId = mLocalId;
          options.iceServers = mIceServers;
          options.forceRelay = mForceRelay;
          options.bindAddress = mBindAddress;
          options.duplicateGapMs = mDuplicateGapMs;
          options.webrtc = mWebRtc;
          options.redundancy = mRedundancy;
          options.encrypt = mEncrypt;
          options.testDropPercent = mTestDropPercent;
        }
        options.remoteId = id;
        options.offerer = offerer;
        options.ufragPrefix = nl::kOurUfragPrefix;

        const nl::EngineAddress address = nl::EngineAddressFor(id);
        nl::LinkCallbacks cb;
        cb.onSignal = [this, id](const nl::CandidatesMessage& m) {
          SNetCommandArg remote(static_cast<std::int32_t>(id));
          SNetCommandArg text(fa::string(nl::ToJson(m).c_str()));
          Write(nl::kCmdIceMsg, &remote, &text);
        };
        cb.onSignalText = [this, id](const std::string& text) {
          SNetCommandArg remote(static_cast<std::int32_t>(id));
          SNetCommandArg body(fa::string(text.c_str()));
          Write(nl::kCmdIceMsg, &remote, &body);
        };
        cb.onState = [this, id](const nl::LinkState) { ReportState(id); };
        cb.onConnected = [this, id](const bool) { ReportState(id); };
        auto counters = std::make_shared<PeerCounters>();
        // libjuice's thread: to the connector that talks to this address.
        cb.onData = [address, counters](const std::uint8_t* data, const std::size_t size) {
          {
            std::lock_guard lock(counters->mutex);
            counters->counts.OnReceived(data, size);
          }
          NET_DeliverFromPeerTransport(nullptr, address.addrHost, address.portHost, data, size);
        };
        const std::string prefix = "NETLINK: peer " + login + "(" + std::to_string(id) + "): ";
        cb.onLog = [prefix](const std::string& text) { gpg::Logf("%s%s", prefix.c_str(), text.c_str()); };

        auto peer = std::make_unique<EnginePeer>();
        peer->id = id;
        peer->login = login;
        peer->address = address;
        peer->link = std::make_shared<nl::Link>(options, std::move(cb));
        peer->counters = counters;
        auto transport = std::make_shared<LinkTransport>();
        transport->link = peer->link;
        transport->counters = counters;
        NET_SetPeerTransport(nullptr, address.addrHost, address.portHost, std::move(transport));
        gpg::Logf(
          "NETLINK: peer %s(%lld) %s at %s", login.c_str(), static_cast<long long>(id),
          offerer ? "offerer" : "answerer", nl::EngineAddressText(id).c_str()
        );

        std::shared_ptr<nl::Link> link = peer->link;
        {
          std::lock_guard lock(mMutex);
          if (mGameEnded) {
            link->SetGameEnded();
          }
          mPeers[id] = std::move(peer);
          StartTickerLocked();
        }
        link->Start();
      }

      void OnIceMsg(const std::int64_t id, const std::string& json)
      {
        std::shared_ptr<nl::Link> link = Find(id);
        if (!link) {
          gpg::Logf("NETLINK: ICE message for unknown peer %lld", static_cast<long long>(id));
          return;
        }
        if (nl::IsWebRtcSignal(json)) {
          link->OnSignalText(json); // issue #239
          return;
        }
        std::string error;
        const std::optional<nl::CandidatesMessage> m = nl::CandidatesMessageFromJson(json, &error);
        if (!m) {
          gpg::Logf("NETLINK: bad ICE message from peer %lld (%s)", static_cast<long long>(id), error.c_str());
          return;
        }
        link->OnSignal(*m);
      }

      void RemovePeer(const std::int64_t id)
      {
        std::unique_ptr<EnginePeer> peer;
        {
          std::lock_guard lock(mMutex);
          const auto it = mPeers.find(id);
          if (it == mPeers.end()) {
            return;
          }
          peer = std::move(it->second);
          mPeers.erase(it);
        }
        NET_SetPeerTransport(nullptr, peer->address.addrHost, peer->address.portHost, nullptr);
        peer->link->Close();
        gpg::Logf("NETLINK: peer %s(%lld) closed", peer->login.c_str(), static_cast<long long>(id));
      }

      void SetGameEnded()
      {
        std::lock_guard lock(mMutex);
        mGameEnded = true;
        for (auto& [id, peer] : mPeers) {
          peer->link->SetGameEnded();
        }
      }

      void Shutdown()
      {
        std::vector<std::int64_t> ids;
        {
          std::lock_guard lock(mMutex);
          for (const auto& [id, peer] : mPeers) {
            ids.push_back(id);
          }
          mStop = true;
        }
        for (const std::int64_t id : ids) {
          RemovePeer(id);
        }
        mWake.notify_all();
        if (mTicker.joinable()) {
          mTicker.join();
        }
        std::lock_guard lock(mMutex);
        mStop = false;
        mGameEnded = false;
        mNative = false;
        mConfigured = false;
      }

    private:
      std::shared_ptr<nl::Link> Find(const std::int64_t id)
      {
        std::lock_guard lock(mMutex);
        const auto it = mPeers.find(id);
        return it == mPeers.end() ? nullptr : it->second->link;
      }

      void ReportState(const std::int64_t id)
      {
        std::shared_ptr<nl::Link> link = Find(id);
        if (!link) {
          return;
        }
        if (IsNative()) {
          // The lobby server has no message for it; the log keeps it.
          gpg::Logf(
            "NETLINK: peer %lld %s%s", static_cast<long long>(id), nl::LinkStateName(link->GetState()),
            link->IsConnected() ? ", connected" : ""
          );
          return;
        }
        SNetCommandArg remote(static_cast<std::int32_t>(id));
        SNetCommandArg state(fa::string(nl::LinkStateName(link->GetState())));
        SNetCommandArg connected(link->IsConnected() ? 1 : 0);
        boost::shared_ptr<CGpgNetInterface> gpgnet = GpgNet();
        if (gpgnet) {
          try {
            gpgnet->WriteCommandWith3Args(nl::kCmdState, &remote, &state, &connected);
          } catch (const std::exception& ex) {
            gpg::Logf("NETLINK: %s not sent: %s", nl::kCmdState, ex.what());
          }
        }
      }

      void Write(const char* name, const SNetCommandArg* a, const SNetCommandArg* b)
      {
        boost::shared_ptr<CGpgNetInterface> gpgnet = GpgNet();
        if (!gpgnet) {
          return;
        }
        if (IsNative() && std::string_view(name) == nl::kCmdIceMsg) {
          name = nl::kCmdNativeIceMsg; // the lobby server routes IceMsg to the peer
        }
        try {
          gpgnet->WriteCommandWith2Args(name, a, b);
        } catch (const std::exception& ex) {
          gpg::Logf("NETLINK: %s not sent: %s", name, ex.what());
        }
      }

      boost::shared_ptr<CGpgNetInterface> GpgNet()
      {
        std::lock_guard lock(mMutex);
        return mGpgNet.lock();
      }

      // mMutex held.
      void StartTickerLocked()
      {
        if (mTicker.joinable()) {
          return;
        }
        mTicker = std::thread([this] { TickLoop(); });
      }

      // Link timers, restarts and every callback but onData run here.
      void TickLoop()
      {
        std::unique_lock lock(mMutex);
        while (!mStop) {
          std::vector<std::shared_ptr<nl::Link>> links;
          for (const auto& [id, peer] : mPeers) {
            links.push_back(peer->link);
          }
          lock.unlock();
          for (const std::shared_ptr<nl::Link>& link : links) {
            link->Tick();
          }
          lock.lock();
          mWake.wait_for(lock, std::chrono::milliseconds(50), [this] { return mStop; });
        }
      }

      std::mutex mMutex;
      std::condition_variable mWake;
      std::thread mTicker;
      bool mStop = false;
      boost::weak_ptr<CGpgNetInterface> mGpgNet;
      std::int64_t mLocalId = 0;
      std::vector<nl::IceServer> mIceServers;
      bool mForceRelay = false;
      std::string mBindAddress;
      int mDuplicateGapMs = -1;
      bool mWebRtc = false;
      int mRedundancy = 0;
      bool mEncrypt = false;
      int mTestDropPercent = 0;
      bool mGameEnded = false;
      bool mNative = false;
      bool mConfigured = false; // the bridge sent NetlinkConfig (in-engine links)
      std::map<std::int64_t, std::unique_ptr<EnginePeer>> mPeers;
    };

    // net_LogTraffic: what actually goes to ICE, with the lane's copies.
    void LogLinkTraffic(const int beat)
    {
      const faf::netlink::WireTotals wire = faf::netlink::GetWireTotals();
      gpg::Logf(
        "NET: links at beat %d: %llu packets, %llu bytes",
        beat,
        static_cast<unsigned long long>(wire.packets),
        static_cast<unsigned long long>(wire.bytes)
      );
    }

    EngineLinks& Links()
    {
      gNetLinkTrafficLog = LogLinkTraffic;
      static EngineLinks links;
      return links;
    }

    std::int64_t IntArg(const SNetCommandArg& arg)
    {
      if (arg.mType != SNetCommandArg::NETARG_Num) {
        throw std::runtime_error("expected an integer argument");
      }
      return arg.mNum;
    }

    std::string StrArg(const SNetCommandArg& arg)
    {
      if (arg.mType != SNetCommandArg::NETARG_String) {
        throw std::runtime_error("expected a string argument");
      }
      return std::string(arg.mStr.c_str(), arg.mStr.size());
    }
  } // namespace

  void NETLINK_SayHello(CGpgNetInterface& gpgnet)
  {
    // `/inenginelinks` on the command line: /con runs on the first frame,
    // which may come after the adapter's Connected.
    if (net_InEngineLinks == 0 && CFG_GetArgOption("/inenginelinks", 0u, nullptr)) {
      net_InEngineLinks = 1;
    }
    if (net_InEngineLinks == 0) {
      return;
    }
    boost::weak_ptr<CGpgNetInterface> weak;
    boost::AssignWeakFromShared(weak, GPGNET_GetPtr());
    Links().SetGpgNet(weak);
    gpg::Logf("NETLINK: asking the adapter for in-engine links");
    SNetCommandArg version(faf::netlink::kEngineLinksVersion);
    gpgnet.WriteCommandWith1Arg(faf::netlink::kCmdHello, &version);
  }

  bool NETLINK_HandleCommand(const fa::string& name, const fa::vector<SNetCommandArg>& args)
  {
    namespace nl = faf::netlink;
    const auto command = name.view();
    if (command.rfind("Netlink", 0) != 0) {
      return false;
    }
    if (net_InEngineLinks == 0) {
      gpg::Logf("NETLINK: %s ignored, net_InEngineLinks is 0", name.c_str());
      return true;
    }
    if (command == nl::kCmdConfig && args.size() == 1) {
      NETLINK_KeepLogLines(); // issue #322
      Links().Configure(StrArg(args[0]));
    } else if (command == nl::kCmdPeer && args.size() == 3) {
      Links().AddPeer(IntArg(args[0]), StrArg(args[1]), IntArg(args[2]) != 0);
    } else if (command == nl::kCmdIceMsg && args.size() == 2) {
      Links().OnIceMsg(IntArg(args[0]), StrArg(args[1]));
    } else if (command == nl::kCmdClose && args.size() == 1) {
      Links().RemovePeer(IntArg(args[0]));
    } else if (command == nl::kCmdGameEnded) {
      Links().SetGameEnded();
    } else {
      gpg::Logf("NETLINK: unexpected %s with %d arguments", name.c_str(), static_cast<int>(args.size()));
    }
    return true;
  }

  void NETLINK_Shutdown()
  {
    NETTRAY_Stop(); // issue #321: the icon goes with the game's links
    Links().Shutdown();
  }

  bool NETLINK_ReconnectPeer(const std::int64_t id, const faf::netlink::PathChoice* const choice)
  {
    return Links().Reconnect(id, choice);
  }

  SNetlinkSnapshot NETLINK_GetSnapshot()
  {
    SNetlinkSnapshot out = Links().Snapshot();
    std::lock_guard lock(gLogLinesMutex);
    if (gLogLines != nullptr) {
      out.log = gLogLines->Lines();
    }
    return out;
  }

  void NETLINK_KeepLogLines()
  {
    std::lock_guard lock(gLogLinesMutex);
    if (gLogLines == nullptr) {
      gLogLines = new NetLogLines(); // never deleted: the log may write to it until exit
    }
  }

  bool NATIVENET_Enabled()
  {
    // `/nativenet` on the command line: /con runs on the first frame, after
    // the launcher's first messages.
    static const bool fromCommandLine = CFG_GetArgOption("/nativenet", 0u, nullptr);
    return net_NativeNet != 0 || fromCommandLine;
  }

  void NATIVENET_Start()
  {
    if (!NATIVENET_Enabled()) {
      return;
    }
    // Ours, for test hosts and players who pin an interface: the address ICE
    // host candidates bind to (empty: every interface).
    std::string bindAddress;
    fa::vector<fa::string> bindArgs;
    if (CFG_GetArgOption("/nativenetbind", 1u, &bindArgs) && !bindArgs.empty()) {
      bindAddress.assign(bindArgs[0].c_str(), bindArgs[0].size());
    }
    // The client's "force relay" setting: only TURN-relayed candidates.
    const bool forceRelay = CFG_GetArgOption("/nativenetrelay", 0u, nullptr);
    boost::weak_ptr<CGpgNetInterface> weak;
    boost::AssignWeakFromShared(weak, GPGNET_GetPtr());
    NETLINK_KeepLogLines(); // issue #322: the panel's log lines
    const bool encrypt = net_NativeNetEncrypt != 0;
    Links().StartNative(weak, bindAddress, forceRelay, net_NativeNetWebRtc != 0, net_NativeNetRedundancy, encrypt);
    gpg::Logf(
      "NETLINK: native mode, the game links every peer itself%s%s%s, redundancy %d%s", forceRelay ? ", relay only" : "",
      bindAddress.empty() ? "" : ", bound to ", bindAddress.c_str(), static_cast<int>(net_NativeNetRedundancy),
      encrypt && net_NativeNetRedundancy > 0 ? ", lane encrypted with peers that offer it" : ""
    );
  }

  bool NATIVENET_HandleCommand(const fa::string& name, fa::vector<SNetCommandArg>& args)
  {
    namespace nl = faf::netlink;
    if (!Links().IsNative()) {
      return false;
    }
    // Issue #275: a game coming back has no lobby. These messages only set up its links.
    static const bool comingBack = CFG_GetArgOption("/rejoin", 0u, nullptr);
    const auto command = name.view();
    const auto isString = [&](const std::size_t i) {
      return args.size() > i && args[i].mType == SNetCommandArg::NETARG_String;
    };
    const auto isNumber = [&](const std::size_t i) {
      return args.size() > i && args[i].mType == SNetCommandArg::NETARG_Num;
    };
    // The shipped form with the peer's engine address, for PullTask's handler.
    const auto toShipped = [&](const std::int64_t id, const std::string& login) {
      fa::vector<SNetCommandArg> shipped;
      shipped.push_back(SNetCommandArg(fa::string(nl::EngineAddressText(id).c_str())));
      shipped.push_back(SNetCommandArg(fa::string(login.c_str())));
      shipped.push_back(SNetCommandArg(static_cast<std::int32_t>(id)));
      args = shipped;
    };

    if (command == nl::kCmdIceServers && isString(0)) {
      Links().SetIceServers(StrArg(args[0]));
      return true;
    }
    if (command == nl::kCmdNativeIceMsg && args.size() == 2 && isNumber(0) && isString(1)) {
      Links().OnIceMsg(IntArg(args[0]), StrArg(args[1]));
      return true;
    }
    if (command == "CreateLobby" && isNumber(3)) {
      Links().SetLocalId(IntArg(args[3]));
      return comingBack;
    }
    if (command == "HostGame") {
      Links().RemoveAll(); // a new game session, as the adapter's createGameSession
      return comingBack;
    }
    // The lobby server's JoinGame [login, id]: link to the host as answerer.
    if (command == "JoinGame" && args.size() == 2 && isString(0) && isNumber(1)) {
      Links().RemoveAll();
      const std::int64_t id = IntArg(args[1]);
      const std::string login = StrArg(args[0]);
      Links().AddPeer(id, login, false);
      toShipped(id, login);
      return comingBack;
    }
    // ConnectToPeer [login, id, offer]: the shipped form has a string second.
    if (command == "ConnectToPeer" && args.size() == 3 && isString(0) && isNumber(1) && isNumber(2)) {
      const std::int64_t id = IntArg(args[1]);
      const std::string login = StrArg(args[0]);
      Links().AddPeer(id, login, IntArg(args[2]) != 0);
      toShipped(id, login);
      return comingBack;
    }
    if (command == "DisconnectFromPeer" && isNumber(0)) {
      Links().RemovePeer(IntArg(args[0]));
      return comingBack;
    }
    if (command.rfind("Netlink", 0) == 0) {
      gpg::Logf("NETLINK: %s ignored in native mode", name.c_str());
      return true;
    }
    return false;
  }

  void NATIVENET_OnGameMessage(const char* const name)
  {
    if (name != nullptr && std::string_view(name) == "GameEnded" && Links().IsNative()) {
      Links().SetGameEnded();
    }
  }
} // namespace moho
