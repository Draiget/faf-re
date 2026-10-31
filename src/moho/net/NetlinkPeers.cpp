#include "moho/net/NetlinkPeers.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "boost/weak_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/NetConVars.h"
#include "moho/net/NetPeerTransport.h"
#include "netlink/EngineLinks.h"
#include "netlink/Json.h"
#include "netlink/Link.h"

namespace moho
{
  namespace
  {
    namespace nl = faf::netlink;

    // The game's datagrams to one peer go into its link.
    struct LinkTransport final : INetPeerTransport
    {
      std::shared_ptr<nl::Link> link;

      void SendDatagram(const void* data, const std::size_t size) override
      {
        link->Send(data, size);
      }
    };

    struct EnginePeer
    {
      std::int64_t id = 0;
      std::string login;
      nl::EngineAddress address;
      std::shared_ptr<nl::Link> link;
    };

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
        gpg::Logf(
          "NETLINK: configured, local id %lld, %d ICE server addresses%s", static_cast<long long>(mLocalId),
          static_cast<int>(mIceServers.size()), mForceRelay ? ", relay only" : ""
        );
        StartTickerLocked();
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
        }
        options.remoteId = id;
        options.offerer = offerer;
        options.ufragPrefix = nl::kOurUfragPrefix;

        const nl::EngineAddress address = nl::EngineAddressFor(id);
        nl::LinkCallbacks cb;
        cb.onSignal = [this, id](const nl::CandidatesMessage& m) {
          SNetCommandArg remote(static_cast<std::int32_t>(id));
          SNetCommandArg text(msvc8::string(nl::ToJson(m).c_str()));
          Write(nl::kCmdIceMsg, &remote, &text);
        };
        cb.onState = [this, id](const nl::LinkState) { ReportState(id); };
        cb.onConnected = [this, id](const bool) { ReportState(id); };
        // libjuice's thread: to the connector that talks to this address.
        cb.onData = [address](const std::uint8_t* data, const std::size_t size) {
          NET_DeliverFromPeerTransport(nullptr, address.addrHost, address.portHost, data, size);
        };
        const std::string prefix = "NETLINK: peer " + login + "(" + std::to_string(id) + "): ";
        cb.onLog = [prefix](const std::string& text) { gpg::Logf("%s%s", prefix.c_str(), text.c_str()); };

        auto peer = std::make_unique<EnginePeer>();
        peer->id = id;
        peer->login = login;
        peer->address = address;
        peer->link = std::make_shared<nl::Link>(options, std::move(cb));
        auto transport = std::make_shared<LinkTransport>();
        transport->link = peer->link;
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
        SNetCommandArg remote(static_cast<std::int32_t>(id));
        SNetCommandArg state(msvc8::string(nl::LinkStateName(link->GetState())));
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
      bool mGameEnded = false;
      std::map<std::int64_t, std::unique_ptr<EnginePeer>> mPeers;
    };

    EngineLinks& Links()
    {
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

  bool NETLINK_HandleCommand(const msvc8::string& name, const msvc8::vector<SNetCommandArg>& args)
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
    Links().Shutdown();
  }
} // namespace moho
