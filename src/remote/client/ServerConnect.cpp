#include "remote/client/ServerConnect.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/app/WinApp.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/Common.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "remote/ContentCheck.h"
#include "remote/client/ServerRelayConnector.h"
#include "remote/net/GameLinks.h"
#include "remote/net/Datagram.h"
#include "remote/net/Handshake.h"
#include "remote/net/LobbySignals.h"
#include "remote/net/UdpSocket.h"

namespace gpg
{
  void Logf(const char* fmt, ...);
} // namespace gpg

namespace faf::remote
{
  namespace
  {
    // The token is opaque to the client: the server checks it. These limits only keep a
    // malformed launch line from reaching the network.
    constexpr std::size_t kMaxTokenLength = 1024;

    // `/gpgnet` isn't one (plan WP12.2): with a server session it is only the launcher's channel.
    constexpr std::array<const char*, 7> kLockstepStartupFlags{
      "/hostgame",
      "/joingame",
      "/replay",
      "/load",
      "/scenario",
      "/map",
      "/perf",
    };

    [[nodiscard]] bool IsTokenText(
      const std::string_view token
    )
    {
      return !token.empty() && token.size() <= kMaxTokenLength && std::ranges::all_of(token, [](const char c) {
        return c > ' ' && c < 0x7F;
      });
    }

    [[nodiscard]] bool ReadOneArg(
      const char* const option,
      std::string& value
    )
    {
      fa::vector<fa::string> args;
      if (!moho::CFG_GetArgOption(option, 1, &args) || args.empty()) {
        return false;
      }
      value = args[0].c_str();
      return true;
    }
  } // namespace

  EServerConnectArgs ReadServerConnectArgs(
    SServerConnectRequest& request,
    std::string& error
  )
  {
    if (!moho::CFG_GetArgOption("/connectserver", 0, nullptr)) {
      return EServerConnectArgs::Absent;
    }

    for (const char* const flag : kLockstepStartupFlags) {
      if (moho::CFG_GetArgOption(flag, 0, nullptr)) {
        error = std::string{"/connectserver cannot be combined with "} + flag + ".";
        return EServerConnectArgs::Invalid;
      }
    }

    std::string endpoint;
    if (!ReadOneArg("/connectserver", endpoint)) {
      error = "/connectserver needs the server's address as host:port.";
      return EServerConnectArgs::Invalid;
    }
    std::string token;
    if (!ReadOneArg("/servertoken", token) || !IsTokenText(token)) {
      error = "/connectserver needs /servertoken with the token the launcher was given.";
      return EServerConnectArgs::Invalid;
    }
    std::string uid;
    if (!ReadOneArg("/serveruid", uid) || std::atoi(uid.c_str()) <= 0) {
      error = "/connectserver needs /serveruid with the player's id, which the token was made for.";
      return EServerConnectArgs::Invalid;
    }
    return MakeServerConnectRequest(endpoint, token, std::atoi(uid.c_str()), request, error)
      ? EServerConnectArgs::Valid
      : EServerConnectArgs::Invalid;
  }

  bool MakeServerConnectRequest(
    const std::string_view endpoint,
    const std::string_view token,
    const std::int32_t uid,
    SServerConnectRequest& request,
    std::string& error
  )
  {
    // The session's channel takes an IPv4 address and port (`StartServerSession`); a name isn't looked up.
    const std::string endpointText(endpoint);
    net::SEndpoint parsed;
    if (!net::ParseEndpoint(endpointText, parsed)) {
      error = "The game server's address must be an IPv4 address and port: \"" + endpointText + "\".";
      return false;
    }
    if (!IsTokenText(token)) {
      error = "The game server's token must be 1 to " + std::to_string(kMaxTokenLength) +
        " printable characters without spaces.";
      return false;
    }
    if (uid <= 0) {
      error = "The player's id for the game server must be above 0, not " + std::to_string(uid) + ".";
      return false;
    }
    request.endpoint = endpointText;
    request.address = parsed.ip;
    request.port = parsed.port;
    request.token.assign(token);
    request.uid = uid;
    return true;
  }

  bool IsPeerLinkCommand(
    const std::string_view command
  )
  {
    // The shipped engine's lobby and link commands (CGpgNetInterface::PullTask), the ICE adapter's and the native
    // links' (moho/net/NetlinkPeers.cpp, netlink/EngineLinks.h).
    constexpr std::array<std::string_view, 9> kCommands{
      "CreateLobby",
      "HostGame",
      "JoinGame",
      "ConnectToPeer",
      "DisconnectFromPeer",
      "SendNatPacket",
      "EjectPlayer",
      "IceServers",
      "IceMsg",
    };
    return std::ranges::find(kCommands, command) != kCommands.end() || command.starts_with("Netlink");
  }

  namespace
  {
    [[nodiscard]] std::uint64_t NowUs() noexcept
    {
      return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch())
          .count()
      );
    }

    /**
     * The client's channel to the server as the lobby uses it: lobby frames in arrival order (`CLobbyInbox`: a server
     * signal holds back the frames after it), the rest kept for the game's session. Its methods take one lock: the
     * stall cover (`CoverStall`) moves the link from its own thread while the game's thread is busy.
     */
    class CLinkRelayChannel final : public IRelayChannel
    {
    public:
      explicit CLinkRelayChannel(
        net::CClientLink& link
      )
        : mLink(link)
      {}

      void SendLobbyFrame(
        const std::span<const std::uint8_t> frame
      ) override
      {
        const std::scoped_lock lock(mLock);
        (void)mLink.SendReliable(frame.data(), frame.size());
      }

      bool TakeLobbyFrame(
        std::vector<std::uint8_t>& frame
      ) override
      {
        const std::scoped_lock lock(mLock);
        Pump();
        return mInbox.TakeLobbyFrame(frame);
      }

      bool Up() const override
      {
        const std::scoped_lock lock(mLock);
        const net::CClientLink::EState state = mLink.State();
        return state == net::CClientLink::EState::Connected || state == net::CClientLink::EState::Connecting;
      }

      void TakeGone(
        std::vector<std::int32_t>& uids
      ) override
      {
        uids.insert(uids.end(), mGone.begin(), mGone.end());
        mGone.clear();
      }

      void ConnectorGone() override
      {
        mConnectorLive = false;
        mGone.clear(); // the old lobby's; a new one's connections start whole
      }

      /** One connector at a time: false while the last one handed out is alive. */
      [[nodiscard]] bool TakeConnectorSlot()
      {
        return !std::exchange(mConnectorLive, true);
      }

      [[nodiscard]] bool TakeSignal(
        net::SLobbySignal& signal
      )
      {
        const std::scoped_lock lock(mLock);
        Pump();
        return mInbox.TakeSignal(signal);
      }

      void MarkGone(
        const std::int32_t uid
      )
      {
        mGone.push_back(uid);
      }

      /** The next message for the game's session (not a lobby frame), in arrival order. */
      [[nodiscard]] bool TakeGameMessage(
        std::vector<std::uint8_t>& message
      )
      {
        const std::scoped_lock lock(mLock);
        Pump();
        if (mForGameNext >= mForGame.size()) {
          mForGame.clear();
          mForGameNext = 0;
          return false;
        }
        message = std::move(mForGame[mForGameNext++]);
        return true;
      }

      void SendGameMessage(
        const std::span<const std::uint8_t> message
      )
      {
        const std::scoped_lock lock(mLock);
        (void)mLink.SendReliable(message.data(), message.size());
      }

      /** The link moves (keepalives, acknowledgements); what arrives waits in order for its taker. */
      void KeepAlive()
      {
        const std::scoped_lock lock(mLock);
        Pump();
      }

      /**
       * Called by the stall cover's thread every `kStallCheckMs`: moves the link when the game's thread hasn't for
       * `kStallStartUs`, up to `kStallCoverUs` into the stall. FAF's lobby screen is built in one Lua call that takes
       * seconds (a window's 6-8 s, measured 2026-11-09); with no keepalives the server took the player for away
       * (`--lobby-away-seconds`, 6 s) and handed the lobby's host role to the next player. FAF's own lobby links stay
       * up the same way: `CNetUDPConnector` runs on its own thread. A game thread stuck for longer than the cover is
       * let go, so the server still sees a hung client as away.
       */
      void CoverStall()
      {
        const std::scoped_lock lock(mLock);
        const std::uint64_t now = NowUs();
        const std::uint64_t stalledUs = now - mLastPumpUs;
        if (mLastPumpUs == 0 || stalledUs < kStallStartUs || stalledUs > kStallCoverUs) {
          return;
        }
        if (!mStallSaid) {
          mStallSaid = true;
          gpg::Logf("Server session: the game's thread is busy; the link to the server is kept up meanwhile.");
        }
        mLink.Pump(now);
        TakeArrived();
      }

      static constexpr int kStallCheckMs = 100;

    private:
      static constexpr std::uint64_t kStallStartUs = 250'000;
      static constexpr std::uint64_t kStallCoverUs = 30'000'000;

      // The lobby pulls every frame, and the session's task too: the link moves here. The caller holds `mLock`.
      void Pump()
      {
        const std::uint64_t now = NowUs();
        mLastPumpUs = now;
        mStallSaid = false;
        mLink.Pump(now);
        TakeArrived();
      }

      void TakeArrived()
      {
        while (mLink.TakeReliable(mMessage)) {
          if (!mMessage.empty() && mMessage[0] == static_cast<std::uint8_t>(net::ESeatMessage::Lobby)) {
            mInbox.Push(std::move(mMessage));
          } else {
            mForGame.push_back(std::move(mMessage)); // the game's session takes these (plan WP11)
          }
          mMessage.clear();
        }
      }

      mutable std::mutex mLock;
      std::uint64_t mLastPumpUs = 0; // 0: not pumped by the game's thread yet
      bool mStallSaid = false;
      net::CClientLink& mLink;
      CLobbyInbox mInbox;
      std::vector<std::uint8_t> mMessage;
      std::vector<std::int32_t> mGone;
      std::vector<std::vector<std::uint8_t>> mForGame;
      std::size_t mForGameNext = 0;
      bool mConnectorLive = false;
    };

    /** One server session: the link, the channel the lobby uses over it, the thread that covers the game's stalls. */
    struct SServerSession
    {
      SServerSession(
        const std::int32_t uid,
        const net::Token& token,
        const net::SEndpoint& server
      )
        : uid(uid)
        , link(uid, token, server)
        , channel(link)
      {}

      SServerSession(const SServerSession&) = delete;
      SServerSession& operator=(const SServerSession&) = delete;

      ~SServerSession()
      {
        stopCover.store(true);
        if (stallCover.joinable()) {
          stallCover.join();
        }
      }

      /** Once connected: from here on the link is only touched through `channel`. */
      void StartStallCover()
      {
        stallCover = std::thread([this] {
          while (!stopCover.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(CLinkRelayChannel::kStallCheckMs));
            channel.CoverStall();
          }
        });
      }

      std::int32_t uid;
      net::CClientLink link;
      CLinkRelayChannel channel;
      std::atomic<bool> stopCover{false};
      std::thread stallCover;
    };

    std::unique_ptr<SServerSession> sSession;

    // How long startup waits for the server's answer before telling the player.
    constexpr double kConnectSeconds = 15.0;
  } // namespace

  moho::INetConnector* TakeServerLobbyConnector()
  {
    if (sSession == nullptr || !sSession->channel.TakeConnectorSlot()) {
      return nullptr;
    }
    return new CServerRelayConnector(sSession->channel); // `CLobby` destroys it, which frees the slot
  }

  void ReportServerContent(
    moho::RRuleGameRules& rules,
    const std::string& gameMods
  )
  {
    if (sSession == nullptr) {
      return;
    }
    const SContentReport report = MakeContentReport(rules, gameMods);
    const std::vector<std::uint8_t> message = EncodeContentReport(report);
    sSession->channel.SendGameMessage(message);
    gpg::Logf(
      "Server session: content reported: blueprints %016llx, mods %016llx",
      static_cast<unsigned long long>(report.blueprints),
      static_cast<unsigned long long>(report.mods)
    );

    // Plan WP17.8: each mod it runs. The sim mods are the launch's; the UI mods FAF's `lua/mods.lua` `GetUiMods()`
    // lists (each with `uid` and `version`). A Lua without it reports none.
    std::vector<SModEntry> mods;
    for (std::string& uid : ReadModUids(gameMods)) {
      mods.push_back(SModEntry{false, std::move(uid), {}});
    }
    try {
      LuaPlus::LuaState* const state = moho::USER_GetLuaState();
      const LuaPlus::LuaObject module =
        state != nullptr ? moho::SCR_Import(state, "/lua/mods.lua") : LuaPlus::LuaObject{};
      const LuaPlus::LuaObject getUiMods = module.IsTable() ? module["GetUiMods"] : LuaPlus::LuaObject{};
      if (getUiMods.IsFunction()) {
        LuaPlus::LuaFunction<LuaPlus::LuaObject> call(getUiMods);
        LuaPlus::LuaObject list = call();
        for (LuaPlus::LuaTableIterator it(&list, 1); list.IsTable() && !it.m_isDone; it.Next()) {
          LuaPlus::LuaObject info = it.GetValue();
          if (!info.IsTable()) {
            continue;
          }
          const LuaPlus::LuaObject uid = info["uid"];
          const LuaPlus::LuaObject version = info["version"];
          if (uid.IsString()) {
            mods.push_back(
              SModEntry{
                true,
                uid.GetString(),
                version.IsString() || version.IsNumber() ? std::string(version.ToString()) : std::string()
              }
            );
          }
        }
      }
    } catch (const std::exception& error) {
      gpg::Warnf("Server session: the UI mods couldn't be read: %s", error.what());
    }
    sSession->channel.SendGameMessage(EncodeModReport(mods));
    const auto ui = static_cast<std::size_t>(std::count_if(mods.begin(), mods.end(), [](const SModEntry& mod) {
      return mod.ui;
    }));
    gpg::Logf("Server session: mods reported: %zu sim, %zu UI", mods.size() - ui, ui);
  }

  bool TakeServerLobbySignal(
    net::SLobbySignal& signal
  )
  {
    return sSession != nullptr && sSession->channel.TakeSignal(signal);
  }

  void EndServerLobbyPeer(
    const std::int32_t uid
  )
  {
    if (sSession != nullptr) {
      sSession->channel.MarkGone(uid);
    }
  }

  bool SendServerLaunchRequest(
    const std::span<const std::uint8_t> configuration
  )
  {
    if (sSession == nullptr) {
      return false;
    }
    const std::vector<std::uint8_t> message = net::EncodeLaunchRequest(configuration);
    std::vector<std::uint8_t> frame;
    net::ByteWriter writer(frame);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::Lobby));
    writer.Varint(0u); // the server itself
    writer.Bytes(message.data(), message.size());
    sSession->channel.SendLobbyFrame(frame);
    return true;
  }

  bool TakeServerGameMessage(
    std::vector<std::uint8_t>& message
  )
  {
    return sSession != nullptr && sSession->channel.TakeGameMessage(message);
  }

  void KeepServerSessionAlive()
  {
    if (sSession != nullptr) {
      sSession->channel.KeepAlive();
    }
  }

  bool SendServerGameMessage(
    const std::span<const std::uint8_t> message
  )
  {
    if (sSession == nullptr) {
      return false;
    }
    sSession->channel.SendGameMessage(message);
    return true;
  }

  std::int32_t ServerSessionUid()
  {
    return sSession != nullptr ? sSession->uid : 0;
  }

  bool ServerSessionUp()
  {
    return sSession != nullptr && sSession->channel.Up();
  }

  EServerSessionStart StartServerSessionFromCommandLine(
    bool (*const startLobbyUi)()
  )
  {
    SServerConnectRequest request;
    std::string error;
    switch (ReadServerConnectArgs(request, error)) {
    case EServerConnectArgs::Absent:
      return EServerSessionStart::NotRequested;
    case EServerConnectArgs::Invalid:
      moho::WIN_OkBox("Ack!", error.c_str());
      return EServerSessionStart::Failed;
    case EServerConnectArgs::Valid:
      break;
    }
    std::string told; // the player has seen it; there is no launcher to tell
    return StartServerSession(request, startLobbyUi, told);
  }

  bool ServerSessionStarted()
  {
    return sSession != nullptr;
  }

  EServerSessionStart StartServerSession(
    const SServerConnectRequest& request,
    bool (*const startLobbyUi)(),
    std::string& error
  )
  {
    if (sSession != nullptr) {
      error = "a server session is already running";
      return EServerSessionStart::Failed;
    }
    gpg::Logf("Server session requested: %s as player %d", request.endpoint.c_str(), request.uid);
    const auto fail = [&](std::string text) {
      moho::WIN_OkBox("Ack!", text.c_str());
      error = std::move(text);
      sSession.reset();
      return EServerSessionStart::Failed;
    };

    // Plan WP12.1: the channel first (one handshake, the token), then the lobby over it.
    net::SEndpoint server;
    if (!net::ParseEndpoint(request.endpoint, server)) {
      return fail("The game server's address must be an IPv4 address and port: \"" + request.endpoint + "\".");
    }
    sSession = std::make_unique<SServerSession>(request.uid, net::MakeToken(request.token), server);
    if (std::string openError; !sSession->link.Open(openError)) {
      return fail("Can't reach the game server: " + openError);
    }
    const auto start = std::chrono::steady_clock::now();
    while (sSession->link.State() == net::CClientLink::EState::Connecting) {
      if (std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() > kConnectSeconds) {
        return fail("The game server at " + request.endpoint + " doesn't answer.");
      }
      sSession->link.Pump(NowUs());
      sSession->link.Wait(20);
    }
    if (sSession->link.State() != net::CClientLink::EState::Connected) {
      const auto refusal = sSession->link.Refusal();
      return fail(
        "The game server refused this player" +
        (refusal ? " (reason " + std::to_string(static_cast<int>(*refusal)) + ")" : std::string()) + "."
      );
    }
    gpg::Logf("Server session: connected to %s", request.endpoint.c_str());
    sSession->channel.KeepAlive(); // the stall cover counts from the game thread's last pump
    sSession->StartStallCover();

    // The front end waits for the server's lobby signals (plan WP2.12): a task the UI side runs takes them and makes
    // the lobby as GPGNet's commands would (moho/app/ServerLobbyUi.h); `InternalCreateLobby` takes
    // `TakeServerLobbyConnector`.
    if (startLobbyUi == nullptr || !startLobbyUi()) {
      return fail("Unable to start the lobby.");
    }
    return EServerSessionStart::Started;
  }
} // namespace faf::remote
