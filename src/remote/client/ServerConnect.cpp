#include "remote/client/ServerConnect.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "gpg/core/containers/String.h"
#include "moho/app/WinApp.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/Common.h"
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

    constexpr std::array<const char*, 8> kLockstepStartupFlags{
      "/hostgame", "/joingame", "/gpgnet", "/replay", "/load", "/scenario", "/map", "/perf",
    };

    [[nodiscard]] bool IsTokenText(const std::string_view token)
    {
      return !token.empty() && token.size() <= kMaxTokenLength
          && std::ranges::all_of(token, [](const char c) { return c > ' ' && c < 0x7F; });
    }

    [[nodiscard]] bool ReadOneArg(const char* const option, std::string& value)
    {
      fa::vector<fa::string> args;
      if (!moho::CFG_GetArgOption(option, 1, &args) || args.empty()) {
        return false;
      }
      value = args[0].c_str();
      return true;
    }
  } // namespace

  EServerConnectArgs ReadServerConnectArgs(SServerConnectRequest& request, std::string& error)
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

    if (!ReadOneArg("/connectserver", request.endpoint)) {
      error = "/connectserver needs the server's address as host:port.";
      return EServerConnectArgs::Invalid;
    }

    u_long address = 0;
    u_short port = 0;
    if (!moho::NET_GetAddrInfo(request.endpoint.c_str(), 0, false, address, port) || port == 0) {
      error = "Invalid address:port for the game server: \"" + request.endpoint + "\".";
      return EServerConnectArgs::Invalid;
    }
    request.address = address;
    request.port = port;

    if (!ReadOneArg("/servertoken", request.token) || !IsTokenText(request.token)) {
      error = "/connectserver needs /servertoken with the token the launcher was given.";
      return EServerConnectArgs::Invalid;
    }

    std::string uid;
    if (!ReadOneArg("/serveruid", uid) || std::atoi(uid.c_str()) <= 0) {
      error = "/connectserver needs /serveruid with the player's id, which the token was made for.";
      return EServerConnectArgs::Invalid;
    }
    request.uid = std::atoi(uid.c_str());

    return EServerConnectArgs::Valid;
  }

  namespace
  {
    [[nodiscard]] std::uint64_t NowUs() noexcept
    {
      return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
      );
    }

    /**
     * The client's channel to the server as the lobby uses it: lobby frames in arrival order (`CLobbyInbox`: a server
     * signal holds back the frames after it), the rest kept for the game's session.
     */
    class CLinkRelayChannel final : public IRelayChannel
    {
    public:
      explicit CLinkRelayChannel(net::CClientLink& link)
        : mLink(link)
      {}

      void SendLobbyFrame(const std::span<const std::uint8_t> frame) override { (void)mLink.SendReliable(frame.data(), frame.size()); }

      bool TakeLobbyFrame(std::vector<std::uint8_t>& frame) override
      {
        Pump();
        return mInbox.TakeLobbyFrame(frame);
      }

      bool Up() const override
      {
        const net::CClientLink::EState state = mLink.State();
        return state == net::CClientLink::EState::Connected || state == net::CClientLink::EState::Connecting;
      }

      void TakeGone(std::vector<std::int32_t>& uids) override
      {
        uids.insert(uids.end(), mGone.begin(), mGone.end());
        mGone.clear();
      }

      [[nodiscard]] bool TakeSignal(net::SLobbySignal& signal)
      {
        Pump();
        return mInbox.TakeSignal(signal);
      }

      void MarkGone(const std::int32_t uid) { mGone.push_back(uid); }

      /** The next message for the game's session (not a lobby frame), in arrival order. */
      [[nodiscard]] bool TakeGameMessage(std::vector<std::uint8_t>& message)
      {
        Pump();
        if (mForGameNext >= mForGame.size()) {
          mForGame.clear();
          mForGameNext = 0;
          return false;
        }
        message = std::move(mForGame[mForGameNext++]);
        return true;
      }

      void SendGameMessage(const std::span<const std::uint8_t> message) { (void)mLink.SendReliable(message.data(), message.size()); }

      /** The link moves (keepalives, acknowledgements); what arrives waits in order for its taker. */
      void KeepAlive() { Pump(); }

    private:
      // The lobby pulls every frame, and the session's task too: the link moves here.
      void Pump()
      {
        mLink.Pump(NowUs());
        while (mLink.TakeReliable(mMessage)) {
          if (!mMessage.empty() && mMessage[0] == static_cast<std::uint8_t>(net::ESeatMessage::Lobby)) {
            mInbox.Push(std::move(mMessage));
          } else {
            mForGame.push_back(std::move(mMessage)); // the game's session takes these (plan WP11)
          }
          mMessage.clear();
        }
      }

      net::CClientLink& mLink;
      CLobbyInbox mInbox;
      std::vector<std::uint8_t> mMessage;
      std::vector<std::int32_t> mGone;
      std::vector<std::vector<std::uint8_t>> mForGame;
      std::size_t mForGameNext = 0;
    };

    /** One server session: the link, the channel the lobby uses over it, the lobby's connector once. */
    struct SServerSession
    {
      SServerSession(const std::int32_t uid, const net::Token& token, const net::SEndpoint& server)
        : uid(uid)
        , link(uid, token, server)
        , channel(link)
      {}

      std::int32_t uid;
      net::CClientLink link;
      CLinkRelayChannel channel;
      bool connectorTaken = false;
    };

    std::unique_ptr<SServerSession> sSession;

    // How long startup waits for the server's answer before telling the player.
    constexpr double kConnectSeconds = 15.0;
  } // namespace

  moho::INetConnector* TakeServerLobbyConnector()
  {
    if (sSession == nullptr || std::exchange(sSession->connectorTaken, true)) {
      return nullptr;
    }
    return new CServerRelayConnector(sSession->channel); // `CLobby` destroys it
  }

  bool TakeServerLobbySignal(net::SLobbySignal& signal)
  {
    return sSession != nullptr && sSession->channel.TakeSignal(signal);
  }

  void EndServerLobbyPeer(const std::int32_t uid)
  {
    if (sSession != nullptr) {
      sSession->channel.MarkGone(uid);
    }
  }

  bool SendServerLaunchRequest(const std::span<const std::uint8_t> configuration)
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

  bool TakeServerGameMessage(std::vector<std::uint8_t>& message)
  {
    return sSession != nullptr && sSession->channel.TakeGameMessage(message);
  }

  void KeepServerSessionAlive()
  {
    if (sSession != nullptr) {
      sSession->channel.KeepAlive();
    }
  }

  bool SendServerGameMessage(const std::span<const std::uint8_t> message)
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

  EServerSessionStart StartServerSessionFromCommandLine(bool (*const startLobbyUi)())
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

    gpg::Logf("Server session requested: %s as player %d", request.endpoint.c_str(), request.uid);

    // Plan WP12.1: the channel first (one handshake, the token), then the lobby over it.
    net::SEndpoint server;
    if (!net::ParseEndpoint(request.endpoint, server)) {
      moho::WIN_OkBox("Ack!", ("The game server's address must be an IPv4 address and port: \"" + request.endpoint + "\".").c_str());
      return EServerSessionStart::Failed;
    }
    sSession = std::make_unique<SServerSession>(request.uid, net::MakeToken(request.token), server);
    if (std::string openError; !sSession->link.Open(openError)) {
      moho::WIN_OkBox("Ack!", ("Can't reach the game server: " + openError).c_str());
      sSession.reset();
      return EServerSessionStart::Failed;
    }
    const auto start = std::chrono::steady_clock::now();
    while (sSession->link.State() == net::CClientLink::EState::Connecting) {
      if (std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() > kConnectSeconds) {
        moho::WIN_OkBox("Ack!", ("The game server at " + request.endpoint + " doesn't answer.").c_str());
        sSession.reset();
        return EServerSessionStart::Failed;
      }
      sSession->link.Pump(NowUs());
      sSession->link.Wait(20);
    }
    if (sSession->link.State() != net::CClientLink::EState::Connected) {
      const auto refusal = sSession->link.Refusal();
      moho::WIN_OkBox(
        "Ack!", ("The game server refused this player" + (refusal ? " (reason " + std::to_string(static_cast<int>(*refusal)) + ")" : std::string()) + ".").c_str()
      );
      sSession.reset();
      return EServerSessionStart::Failed;
    }
    gpg::Logf("Server session: connected to %s", request.endpoint.c_str());

    // The front end waits for the server's lobby signals (plan WP2.12): a task the UI side runs takes them and makes
    // the lobby as GPGNet's commands would (moho/app/ServerLobbyUi.h); `InternalCreateLobby` takes
    // `TakeServerLobbyConnector`.
    if (startLobbyUi == nullptr || !startLobbyUi()) {
      moho::WIN_OkBox("Ack!", "Unable to start the lobby.");
      sSession.reset();
      return EServerSessionStart::Failed;
    }
    return EServerSessionStart::Started;
  }
} // namespace faf::remote
