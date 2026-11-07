#include "moho/app/ServerLobbyUi.h"

#if FAF_SERVER_MODE

#include <cstdlib>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/app/WinApp.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/Common.h"
#include "moho/task/CTask.h"
#include "moho/ui/IUIManager.h"
#include "moho/ui/UiStateTypes.h"
#include "netlink/EngineLinks.h"
#include "gpg/core/streams/BinaryReader.h"
#include "lua/LuaTableIterator.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/net/CLobby.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/LaunchInfoBuilder.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/WldSessionInfo.h"
#include "remote/client/NetworkSimDriver.h"
#include "remote/client/ServerConnect.h"
#include "remote/net/GameLinks.h"
#include "remote/net/LobbySignals.h"

// Engine addition, server mode: see ServerLobbyUi.h.

namespace
{
  using faf::remote::net::ELobbySignal;
  using faf::remote::net::SLobbySignal;

  /** The participant's virtual connection, as the lobby Lua passes addresses: "a.b.c.d:port" (netlink/EngineLinks.h). */
  [[nodiscard]] std::string AddressText(const std::int32_t uid)
  {
    const faf::netlink::EngineAddress address = faf::netlink::EngineAddressFor(uid);
    return std::string(moho::NET_GetDottedOctetFromUInt32(address.addrHost).c_str()) + ":" + std::to_string(address.portHost);
  }

  class CServerLobbyTask final : public moho::CPullTask<CServerLobbyTask>
  {
  public:
    void PullTask();

  private:
    void Apply(const SLobbySignal& signal);
    /** Plan WP2.8, WPR.55: the server's `LaunchInfo` makes the session: this client's launch comes from it alone. */
    void Launch(const std::vector<std::uint8_t>& message);
    void CreateLobby(const SLobbySignal& signal);
    [[nodiscard]] LuaPlus::LuaObject LobbyMethod(const char* name) const;

    // What onlineprovider.lua's `CreateLobby` returned (FAF's lobby module), as `CGpgNetInterface::mLobbyObject`. On
    // the heap and never freed: it must not outlive the Lua state at exit.
    LuaPlus::LuaObject* mLobby = nullptr;
    std::int32_t mHostUid = 0;
    bool mLostSaid = false;
    bool mLaunched = false;
  };

  void CServerLobbyTask::PullTask()
  {
    SLobbySignal signal;
    while (faf::remote::TakeServerLobbySignal(signal)) {
      try {
        Apply(signal);
      } catch (const std::exception& error) {
        gpg::Warnf("SERVER LOBBY: signal %d failed: %s", static_cast<int>(signal.kind), error.what());
      }
    }
    // The server's launch: its first game message is the configuration it launched (with or without a lobby before).
    if (!mLaunched) {
      std::vector<std::uint8_t> message;
      if (faf::remote::TakeServerGameMessage(message)) {
        if (!message.empty() && message[0] == static_cast<std::uint8_t>(faf::remote::net::ESeatMessage::LaunchInfo)) {
          Launch(message);
        } else {
          gpg::Warnf("SERVER LOBBY: a game message (%d) before the launch; dropped", message.empty() ? -1 : static_cast<int>(message[0]));
        }
      }
    }
    if (mLaunched) {
      faf::remote::KeepServerSessionAlive(); // the map loads; the driver reads the channel once the session runs
    }
    if (mLobby == nullptr && !mLostSaid && !mLaunched && !faf::remote::ServerSessionUp()) {
      mLostSaid = true;
      gpg::Logf("SERVER LOBBY: the channel to the server is gone before the lobby started.");
      moho::WIN_OkBox("Ack!", "The connection to the game server was lost.");
    }
  }

  LuaPlus::LuaObject CServerLobbyTask::LobbyMethod(const char* const name) const
  {
    if (mLobby == nullptr) {
      throw std::runtime_error("No lobby.");
    }
    return moho::SCR_GetLuaTableFieldOrThrow(*mLobby, name, "No lobby.", "Lobby method \"%s\" is unavailable.");
  }

  void CServerLobbyTask::CreateLobby(const SLobbySignal& signal)
  {
    if (mLobby != nullptr) {
      throw std::runtime_error("Lobby already exists.");
    }
    // As `CGpgNetInterface::CreateLobby` (0x007B7DE0): the user state to the UI manager, the lobby UI state, then
    // onlineprovider.lua's `CreateLobby(autolaunch, "UDP", port, name, uid, natTraversal, hasSupcom)`.
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    moho::sUIState = moho::UIS_lobby;
    if (state == nullptr || !moho::UI_GetManager()->SetNewLuaState(state)) {
      throw std::runtime_error("UI_GetManager()->SetNewLuaState() failed.");
    }
    constexpr const char* kOnlineProviderModule = "/lua/multiplayer/onlineprovider.lua";
    const LuaPlus::LuaObject provider = moho::SCR_Import(state, gpg::StrArg(kOnlineProviderModule));
    if (!provider.IsTable()) {
      throw std::runtime_error(std::string("Failed to load \"") + kOnlineProviderModule + "\".");
    }
    LuaPlus::LuaObject createLobby = provider["CreateLobby"];
    LuaPlus::LuaFunction<LuaPlus::LuaObject> createLobbyFn(createLobby);
    const std::string uidText = std::to_string(faf::remote::ServerSessionUid());
    // No NAT-traversal object: `InternalCreateLobby` takes the session's relay connector (CLobby.cpp).
    mLobby = new LuaPlus::LuaObject(createLobbyFn.Call_UDP(
      (signal.flags & faf::remote::net::kLobbySignalAutoLobby) != 0, 0, fa::string(signal.name.c_str()), uidText.c_str(), nullptr, 1
    ));
    gpg::Logf("SERVER LOBBY: lobby made for \"%s\" (uid %s).", signal.name.c_str(), uidText.c_str());
  }

  void CServerLobbyTask::Launch(const std::vector<std::uint8_t>& message)
  {
    mLaunched = true;
    LuaPlus::LuaState* const state = moho::USER_GetLuaState();
    LuaPlus::LuaObject config;
    try {
      moho::CMessage bytes(moho::ELobbyMsg::LOBMSG_DirectScriptData);
      (void)bytes.Append(reinterpret_cast<const char*>(message.data() + 1), message.size() - 1u);
      moho::CMessageStream stream(&bytes, moho::CMessageStream::Access::kReadOnly);
      const gpg::BinaryReader reader{&stream};
      LuaPlus::LuaObject codec = state->GetGlobals();
      codec.SCR_FromByteStream(config, state, &reader);
    } catch (const std::exception& error) {
      gpg::Warnf("SERVER LOBBY: the server's launch doesn't read: %s", error.what());
      return;
    }
    if (!config.IsTable()) {
      gpg::Warnf("SERVER LOBBY: the server's launch isn't a table");
      return;
    }
    // This player's name, from their slot in the launch; the server's own observer entry (uid 0) is left out.
    const std::int32_t uid = faf::remote::ServerSessionUid();
    std::string name = "Player";
    LuaPlus::LuaObject players = config["PlayerOptions"];
    if (players.IsTable()) {
      for (LuaPlus::LuaTableIterator it(&players, 1); !it.m_isDone; it.Next()) {
        LuaPlus::LuaObject player = it.GetValue();
        const LuaPlus::LuaObject owner = player.IsTable() ? player["OwnerID"] : LuaPlus::LuaObject{};
        const LuaPlus::LuaObject playerName = player.IsTable() ? player["PlayerName"] : LuaPlus::LuaObject{};
        if (owner.IsString() && std::atoi(owner.GetString()) == uid && playerName.IsString()) {
          name = playerName.GetString();
        }
      }
    }
    LuaPlus::LuaObject noObservers;
    noObservers.AssignNewTable(state, 0, 0u);
    config.SetObject("Observers", noObservers);
    moho::CLaunchRoster roster(uid, fa::string(name.c_str()), {});
    moho::SLaunchBuild build = moho::BuildLaunchInfo(config, roster, 1, true, state); // the seed is the server's sim's
    if (build.failure != nullptr) {
      gpg::Warnf("SERVER LOBBY: the server's launch can't be used: %s", build.failure);
      return;
    }
    faf::remote::client::SServerLaunch launch;
    launch.playerName = name;
    launch.clientIndex = build.localClientIndex;
    launch.uid = uid;
    launch.source = build.localSourceId;
    faf::remote::client::SetServerLaunch(launch);
    gpg::Logf(
      "SERVER LOBBY: launched by the server: map %s, client %d, source %u", build.mapName.c_str(), static_cast<int>(build.localClientIndex),
      static_cast<unsigned>(build.localSourceId)
    );

    auto sessionInfo = fa::auto_ptr<moho::SWldSessionInfo>(new moho::SWldSessionInfo());
    sessionInfo->mIsBeingRecorded = false; // the server keeps the replay
    sessionInfo->mIsReplay = false;
    sessionInfo->mIsMultiplayer = true;
    sessionInfo->mSourceId = build.localSourceId;
    sessionInfo->mMapName = build.mapName;
    sessionInfo->mLaunchInfo = boost::static_pointer_cast<moho::LaunchInfoBase>(build.launchInfo);
    sessionInfo->mClientManager = nullptr; // the network driver makes its own (remote/client/NetworkSimDriver.h)
    moho::LOBBY_ServerSessionLaunched(); // the lobby's screen closes as a launched lobby's does
    delete mLobby;
    mLobby = nullptr;
    moho::WLD_BeginSession(sessionInfo);
  }

  void CServerLobbyTask::Apply(const SLobbySignal& signal)
  {
    switch (signal.kind) {
    case ELobbySignal::Host: {
      CreateLobby(signal);
      mHostUid = faf::remote::ServerSessionUid();
      gpg::Logf("SERVER LOBBY: hosting, map \"%s\".", signal.text.c_str());
      // As `CGpgNetInterface::HostGame` (0x007B81D0): `HostGame(gameName, scenarioFile)`.
      LuaPlus::LuaFunction<void> hostGame(LobbyMethod("HostGame"));
      hostGame("ServerGame", signal.text.c_str());
      return;
    }
    case ELobbySignal::Join: {
      CreateLobby(signal);
      mHostUid = signal.uid;
      const std::string address = AddressText(signal.uid);
      const std::string uidText = std::to_string(signal.uid);
      gpg::Logf("SERVER LOBBY: joining \"%s\" (uid %d) at %s.", signal.text.c_str(), signal.uid, address.c_str());
      // As `CGpgNetInterface::JoinGame` (0x007B83C0): `JoinGame(hostAddress, false, hostName, hostUid)`.
      LuaPlus::LuaFunction<void> joinGame(LobbyMethod("JoinGame"));
      joinGame(address.c_str(), false, signal.text.c_str(), uidText.c_str());
      return;
    }
    case ELobbySignal::ConnectToPeer: {
      const std::string address = AddressText(signal.uid);
      const std::string uidText = std::to_string(signal.uid);
      gpg::Logf("SERVER LOBBY: peer \"%s\" (uid %d) at %s.", signal.name.c_str(), signal.uid, address.c_str());
      // As `CGpgNetInterface::ConnectToPeer` (0x007B85A0).
      LuaPlus::LuaFunction<void> connectToPeer(LobbyMethod("ConnectToPeer"));
      connectToPeer(address.c_str(), signal.name.c_str(), uidText.c_str());
      return;
    }
    case ELobbySignal::LaunchRefused:
    case ELobbySignal::Launching: {
      const std::string text = signal.kind == ELobbySignal::Launching ? std::string("The game server is starting the match.")
                                                                      : "The game server won't start this: " + signal.text + ".";
      gpg::Logf("SERVER LOBBY: %s", text.c_str());
      // FAF's lobby.lua `AddChatText(text)`; autolobby.lua has none, which the log line covers.
      LuaPlus::LuaFunction<void> addChatText(LobbyMethod("AddChatText"));
      addChatText(text.c_str());
      return;
    }
    case ELobbySignal::DisconnectFromPeer: {
      gpg::Logf("SERVER LOBBY: uid %d left.", signal.uid);
      if (signal.uid == mHostUid) {
        // The host's connection ends: `CLobby` tells the Lua the host left, as it does when the host's link drops.
        faf::remote::EndServerLobbyPeer(signal.uid);
        return;
      }
      // As `CGpgNetInterface::DisconnectFromPeer` (0x007B8780). `CLobby::PeerDisconnected` ends the connection itself;
      // ending it here as well would hand `CLobby::Reconnect` a connection it no longer knows.
      const std::string uidText = std::to_string(signal.uid);
      LuaPlus::LuaFunction<void> disconnectFromPeer(LobbyMethod("DisconnectFromPeer"));
      disconnectFromPeer(uidText.c_str());
      return;
    }
    }
  }
} // namespace

bool moho::SERVERLOBBY_Start()
{
  // As the `/gpgnet` start (CScApp.cpp): the user state to the UI manager and gpgnet.lua's waiting front end.
  LuaPlus::LuaState* const state = USER_GetLuaState();
  IUIManager* const uiManager = UI_GetManager();
  if (state == nullptr || uiManager == nullptr || !uiManager->SetNewLuaState(state)) {
    return false;
  }
  try {
    const LuaPlus::LuaObject gpgNetModule = SCR_ImportLuaModule(state, "/lua/multiplayer/gpgnet.lua");
    const LuaPlus::LuaObject createUi = SCR_GetLuaTableField(state, gpgNetModule, "CreateUI");
    if (!createUi.IsNil()) {
      LuaPlus::LuaFunction<void> createUiFn(createUi);
      createUiFn();
    }
  } catch (const std::exception& error) {
    gpg::Warnf("SERVER LOBBY: no waiting screen: %s", error.what());
  }
  (void)new CServerLobbyTask(); // runs every frame for the rest of the session, as CGpgNetInterface's task
  gpg::Logf("SERVER LOBBY: waiting for the server's lobby signals.");
  return true;
}

#endif
