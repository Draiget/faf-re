#include "netbridge/Bridge.h"
#include "netlink/EngineLinks.h"
#include "netlink/WebRtc.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>

namespace faf::netbridge
{
  using netlink::JsonValue;

  namespace
  {
    constexpr const char* kVersion = "faf-netbridge 0.1";

    std::string Timestamp()
    {
      const auto now = std::chrono::system_clock::now();
      const std::time_t t = std::chrono::system_clock::to_time_t(now);
      const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
      std::tm tm{};
#ifdef _WIN32
      localtime_s(&tm, &t);
#else
      localtime_r(&t, &tm);
#endif
      char buf[32];
      std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d", tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms));
      return buf;
    }

    // FaDataInputStream.readChunks: strings from the game get "/t" and "/n"
    // turned into tab and newline before they reach the client.
    std::string GameString(std::string s)
    {
      for (const auto& [from, to] : {std::pair<const char*, const char*>{"/t", "\t"}, {"/n", "\n"}}) {
        std::size_t pos = 0;
        while ((pos = s.find(from, pos)) != std::string::npos) {
          s.replace(pos, 2, to);
          pos += 1;
        }
      }
      return s;
    }

    // FaDataOutputStream.writeArgs: numbers become ints, strings strings.
    GpgArg ArgFromJson(const JsonValue& v)
    {
      switch (v.GetKind()) {
        case JsonValue::Kind::Number: return GpgArg::Int(static_cast<std::int32_t>(v.AsInt()));
        case JsonValue::Kind::Bool: return GpgArg::Int(v.AsBool() ? 1 : 0);
        case JsonValue::Kind::String: return GpgArg::Str(v.AsString());
        default: return GpgArg::Str(netlink::WriteJson(v));
      }
    }

    bool ParseU16(const char* s, std::uint16_t& out)
    {
      char* end = nullptr;
      const long v = std::strtol(s, &end, 10);
      if (end == s || v < 0 || v > 65535) {
        return false;
      }
      out = static_cast<std::uint16_t>(v);
      return true;
    }
  } // namespace

  BridgeOptions ParseBridgeArgs(const int argc, char** argv)
  {
    BridgeOptions o;
    for (int i = 1; i < argc; ++i) {
      std::string name = argv[i];
      std::string value;
      bool hasValue = false;
      if (const std::size_t eq = name.find('='); name.rfind("--", 0) == 0 && eq != std::string::npos) {
        value = name.substr(eq + 1);
        name = name.substr(0, eq);
        hasValue = true;
      }
      auto next = [&]() -> const char* {
        if (hasValue) {
          return value.c_str();
        }
        if (i + 1 < argc) {
          return argv[++i];
        }
        return "";
      };
      if (name == "--id") {
        o.id = std::strtoll(next(), nullptr, 10);
      } else if (name == "--game-id") {
        o.gameId = std::strtoll(next(), nullptr, 10);
      } else if (name == "--login") {
        o.login = next();
      } else if (name == "--rpc-port") {
        ParseU16(next(), o.rpcPort);
      } else if (name == "--gpgnet-port") {
        ParseU16(next(), o.gpgnetPort);
      } else if (name == "--lobby-port") {
        ParseU16(next(), o.lobbyPort);
      } else if (name == "--force-relay") {
        o.forceRelay = true;
      } else if (name == "--bind-address") {
        o.bindAddress = next();
      } else if (name == "--game-address") {
        o.gameAddress = next();
      } else if (name == "--duplicate-ms") {
        o.duplicateGapMs = std::atoi(next());
      } else if (name == "--webrtc") {
        o.webrtc = true;
      } else if (name == "--redundancy") {
        o.redundancy = std::atoi(next()); // issue #240
      } else if (name == "--test-drop-percent") {
        o.testDropPercent = std::atoi(next());
      } else if (name == "--stats-interval") {
        o.statsIntervalSec = std::atoi(next());
      } else if (name == "--log-file") {
        o.logPath = next();
      } else if (name == "--access-token" || name == "--icebreaker-base-url" || name == "--telemetry-server" ||
                 name == "--ping-count" || name == "--acceptable-latency" || name == "--delay-ui") {
        next(); // known to the launcher or the Java adapter, not used here
      }
      // Anything else (--debug-window, --info-window, unknown) is skipped.
    }
    return o;
  }

  Logger::Logger(const std::string& path)
  {
    if (!path.empty()) {
      mFile = std::fopen(path.c_str(), "a");
    }
  }

  Logger::~Logger()
  {
    if (mFile != nullptr) {
      std::fclose(mFile);
    }
  }

  void Logger::Write(const std::string& line)
  {
    std::lock_guard lock(mMutex);
    const std::string text = Timestamp() + " " + line + "\n";
    std::fputs(text.c_str(), stderr);
    if (mFile != nullptr) {
      std::fputs(text.c_str(), mFile);
      std::fflush(mFile);
    }
  }

  namespace
  {
    constexpr unsigned char kPacketData = 4; // PT_Data
    constexpr unsigned char kPacketTypes = 9; // PT_Connect .. PT_NATTraversal
    constexpr std::size_t kHeaderSize = 15;  // kNetPacketHeaderSize

    std::uint16_t U16(const unsigned char* p) { return static_cast<std::uint16_t>(p[0] | (p[1] << 8)); }
    // Serial and sequence numbers wrap at 16 bits.
    std::int32_t Diff16(const std::uint16_t a, const std::uint16_t b) { return static_cast<std::int16_t>(a - b); }
  } // namespace

  void GameCounters::OnSent(const unsigned char* d, const std::size_t n)
  {
    ++sent;
    if (n < kHeaderSize || d[0] != kPacketData) {
      return;
    }
    const std::uint16_t seq = U16(d + 9);
    if (mHaveSeq && Diff16(seq, mTopSeq) <= 0) {
      ++dataResends;
      return;
    }
    mHaveSeq = true;
    mTopSeq = seq;
  }

  void GameCounters::OnReceived(const unsigned char* d, const std::size_t n)
  {
    ++received;
    if (n < kHeaderSize || d[0] >= kPacketTypes) {
      return;
    }
    const std::uint16_t serial = U16(d + 5);
    if (!mHaveSerial) {
      mHaveSerial = true;
      mTopSerial = serial;
      mSeenMask = 1;
      return;
    }
    const std::int32_t ahead = Diff16(serial, mTopSerial);
    if (ahead > 0) {
      // Everything skipped counts as lost until it turns up late.
      const auto shift = static_cast<std::uint64_t>(ahead);
      lost += shift - 1;
      mSeenMask = shift >= 64 ? 1 : (mSeenMask << shift) | 1;
      mTopSerial = serial;
      return;
    }
    const auto back = static_cast<std::uint64_t>(-ahead);
    if (back >= 64) {
      ++late; // too old to tell apart
      return;
    }
    if ((mSeenMask >> back) & 1) {
      ++repeats;
      return;
    }
    mSeenMask |= std::uint64_t{1} << back;
    ++late;
    if (lost > 0) {
      --lost; // counted missing when a newer one came first
    }
  }

  Bridge::Bridge(BridgeOptions options, Logger& log) : mOptions(std::move(options)), mLog(log) {}

  Bridge::~Bridge()
  {
    mPeers.clear();
    CloseSocket(mRpcClient);
    CloseSocket(mRpcListen);
    CloseSocket(mGpgClient);
    CloseSocket(mGpgListen);
  }

  std::uint16_t Bridge::PickLobbyPort() const
  {
    // GPGNetServer: NetworkToolbox.findFreeUDPPort(20000, 65536). The game
    // binds every interface, so the port has to be free there.
    std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> pick(20000, 65535);
    for (int attempt = 0; attempt < 200; ++attempt) {
      const auto port = static_cast<std::uint16_t>(pick(rng));
      SocketHandle s = BindUdp("0.0.0.0", port);
      if (s != kInvalidSocket) {
        CloseSocket(s);
        return port;
      }
    }
    return 0;
  }

  bool Bridge::Listen()
  {
    mGpgListen = ListenTcp("127.0.0.1", mOptions.gpgnetPort);
    if (mGpgListen == kInvalidSocket) {
      Log("cannot listen for the game on GPGNet port " + std::to_string(mOptions.gpgnetPort));
      return false;
    }
    mRpcListen = ListenTcp("127.0.0.1", mOptions.rpcPort);
    if (mRpcListen == kInvalidSocket) {
      Log("cannot listen for the client on RPC port " + std::to_string(mOptions.rpcPort));
      return false;
    }
    mLobbyPort = mOptions.lobbyPort != 0 ? mOptions.lobbyPort : PickLobbyPort();
    Log(std::string(kVersion) + ": player " + mOptions.login + " (" + std::to_string(mOptions.id) + "), game " +
        std::to_string(mOptions.gameId) + ", RPC port " + std::to_string(LocalPort(mRpcListen)) + ", GPGNet port " +
        std::to_string(LocalPort(mGpgListen)) + ", lobby port " + std::to_string(mLobbyPort) +
        (mOptions.forceRelay ? ", relay only" : ""));
    return true;
  }

  int Bridge::Run()
  {
    if (!Listen()) {
      return 1;
    }
    mNextStats = std::chrono::steady_clock::now() + std::chrono::seconds(mOptions.statsIntervalSec);
    while (!mQuit) {
      Poll();
      for (auto& [id, peer] : mPeers) {
        peer->link->Tick();
      }
      if (mOptions.statsIntervalSec > 0 && std::chrono::steady_clock::now() >= mNextStats) {
        mNextStats = std::chrono::steady_clock::now() + std::chrono::seconds(mOptions.statsIntervalSec);
        for (auto& [id, peer] : mPeers) {
          LogStats(*peer, "periodic");
        }
      }
    }
    Log("stopping, exit code " + std::to_string(mExitCode));
    return mExitCode;
  }

  void Bridge::Poll()
  {
    fd_set read;
    FD_ZERO(&read);
    SocketHandle maxFd = 0;
    auto add = [&](const SocketHandle s) {
      if (s != kInvalidSocket) {
        FD_SET(s, &read);
        maxFd = s > maxFd ? s : maxFd;
      }
    };
    add(mRpcListen);
    add(mRpcClient);
    add(mGpgListen);
    add(mGpgClient);
    for (auto& [id, peer] : mPeers) {
      add(peer->udp);
    }
    timeval tv{0, 20 * 1000};
    const int n = select(static_cast<int>(maxFd + 1), &read, nullptr, nullptr, &tv);
    if (n <= 0) {
      return;
    }
    if (mRpcListen != kInvalidSocket && FD_ISSET(mRpcListen, &read)) {
      AcceptRpc();
    }
    if (mRpcClient != kInvalidSocket && FD_ISSET(mRpcClient, &read)) {
      ReadRpc();
    }
    if (mGpgListen != kInvalidSocket && FD_ISSET(mGpgListen, &read)) {
      AcceptGpg();
    }
    if (mGpgClient != kInvalidSocket && FD_ISSET(mGpgClient, &read)) {
      ReadGpg();
    }
    for (auto& [id, peer] : mPeers) {
      if (peer->udp != kInvalidSocket && FD_ISSET(peer->udp, &read)) {
        ReadPeer(*peer);
      }
    }
  }

  // --- RPC -------------------------------------------------------------------

  void Bridge::AcceptRpc()
  {
    SocketHandle s = accept(mRpcListen, nullptr, nullptr);
    if (s == kInvalidSocket) {
      return;
    }
    if (mRpcClient != kInvalidSocket) {
      // RPCService serves its first peer only.
      Log("second RPC connection refused");
      CloseSocket(s);
      return;
    }
    int noDelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    mRpcClient = s;
    Log("RPC client connected");
  }

  void Bridge::ReadRpc()
  {
    char buf[16384];
    const int n = recv(mRpcClient, buf, sizeof(buf), 0);
    if (n <= 0) {
      OnRpcLost();
      return;
    }
    mRpcIn.append(buf, static_cast<std::size_t>(n));
    // One JSON object per message. Unlike JJsonRpc's reader this one skips
    // braces inside strings: the client's JSON writer does not escape them.
    for (;;) {
      std::size_t start = mRpcIn.find('{');
      if (start == std::string::npos) {
        mRpcIn.clear();
        return;
      }
      int depth = 0;
      bool inString = false;
      bool escape = false;
      std::size_t end = std::string::npos;
      for (std::size_t i = start; i < mRpcIn.size(); ++i) {
        const char c = mRpcIn[i];
        if (inString) {
          if (escape) {
            escape = false;
          } else if (c == '\\') {
            escape = true;
          } else if (c == '"') {
            inString = false;
          }
          continue;
        }
        if (c == '"') {
          inString = true;
        } else if (c == '{') {
          ++depth;
        } else if (c == '}' && --depth == 0) {
          end = i;
          break;
        }
      }
      if (end == std::string::npos) {
        mRpcIn.erase(0, start);
        return;
      }
      const std::string text = mRpcIn.substr(start, end - start + 1);
      mRpcIn.erase(0, end + 1);
      std::string error;
      const std::optional<JsonValue> msg = netlink::ParseJson(text, &error);
      if (!msg || !msg->IsObject()) {
        Log("bad RPC message (" + error + "): " + text);
        continue;
      }
      HandleRpc(*msg);
      if (mQuit) {
        return;
      }
    }
  }

  void Bridge::OnRpcLost()
  {
    CloseSocket(mRpcClient);
    mRpcIn.clear();
    // RPCService.close: keep running while the game is launching (the client
    // may be restarting), otherwise stop.
    if (mGameState == "Launching") {
      Log("lost the RPC client while the game is launching, not stopping");
      return;
    }
    Log("lost the RPC client, stopping");
    mQuit = true;
  }

  void Bridge::WriteRpc(const JsonValue& msg)
  {
    if (mRpcClient == kInvalidSocket) {
      return;
    }
    const std::string line = netlink::WriteJson(msg) + "\n"; // println
    if (!SendAll(mRpcClient, line.data(), line.size())) {
      OnRpcLost();
    }
  }

  void Bridge::Respond(const std::int64_t id, const JsonValue& result)
  {
    JsonValue m = JsonValue::Object();
    m.Set("result", result);
    m.Set("id", id);
    m.Set("jsonrpc", "2.0");
    WriteRpc(m);
  }

  void Bridge::RespondError(const std::int64_t id, const int code, const std::string& message)
  {
    JsonValue err = JsonValue::Object();
    err.Set("code", code);
    err.Set("message", message);
    JsonValue m = JsonValue::Object();
    m.Set("id", id);
    m.Set("error", std::move(err));
    m.Set("jsonrpc", "2.0");
    WriteRpc(m);
  }

  void Bridge::Notify(const std::string& method, JsonValue params)
  {
    JsonValue m = JsonValue::Object();
    m.Set("method", method);
    m.Set("params", std::move(params));
    m.Set("jsonrpc", "2.0");
    WriteRpc(m);
  }

  void Bridge::HandleRpc(const JsonValue& msg)
  {
    const std::string& method = msg.Get("method").AsString();
    const JsonValue& params = msg.Get("params");
    const JsonValue* idValue = msg.Find("id");
    const bool hasId = idValue != nullptr && idValue->IsNumber();
    const std::int64_t id = hasId ? idValue->AsInt() : 0;
    if (method.empty()) {
      return; // a response to something we never sent
    }
    Log("RPC " + method + " " + netlink::WriteJson(params));

    JsonValue result;
    bool known = true;
    if (method == "quit") {
      if (hasId) {
        Respond(id, result);
      }
      mExitCode = 0;
      mQuit = true;
      return;
    }
    if (method == "hostGame") {
      NewGameSession();
      SendToGame({"HostGame", {GpgArg::Str(params[0].AsString())}});
    } else if (method == "joinGame") {
      NewGameSession();
      const std::string& login = params[0].AsString();
      const std::int64_t remote = params[1].AsInt();
      const std::string address = ConnectPeer(remote, login, false);
      SendToGame({"JoinGame", {GpgArg::Str(address), GpgArg::Str(login), GpgArg::Int(static_cast<std::int32_t>(remote))}});
    } else if (method == "connectToPeer") {
      if (mGpgClient != kInvalidSocket && (mGameState == "Launching" || mGameState == "Ended")) {
        Log("game ended or in progress, ignoring connectToPeer");
      } else {
        const std::string& login = params[0].AsString();
        const std::int64_t remote = params[1].AsInt();
        const std::string address = ConnectPeer(remote, login, params[2].AsBool());
        SendToGame(
          {"ConnectToPeer", {GpgArg::Str(address), GpgArg::Str(login), GpgArg::Int(static_cast<std::int32_t>(remote))}}
        );
      }
    } else if (method == "disconnectFromPeer") {
      const std::int64_t remote = params[0].AsInt();
      RemovePeer(remote);
      if (const auto engine = mEnginePeers.find(remote); engine != mEnginePeers.end()) {
        const bool wasConnected = engine->second.connected;
        mEnginePeers.erase(engine);
        SendToGame({netlink::kCmdClose, {GpgArg::Int(static_cast<std::int32_t>(remote))}});
        if (wasConnected) {
          JsonValue p = JsonValue::Array();
          p.Push(mOptions.id);
          p.Push(remote);
          p.Push(false);
          Notify("onConnected", std::move(p));
        }
      }
      SendToGame({"DisconnectFromPeer", {GpgArg::Int(static_cast<std::int32_t>(remote))}});
    } else if (method == "setLobbyInitMode") {
      mInitMode = params[0].AsString() == "auto" ? 1 : 0; // LobbyInitMode NORMAL 0, AUTO 1
    } else if (method == "iceMsg") {
      OnIceMsg(params[0].AsInt(), params[1]);
    } else if (method == "sendToGpgNet") {
      GpgMessage m{params[0].AsString(), {}};
      for (const JsonValue& chunk : params[1].Items()) {
        m.args.push_back(ArgFromJson(chunk));
      }
      SendToGame(std::move(m));
    } else if (method == "status") {
      result = netlink::WriteJson(Status());
    } else if (method == "setIceServers") {
      mIceServers = netlink::ParseIceServers(params[0]);
      mIceServersJson = params[0];
      Log("ICE servers set, " + std::to_string(mIceServers.size()) + " usable addresses");
      if (mEngineLinks) {
        SendEngineConfig();
      }
    } else {
      known = false;
    }
    if (!hasId) {
      return;
    }
    if (known) {
      Respond(id, result);
    } else {
      RespondError(id, -32601, "Method not found");
    }
  }

  void Bridge::OnIceMsg(const std::int64_t remoteId, const JsonValue& msg)
  {
    if (mEnginePeers.count(remoteId) != 0) {
      const std::string text = msg.IsString() ? msg.AsString() : netlink::WriteJson(msg);
      SendToGame({netlink::kCmdIceMsg, {GpgArg::Int(static_cast<std::int32_t>(remoteId)), GpgArg::Str(text)}});
      return;
    }
    const auto it = mPeers.find(remoteId);
    if (it == mPeers.end()) {
      Log("ICE message ignored for unknown peer " + std::to_string(remoteId));
      return;
    }
    const std::string text = msg.IsString() ? msg.AsString() : netlink::WriteJson(msg);
    if (netlink::IsWebRtcSignal(text)) {
      it->second->link->OnSignalText(text); // issue #239
      return;
    }
    std::string error;
    const std::optional<netlink::CandidatesMessage> m = netlink::CandidatesMessageFromJson(text, &error);
    if (!m) {
      Log("failed to parse iceMsg (" + error + "): " + text);
      return;
    }
    it->second->link->OnSignal(*m);
  }

  JsonValue Bridge::Status() const
  {
    // RPCHandler.status / IceStatus, field for field.
    JsonValue options = JsonValue::Object();
    options.Set("player_id", mOptions.id);
    options.Set("player_login", mOptions.login);
    options.Set("rpc_port", static_cast<int>(LocalPort(mRpcListen)));
    options.Set("gpgnet_port", static_cast<int>(LocalPort(mGpgListen)));
    JsonValue gpg = JsonValue::Object();
    gpg.Set("local_port", static_cast<int>(LocalPort(mGpgListen)));
    gpg.Set("connected", mGpgClient != kInvalidSocket);
    gpg.Set("game_state", mGameState);
    gpg.Set("task_string", "-");
    JsonValue relays = JsonValue::Array();
    for (const auto& [id, peer] : mPeers) {
      JsonValue ice = JsonValue::Object();
      ice.Set("offerer", peer->offerer);
      ice.Set("state", netlink::LinkStateName(peer->link->GetState()));
      ice.Set("gathering_state", "");
      ice.Set("datachannel_state", "");
      ice.Set("connected", peer->link->IsConnected());
      ice.Set("loc_cand_addr", "");
      ice.Set("rem_cand_addr", "");
      ice.Set("loc_cand_type", "");
      ice.Set("rem_cand_type", "");
      ice.Set("time_to_connected", -1.0);
      JsonValue relay = JsonValue::Object();
      relay.Set("remote_player_id", id);
      relay.Set("remote_player_login", peer->login);
      relay.Set("local_game_udp_port", static_cast<int>(peer->port));
      relay.Set("ice", std::move(ice));
      relays.Push(std::move(relay));
    }
    for (const auto& [id, peer] : mEnginePeers) {
      JsonValue ice = JsonValue::Object();
      ice.Set("offerer", peer.offerer);
      ice.Set("state", peer.state);
      ice.Set("gathering_state", "");
      ice.Set("datachannel_state", "");
      ice.Set("connected", peer.connected);
      ice.Set("loc_cand_addr", "");
      ice.Set("rem_cand_addr", "");
      ice.Set("loc_cand_type", "");
      ice.Set("rem_cand_type", "");
      ice.Set("time_to_connected", -1.0);
      JsonValue relay = JsonValue::Object();
      relay.Set("remote_player_id", id);
      relay.Set("remote_player_login", peer.login);
      relay.Set("local_game_udp_port", static_cast<int>(netlink::EngineAddressFor(id).portHost));
      relay.Set("ice", std::move(ice));
      relays.Push(std::move(relay));
    }
    JsonValue s = JsonValue::Object();
    s.Set("version", kVersion);
    s.Set("ice_servers_size", static_cast<int>(mIceServers.size()));
    s.Set("lobby_port", static_cast<int>(mLobbyPort));
    s.Set("init_mode", mInitMode == 1 ? "auto" : "normal");
    s.Set("options", std::move(options));
    s.Set("gpgpnet", std::move(gpg)); // sic, as IceStatus spells it
    s.Set("relays", std::move(relays));
    return s;
  }

  // --- Peers -----------------------------------------------------------------

  void Bridge::NewGameSession()
  {
    // IceAdapter.createGameSession: a new session replaces the old one.
    if (!mPeers.empty()) {
      Log("new game session, closing " + std::to_string(mPeers.size()) + " links");
    }
    mPeers.clear();
    for (const auto& [id, peer] : mEnginePeers) {
      SendToGame({netlink::kCmdClose, {GpgArg::Int(static_cast<std::int32_t>(id))}});
    }
    mEnginePeers.clear();
    mGameEnded = false;
  }

  std::string Bridge::ConnectPeer(const std::int64_t id, const std::string& login, const bool offerer)
  {
    if (!mEngineLinks) {
      return mOptions.gameAddress + ":" + std::to_string(AddPeer(id, login, offerer));
    }
    // Issue #233: the game links; NetlinkPeer goes ahead of the command that
    // names the address, through the same queue.
    RemovePeer(id);
    EnginePeer& peer = mEnginePeers[id];
    peer = EnginePeer{};
    peer.login = login;
    peer.offerer = offerer;
    const std::string address = netlink::EngineAddressText(id);
    Log("peer " + login + "(" + std::to_string(id) + "): link in the game, " + (offerer ? "offerer" : "answerer") +
        ", game sends to " + address);
    SendToGame({netlink::kCmdPeer,
                {GpgArg::Int(static_cast<std::int32_t>(id)), GpgArg::Str(login), GpgArg::Int(offerer ? 1 : 0)}});
    return address;
  }

  void Bridge::SendEngineConfig()
  {
    JsonValue config = JsonValue::Object();
    config.Set("localId", mOptions.id);
    config.Set("iceServers", mIceServersJson);
    config.Set("forceRelay", mOptions.forceRelay);
    config.Set("bindAddress", mOptions.bindAddress);
    config.Set("duplicateMs", static_cast<std::int64_t>(mOptions.duplicateGapMs));
    config.Set("webrtc", mOptions.webrtc);
    config.Set("redundancy", static_cast<std::int64_t>(mOptions.redundancy));
    config.Set("testDropPercent", static_cast<std::int64_t>(mOptions.testDropPercent));
    SendToGame({netlink::kCmdConfig, {GpgArg::Str(netlink::WriteJson(config))}}, false);
  }

  bool Bridge::HandleEngineMessage(const GpgMessage& m)
  {
    if (m.command == netlink::kCmdHello) {
      const int version = m.args.empty() ? 0 : m.args[0].number;
      Log("the game runs the peer links itself (NetlinkHello " + std::to_string(version) + ")");
      mEngineLinks = true;
      SendEngineConfig();
      return true;
    }
    if (m.command == netlink::kCmdIceMsg && m.args.size() == 2) {
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(static_cast<std::int64_t>(m.args[0].number));
      p.Push(m.args[1].text);
      Notify("onIceMsg", std::move(p));
      return true;
    }
    if (m.command == netlink::kCmdState && m.args.size() == 3) {
      const std::int64_t id = m.args[0].number;
      const auto it = mEnginePeers.find(id);
      const bool connected = m.args[2].number != 0;
      const bool connectedChanged = it == mEnginePeers.end() || it->second.connected != connected;
      if (it != mEnginePeers.end()) {
        it->second.state = m.args[1].text;
        it->second.connected = connected;
      }
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(m.args[1].text);
      Notify("onIceConnectionStateChanged", std::move(p));
      if (connectedChanged) {
        JsonValue c = JsonValue::Array();
        c.Push(mOptions.id);
        c.Push(id);
        c.Push(connected);
        Notify("onConnected", std::move(c));
      }
      return true;
    }
    return m.command.rfind("Netlink", 0) == 0;
  }

  std::uint16_t Bridge::AddPeer(const std::int64_t id, const std::string& login, const bool offerer)
  {
    RemovePeer(id);
    auto peer = std::make_unique<Peer>();
    peer->id = id;
    peer->login = login;
    peer->offerer = offerer;
    // On the game's address: a socket bound to 127.0.0.1 cannot send to
    // another local address (WSAEADDRNOTAVAIL), so with --game-address the
    // game's datagrams never arrived.
    peer->udp = BindUdp(mOptions.gameAddress.c_str(), 0);
    if (peer->udp == kInvalidSocket) {
      Log("cannot open a UDP port on " + mOptions.gameAddress + " for peer " + std::to_string(id));
      return 0;
    }
    SetSocketBuffers(peer->udp, 2 * 1024 * 1024); // as Peer.initForwarding, adapter 3.3.15
    peer->port = LocalPort(peer->udp);

    netlink::LinkOptions lo;
    lo.localId = mOptions.id;
    lo.remoteId = id;
    lo.offerer = offerer;
    lo.iceServers = mIceServers;
    lo.forceRelay = mOptions.forceRelay;
    lo.bindAddress = mOptions.bindAddress;
    lo.duplicateGapMs = mOptions.duplicateGapMs;
    lo.webrtc = mOptions.webrtc;
    lo.redundancy = mOptions.redundancy;
    lo.testDropPercent = mOptions.testDropPercent;
    lo.ufragPrefix = netlink::kOurUfragPrefix;

    Peer* raw = peer.get();
    const std::string prefix = "peer " + login + "(" + std::to_string(id) + "): ";
    netlink::LinkCallbacks cb;
    cb.onSignal = [this, id](const netlink::CandidatesMessage& m) {
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(netlink::ToJson(m));
      Notify("onIceMsg", std::move(p));
    };
    cb.onSignalText = [this, id](const std::string& text) {
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(text);
      Notify("onIceMsg", std::move(p));
    };
    cb.onState = [this, id](const netlink::LinkState s) {
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(netlink::LinkStateName(s));
      Notify("onIceConnectionStateChanged", std::move(p));
    };
    cb.onConnected = [this, id](const bool connected) {
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(connected);
      Notify("onConnected", std::move(p));
    };
    // libjuice's thread: straight to the game's lobby port.
    cb.onData = [this, raw](const std::uint8_t* data, const std::size_t size) {
      {
        std::lock_guard lock(raw->countersMutex);
        raw->counters.OnReceived(data, size);
      }
      const sockaddr_in to = MakeAddress(mOptions.gameAddress.c_str(), mLobbyPort);
      sendto(raw->udp, reinterpret_cast<const char*>(data), static_cast<int>(size), 0,
             reinterpret_cast<const sockaddr*>(&to), sizeof(to));
      ++raw->toGame;
    };
    cb.onLog = [this, prefix](const std::string& t) { Log(prefix + t); };
    peer->link = std::make_unique<netlink::Link>(lo, std::move(cb));
    if (mGameEnded) {
      peer->link->SetGameEnded();
    }
    Log(prefix + (offerer ? "offerer" : "answerer") + ", game sends to " + mOptions.gameAddress + ":" + std::to_string(peer->port));
    peer->link->Start();
    const std::uint16_t port = peer->port;
    mPeers[id] = std::move(peer);
    return port;
  }

  void Bridge::RemovePeer(const std::int64_t id)
  {
    const auto it = mPeers.find(id);
    if (it == mPeers.end()) {
      return;
    }
    Peer& peer = *it->second;
    const bool wasConnected = peer.link->IsConnected();
    peer.link->Close(); // joins libjuice's thread before the socket goes
    LogStats(peer, "at close");
    CloseSocket(peer.udp);
    mPeers.erase(it);
    if (wasConnected) { // PeerIceModule.tearDown, adapter 3.3.15
      JsonValue p = JsonValue::Array();
      p.Push(mOptions.id);
      p.Push(id);
      p.Push(false);
      Notify("onConnected", std::move(p));
    }
  }

  void Bridge::ReadPeer(Peer& peer)
  {
    char buf[2048];
    for (;;) {
      sockaddr_in from{};
      socklen_t len = sizeof(from);
#ifdef _WIN32
      u_long avail = 0;
      if (ioctlsocket(peer.udp, FIONREAD, &avail) != 0 || avail == 0) {
        return;
      }
#endif
      const int n = recvfrom(peer.udp, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &len);
      if (n < 0) {
        return;
      }
      ++peer.fromGame;
      {
        std::lock_guard lock(peer.countersMutex);
        peer.counters.OnSent(reinterpret_cast<const unsigned char*>(buf), static_cast<std::size_t>(n));
      }
      peer.link->Send(buf, static_cast<std::size_t>(n));
#ifndef _WIN32
      return; // one per select round without FIONREAD
#endif
    }
  }

  void Bridge::LogStats(Peer& peer, const char* when)
  {
    const netlink::LinkStats ls = peer.link->GetStats();
    GameCounters c;
    {
      std::lock_guard lock(peer.countersMutex);
      c = peer.counters;
    }
    const std::uint64_t expected = c.received - c.repeats + c.lost;
    const double lossPercent = expected > 0 ? 100.0 * static_cast<double>(c.lost) / static_cast<double>(expected) : 0.0;
    char line[640];
    std::snprintf(line, sizeof(line),
                  "stats %s, peer %s(%lld) %s: rtt %.1f ms; to peer %llu datagrams, %llu game resends, %llu dropped "
                  "while not connected, %llu copies; from peer %llu datagrams, %llu lost (%.2f%%), %llu repeats, "
                  "%llu late",
                  when, peer.login.c_str(), static_cast<long long>(peer.id),
                  netlink::LinkStateName(peer.link->GetState()), ls.lastRttMs,
                  static_cast<unsigned long long>(c.sent), static_cast<unsigned long long>(c.dataResends),
                  static_cast<unsigned long long>(ls.dataDropped), static_cast<unsigned long long>(ls.duplicatesSent),
                  static_cast<unsigned long long>(c.received), static_cast<unsigned long long>(c.lost), lossPercent,
                  static_cast<unsigned long long>(c.repeats), static_cast<unsigned long long>(c.late));
    std::string text = line;
    if (ls.webRtcSent > 0 || ls.onWebRtc) {
      // Issue #239: how many of the datagrams to the peer took the data channel.
      text += "; " + std::to_string(ls.webRtcSent) + " sent on WebRTC" + (ls.onWebRtc ? " (open)" : " (closed)");
    }
    Log(text);
  }

  // --- GPGNet ----------------------------------------------------------------

  void Bridge::AcceptGpg()
  {
    SocketHandle s = accept(mGpgListen, nullptr, nullptr);
    if (s == kInvalidSocket) {
      return;
    }
    if (mGpgClient != kInvalidSocket) {
      // GPGNetServer: a new game connection replaces the old one.
      OnGpgLost();
    }
    int noDelay = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    mGpgClient = s;
    mGpgIn = GpgDecoder();
    Log("game connected over GPGNet");
    JsonValue p = JsonValue::Array();
    p.Push("Connected");
    Notify("onConnectionStateChanged", std::move(p));
  }

  void Bridge::ReadGpg()
  {
    char buf[16384];
    const int n = recv(mGpgClient, buf, sizeof(buf), 0);
    if (n <= 0) {
      OnGpgLost();
      return;
    }
    mGpgIn.Feed(buf, static_cast<std::size_t>(n));
    for (;;) {
      bool bad = false;
      std::optional<GpgMessage> m = mGpgIn.Next(&bad);
      if (bad) {
        Log("malformed GPGNet stream from the game");
        OnGpgLost();
        return;
      }
      if (!m) {
        return;
      }
      HandleGame(*m);
    }
  }

  void Bridge::OnGpgLost()
  {
    if (mGpgClient == kInvalidSocket) {
      return;
    }
    Log("GPGNet connection lost");
    CloseSocket(mGpgClient);
    mGameState.clear();
    mGameInLobby = false;
    JsonValue p = JsonValue::Array();
    p.Push("Disconnected");
    Notify("onConnectionStateChanged", std::move(p));
    // IceAdapter.onFAShutdown: the game session goes with the game.
    mPeers.clear();
    mEngineLinks = false;
    mEnginePeers.clear();
  }

  void Bridge::HandleGame(const GpgMessage& m)
  {
    Log("from game: " + DescribeGpg(m));
    if (HandleEngineMessage(m)) {
      return; // ours (issue #233), not the client's
    }
    if (m.command == "GameState" && !m.args.empty()) {
      mGameState = m.args[0].text;
      if (mGameState == "Idle") {
        // GPGNetServer: CreateLobby <init mode> <lobby port> <login> <id> 1.
        SendToGame({"CreateLobby",
                    {GpgArg::Int(mInitMode), GpgArg::Int(mLobbyPort), GpgArg::Str(mOptions.login),
                     GpgArg::Int(static_cast<std::int32_t>(mOptions.id)), GpgArg::Int(1)}},
                   false);
      } else if (mGameState == "Lobby") {
        mGameInLobby = true;
        std::vector<GpgMessage> queued;
        queued.swap(mForGame);
        for (const GpgMessage& q : queued) {
          WriteGame(q);
        }
      }
    } else if (m.command == "GameEnded") {
      mGameEnded = true;
      for (auto& [id, peer] : mPeers) {
        peer->link->SetGameEnded();
      }
      if (mEngineLinks) {
        SendToGame({netlink::kCmdGameEnded, {}}, false);
      }
      Log("GameEnded received, stopping reconnects");
    }
    JsonValue chunks = JsonValue::Array();
    for (const GpgArg& a : m.args) {
      if (a.kind == GpgArg::Kind::Int) {
        chunks.Push(static_cast<std::int64_t>(a.number));
      } else {
        chunks.Push(GameString(a.text));
      }
    }
    JsonValue p = JsonValue::Array();
    p.Push(m.command);
    p.Push(std::move(chunks));
    Notify("onGpgNetMessageReceived", std::move(p));
  }

  void Bridge::SendToGame(GpgMessage m, const bool waitForLobby)
  {
    // GPGNetServer.sendToGpgNet waits for the game's GameState Lobby.
    if (waitForLobby && (mGpgClient == kInvalidSocket || !mGameInLobby)) {
      mForGame.push_back(std::move(m));
      return;
    }
    WriteGame(m);
  }

  void Bridge::WriteGame(const GpgMessage& m)
  {
    if (mGpgClient == kInvalidSocket) {
      return;
    }
    const std::string bytes = EncodeGpg(m);
    if (!SendAll(mGpgClient, bytes.data(), bytes.size())) {
      OnGpgLost();
      return;
    }
    Log("to game: " + DescribeGpg(m));
  }
} // namespace faf::netbridge
