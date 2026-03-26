#include "CGpgNetInterface.h"

#include <cstring>
#include <mutex>
#include <stdexcept>
#include <vector>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "INetTCPServer.h"
#include "INetTCPSocket.h"
#include "moho/app/CWaitHandleSet.h"
#include "platform/Platform.h"

using namespace moho;

namespace
{
  std::mutex gGpgNetStateLock;
  boost::shared_ptr<CGpgNetInterface> gGpgNet;

  int32_t ExpectIntArg(CGpgNetInterface& owner, const SNetCommandArg* arg)
  {
    if (!arg || arg->mType != SNetCommandArg::NETARG_Num) {
      owner.ExpectedInt();
    }
    return arg->mNum;
  }

  void ReadExactFromSocket(INetTCPSocket* socket, char* out, const size_t size, const char* eofMessage)
  {
    size_t total = 0;
    while (total < size) {
      const size_t got = socket->Read(out + total, size - total);
      if (got == 0) {
        throw std::runtime_error(eofMessage);
      }
      total += got;
    }
  }

  LuaPlus::LuaObject GetTableField(const LuaPlus::LuaObject& table, const char* key)
  {
    LuaPlus::LuaObject out;
    if (table.IsNil() || !table.IsTable()) {
      return out;
    }

    LuaPlus::LuaState* const state = table.GetActiveState();
    if (!state) {
      return out;
    }

    lua_State* const luaState = state->GetCState();
    if (!luaState) {
      return out;
    }

    const int oldTop = lua_gettop(luaState);
    const_cast<LuaPlus::LuaObject&>(table).PushStack(luaState);
    lua_pushstring(luaState, key ? key : "");
    lua_gettable(luaState, -2);
    out = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, -1));
    lua_settop(luaState, oldTop);
    return out;
  }

  LuaPlus::LuaObject GetLobbyMethodOrThrow(const LuaPlus::LuaObject& lobbyObject, const char* methodName)
  {
    if (lobbyObject.IsNil()) {
      throw std::runtime_error("No lobby.");
    }

    LuaPlus::LuaObject methodObject = GetTableField(lobbyObject, methodName);
    if (methodObject.IsNil()) {
      throw std::runtime_error(
        gpg::STR_Printf("Lobby method \"%s\" is unavailable.", methodName ? methodName : "").c_str()
      );
    }

    return methodObject;
  }

  void LogUnknownCommand(const msvc8::string& commandName)
  {
    throw std::runtime_error(gpg::STR_Printf("Unknown GPGNET command \"%s\".", commandName.c_str()).c_str());
  }
} // namespace

void moho::GPGNET_SetPtr(const boost::shared_ptr<CGpgNetInterface>& ptr)
{
  std::lock_guard<std::mutex> lock(gGpgNetStateLock);
  gGpgNet = ptr;
}

boost::shared_ptr<moho::CGpgNetInterface> moho::GPGNET_GetPtr()
{
  std::lock_guard<std::mutex> lock(gGpgNetStateLock);
  return gGpgNet;
}

/**
 * Address: 0x007B9360 (FUN_007B9360, ?GPGNET_Attach@Moho@@YAXIG@Z)
 *
 * What it does:
 * Creates and connects the process-global GPGNet interface.
 */
void moho::GPGNET_Attach(const u_long addr, const u_short port)
{
  if (GPGNET_GetPtr()) {
    throw std::runtime_error("Can't attach to a gpg.net if we already are.");
  }

  boost::shared_ptr<CGpgNetInterface> created(new CGpgNetInterface{});
  created->Connect(addr, port);
  GPGNET_SetPtr(created);
}

/**
 * Address: 0x007BB590 (FUN_007BB590, ?GPGNET_Shutdown@Moho@@YAXXZ)
 *
 * What it does:
 * Shuts down and clears the process-global GPGNet interface pointer.
 */
void moho::GPGNET_Shutdown()
{
  boost::shared_ptr<CGpgNetInterface> active;
  {
    std::lock_guard<std::mutex> lock(gGpgNetStateLock);
    active.swap(gGpgNet);
  }

  if (active) {
    (void)active->Shutdown();
  }
}

/**
 * Address: 0x007B6800 (FUN_007B6800)
 *
 * What it does:
 * Initializes GPGNet task/provider state, creates queue event, and registers
 * the event with the global wait-handle set.
 */
CGpgNetInterface::CGpgNetInterface()
  : enable_shared_from_this()
  , mConnectionState(kNetStatePending)
  , mTcpServer(nullptr)
  , mTcpSocket(nullptr)
  , mCommands()
  , mQueueEvent(nullptr)
  , mConnectThreadWorker(nullptr)
  , mLobbyObject()
  , mNATHandler()
{
  mQueueEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->AddHandle(mQueueEvent);
    }
  }
}

/**
 * Address: 0x007B6900 (FUN_007B6900 non-deleting body)
 * Address: 0x007B68C0 (FUN_007B68C0 deleting wrapper)
 *
 * What it does:
 * Shuts down transport resources, unregisters the queue event, and releases
 * NAT-traversal callback ownership.
 */
CGpgNetInterface::~CGpgNetInterface()
{
  Shutdown();

  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->RemoveHandle(mQueueEvent);
    }
    CloseHandle(mQueueEvent);
    mQueueEvent = nullptr;
  }

  mNATHandler.reset();
}

/**
 * Address: 0x007B7680 (FUN_007B7680)
 *
 * What it does:
 * Closes active TCP endpoints, stops the connect worker thread, clears the
 * pending command queue, resets connection state, and resets queue event.
 */
bool CGpgNetInterface::Shutdown()
{
  if (mTcpSocket) {
    mTcpSocket->VirtClose(gpg::Stream::ModeBoth);
  }

  if (mTcpServer) {
    mTcpServer->CloseSocket();
  }

  if (mConnectThreadWorker) {
    mConnectThreadWorker->join();
    delete mConnectThreadWorker;
    mConnectThreadWorker = nullptr;
  }

  mCommands.clear();

  if (mTcpSocket) {
    delete mTcpSocket;
    mTcpSocket = nullptr;
  }

  if (mTcpServer) {
    delete mTcpServer;
    mTcpServer = nullptr;
  }

  mConnectionState = kNetStatePending;
  return mQueueEvent ? ResetEvent(mQueueEvent) != FALSE : true;
}

/**
 * Address: 0x007B9070 (FUN_007B9070)
 * Address: 0x10381F80 (sub_10381F80)
 *
 * What it does:
 * Updates weak NAT handler pointer used by SendNatPacket command path.
 */
void CGpgNetInterface::SetTraversalHandler(const int port, boost::shared_ptr<INetNATTraversalHandler>* handler)
{
  (void)port;
  boost::mutex::scoped_lock lock(mLock);
  gpg::Logf("GPGNET: setting nat handler to 0x%08x", reinterpret_cast<uintptr_t>(handler->get()));
  mNATHandler = *handler;
}

/**
 * Address: 0x007B9160 (FUN_007B9160)
 * Address: 0x10382070 (sub_10382070)
 *
 * What it does:
 * Wraps NAT payload into `ProcessNatPacket` command (`"ip:port"`, binary blob)
 * and forwards it to the GPGNet command stream.
 */
void CGpgNetInterface::ReceivePacket(const u_long address, u_short port, const char* data, size_t size)
{
  const auto ip = NET_GetDottedOctetFromUInt32(address);
  gpg::Logf("GPGNET: received nat packet from %s:%d", ip.c_str(), port);

  const msvc8::string connStr = gpg::STR_Printf("%s:%d", ip.c_str(), static_cast<int>(port));
  SNetCommandArg argFrom(connStr);

  msvc8::string blob;
  if (data && size) {
    blob.assign(data, size);
  }
  SNetCommandArg argData(blob);
  argData.mType = SNetCommandArg::NETARG_Data;

  WriteCommandWith2Args("ProcessNatPacket", &argFrom, &argData);
}

/**
 * Address: 0x007BB250 (FUN_007BB250)
 *
 * What it does:
 * Executes one command-queue processing pass and returns task continuation (`1`).
 */
int CGpgNetInterface::Execute()
{
  Process();
  return 1;
}

/**
 * Address: 0x007B65C0 (FUN_007B65C0)
 *
 * What it does:
 * Throws argument-type error for expected integer argument.
 */
void CGpgNetInterface::ExpectedInt() noexcept(false)
{
  throw std::runtime_error("incorrect argument type, expected int");
}

/**
 * Address: 0x007B6630 (FUN_007B6630)
 *
 * What it does:
 * Returns string payload reference or throws type-error if arg is not string.
 */
const msvc8::string& CGpgNetInterface::ExpectedString(const SNetCommandArg* arg) noexcept(false)
{
  if (arg->mType != SNetCommandArg::NETARG_String) {
    throw std::runtime_error("incorrect argument type, expected string");
  }
  return arg->mStr;
}

/**
 * Address: 0x007B66B0 (FUN_007B66B0)
 *
 * What it does:
 * Throws argument-type error for expected binary-data argument.
 */
void CGpgNetInterface::ExpectedData() noexcept(false)
{
  throw std::runtime_error("incorrect argument type, expected data");
}

/**
 * Address: 0x007B67A0 (FUN_007B67A0)
 *
 * What it does:
 * Enqueues a named command with zero arguments and explicit state value.
 */
void CGpgNetInterface::EnqueueCommand0(const char* str, int val)
{
  msvc8::vector<SNetCommandArg> args;
  EnqueueCommand(str, args, val);
}

/**
 * Address: 0x007B6A30 (FUN_007B6A30)
 *
 * What it does:
 * Starts async TCP connect worker and marks connection state as connecting.
 */
void CGpgNetInterface::Connect(const u_long address, const u_short port)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStatePending) {
    throw std::runtime_error("Already connected.");
  }

  mConnectionState = kNetStateConnecting;

  boost::thread* const thread = new boost::thread([this, address, port] {
    ConnectThread(address, port);
  });

  boost::thread* const oldThread = mConnectThreadWorker;
  mConnectThreadWorker = thread;
  if (oldThread) {
    oldThread->join();
    delete oldThread;
  }
}

/**
 * Address: 0x007B6DB0 (FUN_007B6DB0)
 *
 * What it does:
 * Writes a command name plus argument vector to active GPGNet socket stream.
 */
void CGpgNetInterface::WriteCommand(const char* name, const msvc8::vector<SNetCommandArg>& args)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  const uint32_t argc = static_cast<uint32_t>(args.size());
  mTcpSocket->Write(argc);

  for (const SNetCommandArg& arg : args) {
    WriteArg(&arg);
  }

  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6F00 (FUN_007B6F00)
 *
 * What it does:
 * Emits `BottleneckCleared` notification over active GPGNet command stream.
 */
void CGpgNetInterface::SendBottleneckCleared()
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName("BottleneckCleared");
  constexpr uint32_t argc = 0;
  mTcpSocket->Write(argc);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6FF0 (FUN_007B6FF0)
 *
 * What it does:
 * Writes command name with one serialized argument and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith1Arg(const char* name, const SNetCommandArg* arg)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);
  constexpr uint32_t argc = 1;
  mTcpSocket->Write(argc);
  WriteArg(arg);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B70F0 (FUN_007B70F0)
 *
 * What it does:
 * Writes command name with two serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith2Args(const char* name, const SNetCommandArg* arg1, const SNetCommandArg* arg2)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 2;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7200 (FUN_007B7200)
 *
 * What it does:
 * Writes command name with three serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith3Args(
  const char* name, const SNetCommandArg* arg1, const SNetCommandArg* arg2, const SNetCommandArg* arg3
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 3;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7310 (FUN_007B7310)
 *
 * What it does:
 * Writes command name with four serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith4Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2,
  const SNetCommandArg* arg3,
  const SNetCommandArg* arg4
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 4;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  WriteArg(arg4);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7420 (FUN_007B7420)
 *
 * What it does:
 * Writes command name as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteCommandName(const char* name)
{
  if (!mTcpSocket) {
    return;
  }

  const char* const value = name ? name : "";
  const uint32_t len = static_cast<uint32_t>(std::strlen(value));
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(value, len);
  }
}

/**
 * Address: 0x007B74A0 (FUN_007B74A0)
 *
 * What it does:
 * Writes `msvc8::string` payload as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteString(const msvc8::string& str)
{
  if (!mTcpSocket) {
    return;
  }

  const uint32_t len = static_cast<uint32_t>(str.size());
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(str.data(), len);
  }
}

/**
 * Address: 0x007B7520 (FUN_007B7520)
 *
 * What it does:
 * Serializes one `SNetCommandArg` as tagged payload (`type` + body).
 */
void CGpgNetInterface::WriteArg(const SNetCommandArg* arg)
{
  if (!mTcpSocket || !arg) {
    return;
  }

  const uint8_t type = static_cast<uint8_t>(arg->mType);
  mTcpSocket->Write(type);
  switch (arg->mType) {
  case SNetCommandArg::NETARG_Num:
    mTcpSocket->Write(arg->mNum);
    return;
  case SNetCommandArg::NETARG_String:
    WriteString(ExpectedString(arg));
    return;
  case SNetCommandArg::NETARG_Data:
    WriteString(arg->mStr);
    return;
  default:
    return;
  }
}

/**
 * Address: 0x007B7710 (FUN_007B7710 / func_GPGNETProcess)
 *
 * What it does:
 * Drains queued inbound commands, updates state from each command envelope,
 * and dispatches to command-specific handlers.
 */
void CGpgNetInterface::Process()
{
  msvc8::vector<SNetCommand> pending;

  {
    boost::mutex::scoped_lock lock(mLock);
    while (!mCommands.empty()) {
      pending.push_back(mCommands.front());
      mCommands.pop_front();
    }
    if (mQueueEvent) {
      ResetEvent(mQueueEvent);
    }
  }

  for (std::size_t i = 0; i < pending.size(); ++i) {
    SNetCommand& command = pending[i];
    mConnectionState = static_cast<DWORD>(command.mVal);

    try {
      const auto commandName = command.mName.view();
      if (commandName == "Test") {
        Test(command.mArgs);
      } else if (commandName == "Connected") {
        Connected(command.mArgs);
      } else if (commandName == "CreateLobby") {
        CreateLobby(command.mArgs);
      } else if (commandName == "HasSupcom") {
        HasSupCom(command.mArgs);
      } else if (commandName == "HasForgedAlliance") {
        HasForgedAlliance(command.mArgs);
      } else if (commandName == "HostGame") {
        HostGame(command.mArgs);
      } else if (commandName == "JoinGame") {
        JoinGame(command.mArgs);
      } else if (commandName == "ConnectToPeer") {
        ConnectToPeer(command.mArgs);
      } else if (commandName == "DisconnectFromPeer") {
        DisconnectFromPeer(command.mArgs);
      } else if (commandName == "SendNatPacket") {
        SendNatPacket(command.mArgs);
      } else if (commandName == "EjectPlayer") {
        EjectPlayer(command.mArgs);
      } else {
        LogUnknownCommand(command.mName);
      }
    } catch (const std::exception& ex) {
      gpg::Logf("GPGNET: command processing failed: %s", ex.what());
    }
  }
}

/**
 * Address: 0x007B7A30 (FUN_007B7A30)
 *
 * What it does:
 * Logs diagnostic dump for Test command arguments.
 */
void CGpgNetInterface::Test(msvc8::vector<SNetCommandArg>& args)
{
  gpg::Logf("GPGNET: test message, %d args", static_cast<int>(args.size()));

  for (std::size_t i = 0; i < args.size(); ++i) {
    const SNetCommandArg& arg = args[i];
    switch (arg.mType) {
    case SNetCommandArg::NETARG_Num:
      gpg::Logf(" arg[%d]=%d [int]", static_cast<int>(i), arg.mNum);
      break;
    case SNetCommandArg::NETARG_String:
      gpg::Logf(" arg[%d]=\"%s\" [str]", static_cast<int>(i), arg.mStr.c_str());
      break;
    case SNetCommandArg::NETARG_Data: {
      msvc8::string hexDump;
      for (std::size_t b = 0; b < arg.mStr.size(); ++b) {
        if (b != 0) {
          hexDump.append(1, ' ');
        }
        const auto chunk = gpg::STR_Printf("%02x", static_cast<unsigned char>(arg.mStr[b]));
        hexDump.append(chunk.data(), chunk.size());
      }
      gpg::Logf(" arg[%d]={%s}", static_cast<int>(i), hexDump.c_str());
      break;
    }
    default:
      gpg::Logf(" arg[%d]=? [unknown type %d]", static_cast<int>(i), static_cast<int>(arg.mType));
      break;
    }
  }
}

/**
 * Address: 0x007B7C50 (FUN_007B7C50)
 *
 * What it does:
 * Verifies empty argument list and sends `GameState = "Idle"` to GPGNet.
 */
void CGpgNetInterface::Connected(msvc8::vector<SNetCommandArg>& args)
{
  if (!args.empty()) {
    throw std::runtime_error("Wrong number of arguments to Connected command, expected 0");
  }

  gpg::Logf("GPGNET: entering idle state.");
  SNetCommandArg stateArg(msvc8::string("Idle"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007B7DE0 (FUN_007B7DE0)
 *
 * What it does:
 * Calls Lua-side `CreateLobby` factory and stores returned lobby object.
 *
 * Note:
 * NAT traversal object argument is currently passed as `nil` until
 * `NET_MakeNATTraversal` binding is fully reconstructed.
 */
void CGpgNetInterface::CreateLobby(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 5) {
    throw std::runtime_error("Wrong number of arguments to CreateLobby command, expected 5");
  }

  if (!mLobbyObject.IsNil()) {
    throw std::runtime_error("Lobby already exists.");
  }

  LuaPlus::LuaState* const state = LuaPlus::g_ConsoleLuaState();
  if (!state) {
    throw std::runtime_error("No active Lua state.");
  }

  LuaPlus::LuaObject createLobby = state->GetGlobal("CreateLobby");
  if (createLobby.IsNil()) {
    throw std::runtime_error("Failed to load \"/lua/multiplayer/onlineprovider.lua\".");
  }

  const bool useUdp = ExpectIntArg(*this, &args[0]) != 0;
  const int localPort = ExpectIntArg(*this, &args[1]);
  const msvc8::string& playerName = ExpectedString(&args[2]);
  const int playerUid = ExpectIntArg(*this, &args[3]);
  const int natPort = ExpectIntArg(*this, &args[4]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  LuaPlus::LuaFunction<LuaPlus::LuaObject> createLobbyFn(createLobby);
  mLobbyObject = createLobbyFn(
    useUdp, localPort, playerName.c_str(), playerUidText.c_str(), static_cast<LuaPlus::LuaObject*>(nullptr), natPort
  );

  gpg::Logf("GPGNET: entering lobby state.");
  SNetCommandArg stateArg(msvc8::string("Lobby"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007B81D0 (FUN_007B81D0)
 *
 * What it does:
 * Invokes lobby `HostGame` script callback with optional scenario path.
 */
void CGpgNetInterface::HostGame(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() > 1) {
    throw std::runtime_error("Wrong number of arguments to HostGame command, expected 0 or 1");
  }

  LuaPlus::LuaObject hostGameObj = GetLobbyMethodOrThrow(mLobbyObject, "HostGame");
  LuaPlus::LuaFunction<void> hostGame(hostGameObj);

  msvc8::string scenarioPath;
  if (!args.empty()) {
    const msvc8::string& mapName = ExpectedString(&args[0]);
    scenarioPath = gpg::STR_Printf("/maps/%s/%s_scenario.lua", mapName.c_str(), mapName.c_str());
  }

  hostGame(scenarioPath.c_str());
}

/**
 * Address: 0x007B83C0 (FUN_007B83C0)
 *
 * What it does:
 * Invokes lobby `JoinGame` script callback with host/player/uid parameters.
 */
void CGpgNetInterface::JoinGame(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to JoinGame command, expected 3");
  }

  LuaPlus::LuaObject joinGameObj = GetLobbyMethodOrThrow(mLobbyObject, "JoinGame");
  LuaPlus::LuaFunction<void> joinGame(joinGameObj);

  const msvc8::string& hostAddress = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int playerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  joinGame(hostAddress.c_str(), false, playerName.c_str(), playerUidText.c_str());
}

/**
 * Address: 0x007B85A0 (FUN_007B85A0)
 *
 * What it does:
 * Invokes lobby `ConnectToPeer` script callback.
 */
void CGpgNetInterface::ConnectToPeer(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to ConnectToPeer command, expected 3");
  }

  LuaPlus::LuaObject connectToPeerObj = GetLobbyMethodOrThrow(mLobbyObject, "ConnectToPeer");
  LuaPlus::LuaFunction<void> connectToPeer(connectToPeerObj);

  const msvc8::string& endpoint = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int peerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);

  connectToPeer(endpoint.c_str(), playerName.c_str(), peerUidText.c_str());
}

/**
 * Address: 0x007B8780 (FUN_007B8780)
 *
 * What it does:
 * Invokes lobby `DisconnectFromPeer` script callback for one uid.
 */
void CGpgNetInterface::DisconnectFromPeer(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to DisconnectFromPeer command, expected 1");
  }

  LuaPlus::LuaObject disconnectObj = GetLobbyMethodOrThrow(mLobbyObject, "DisconnectFromPeer");
  LuaPlus::LuaFunction<void> disconnectFromPeer(disconnectObj);

  const int peerUid = ExpectIntArg(*this, &args[0]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);
  disconnectFromPeer(peerUidText.c_str());
}

/**
 * Address: 0x007B8920 (FUN_007B8920)
 *
 * What it does:
 * Invokes lobby `SetHasSupcom` script callback.
 */
void CGpgNetInterface::HasSupCom(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasSupcom command, expected 1");
  }

  LuaPlus::LuaObject hasSupComObj = GetLobbyMethodOrThrow(mLobbyObject, "SetHasSupcom");
  LuaPlus::LuaFunction<void> setHasSupCom(hasSupComObj);
  setHasSupCom(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8A70 (FUN_007B8A70)
 *
 * What it does:
 * Invokes lobby `SetHasForgedAlliance` script callback.
 */
void CGpgNetInterface::HasForgedAlliance(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasForgedAlliance command, expected 1");
  }

  LuaPlus::LuaObject hasFaObj = GetLobbyMethodOrThrow(mLobbyObject, "SetHasForgedAlliance");
  LuaPlus::LuaFunction<void> setHasFa(hasFaObj);
  setHasFa(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8BC0 (FUN_007B8BC0)
 *
 * What it does:
 * Validates NAT command args (`"ip:port"`, binary payload), resolves remote
 * endpoint, and forwards payload through registered NAT traversal handler.
 */
void CGpgNetInterface::SendNatPacket(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 2) {
    throw std::runtime_error("Wrong number of arguments to SendNatPacket command, expected 2");
  }

  const auto natHandler = mNATHandler.lock();
  if (!natHandler) {
    throw std::runtime_error("Can't send nat packets if we don't have a nat handler.");
  }

  const msvc8::string& endpoint = ExpectedString(&args[0]);

  u_long remoteAddress = 0;
  u_short remotePort = 0;
  if (!NET_GetAddrInfo(endpoint.c_str(), 0, false, remoteAddress, remotePort) || remotePort == 0) {
    throw std::runtime_error("Invalid remote address");
  }

  const auto& payloadArg = args[1];
  if (payloadArg.mType != SNetCommandArg::NETARG_Data) {
    ExpectedData();
  }

  const auto remoteHost = NET_GetDottedOctetFromUInt32(remoteAddress);
  gpg::Logf("GPGNET: sending nat packet to %s:%d", remoteHost.c_str(), static_cast<int>(remotePort));

  natHandler->ReceivePacket(remoteAddress, remotePort, payloadArg.mStr.data(), payloadArg.mStr.size());
}

/**
 * Address: 0x007B8E20 (FUN_007B8E20)
 *
 * What it does:
 * Validates eject request and forwards to lobby script method when available.
 *
 * Note:
 * Full CSimDriver-backed eject path is still pending reconstruction.
 */
void CGpgNetInterface::EjectPlayer(msvc8::vector<SNetCommandArg>& args)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to EjectPlayer, expected 1");
  }

  const int playerUid = ExpectIntArg(*this, &args[0]);

  if (!mLobbyObject.IsNil()) {
    LuaPlus::LuaObject ejectObj = GetTableField(mLobbyObject, "EjectPlayer");
    if (!ejectObj.IsNil()) {
      LuaPlus::LuaFunction<void> ejectPlayer(ejectObj);
      ejectPlayer(playerUid);
      return;
    }
  }

  throw std::runtime_error("EjectPlayer path requires CSimDriver mapping and is not fully reconstructed yet.");
}

/**
 * Address: 0x007BA5E0 (FUN_007BA5E0)
 *
 * What it does:
 * Performs synchronous TCP connect and starts inbound socket read loop.
 */
void CGpgNetInterface::ConnectThread(const u_long address, const u_short port)
{
  INetTCPSocket* const connectedSocket = NET_TCPConnect(address, port);
  INetTCPSocket* const oldSocket = mTcpSocket;
  mTcpSocket = connectedSocket;
  if (oldSocket) {
    delete oldSocket;
  }

  if (mTcpSocket) {
    ReadFromSocket();
  } else {
    EnqueueCommand0("ConnectFailed", kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BA880 (FUN_007BA880)
 *
 * What it does:
 * Reads and decodes framed commands from TCP stream and enqueues them for
 * pull-task dispatch.
 */
void CGpgNetInterface::ReadFromSocket()
{
  if (!mTcpSocket) {
    return;
  }

  EnqueueCommand0("Connected", kNetStateEstablishing);

  try {
    for (;;) {
      uint32_t commandNameLength = 0;
      const size_t got = mTcpSocket->Read(reinterpret_cast<char*>(&commandNameLength), sizeof(commandNameLength));
      if (got == 0) {
        EnqueueCommand0("ConnectionShutdown", kNetStateEstablishing);
        return;
      }
      if (got < sizeof(commandNameLength)) {
        throw std::runtime_error("premature EOF reading from gpg.net socket");
      }

      msvc8::string commandName;
      if (commandNameLength != 0) {
        std::vector<char> nameBuffer(commandNameLength);
        ReadExactFromSocket(
          mTcpSocket, nameBuffer.data(), commandNameLength, "premature EOF reading from gpg.net socket"
        );
        commandName.assign(nameBuffer.data(), commandNameLength);
      }

      gpg::BinaryReader reader(mTcpSocket);
      uint32_t argCount = 0;
      reader.ReadExact(argCount);

      msvc8::vector<SNetCommandArg> args;
      if (argCount) {
        args.reserve(argCount);
      }

      for (uint32_t i = 0; i < argCount; ++i) {
        uint8_t typeCode = 0;
        reader.ReadExact(typeCode);

        switch (typeCode) {
        case 0: {
          int32_t value = 0;
          reader.ReadExact(value);
          args.push_back(SNetCommandArg(value));
          break;
        }
        case 1:
        case 2: {
          uint32_t payloadLen = 0;
          reader.ReadExact(payloadLen);

          msvc8::string payload;
          if (payloadLen != 0) {
            std::vector<char> payloadBuffer(payloadLen);
            reader.Read(payloadBuffer.data(), payloadLen);
            payload.assign(payloadBuffer.data(), payloadLen);
          }

          SNetCommandArg arg(payload);
          if (typeCode == 2) {
            arg.mType = SNetCommandArg::NETARG_Data;
          }
          args.push_back(arg);
          break;
        }
        default:
          throw std::runtime_error("invalid arg typecode");
        }
      }

      EnqueueCommand(commandName.c_str(), args, kNetStateEstablishing);
    }
  } catch (const std::exception& ex) {
    msvc8::vector<SNetCommandArg> args;
    args.push_back(SNetCommandArg(msvc8::string(ex.what() ? ex.what() : "communication error")));
    EnqueueCommand("CommunicationError", args, kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BAE50 (FUN_007BAE50)
 *
 * What it does:
 * Queues one decoded command and signals queue event if queue transitions
 * from empty to non-empty.
 */
void CGpgNetInterface::EnqueueCommand(const char* name, msvc8::vector<SNetCommandArg>& args, int val)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mCommands.empty() && mQueueEvent) {
    SetEvent(mQueueEvent);
  }

  SNetCommand command{};
  command.mName = msvc8::string(name ? name : "");
  command.mArgs = args;
  command.mVal = val;
  mCommands.push_back(command);
}
