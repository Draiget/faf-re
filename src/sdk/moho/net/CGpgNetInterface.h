#pragma once
#include "boost/enable_shared_from_this.h"
#include "boost/mutex.h"
#include "boost/recursive_mutex.h"
#include "boost/shared_ptr.h"
#include "boost/thread.h"
#include "boost/weak_ptr.h"
#include "gpg/core/utils/Sync.h"
#include "INetNATTraversalProvider.h"
#include "legacy/containers/Deque.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinderFwd.h"
#include "moho/task/CTask.h"

struct lua_State;

namespace moho
{
  class INetTCPSocket;
  class INetTCPServer;
  struct SClientBottleneckInfo;

  struct SNetCommandArg
  {
    enum EType
    {
      NETARG_Num = 0x0,
      NETARG_String = 0x1,
      NETARG_Data = 0x2,
    };

    EType mType{NETARG_Num};
    int32_t mNum{0};
    msvc8::string mStr{};

    explicit SNetCommandArg(
      const int32_t num
    )
      : mType{NETARG_Num}
      , mNum{num}
    {}

    explicit SNetCommandArg(
      const msvc8::string& str
    )
      : mType{NETARG_String}
      , mNum{0}
      , mStr{str}
    {}
  };
  static_assert(sizeof(SNetCommandArg) == 0x24, "SNetCommandArg size must be 0x24");

  struct SNetCommand
  {
    msvc8::string mName;
    msvc8::vector<SNetCommandArg> mArgs;
    int mVal{0};

    /**
     * Address: 0x007B6720 (FUN_007B6720, ??0SNetCommand@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one queued command entry with copied name, argument vector,
     * and value lanes.
     */
    SNetCommand(const char* name, const msvc8::vector<SNetCommandArg>& args, int val);

    /**
     * Address: 0x007BAEF0 (FUN_007BAEF0, ??1SNetCommand@Moho@@QAE@@Z)
     *
     * What it does:
     * Destroys argument/vector storage and string payload lanes for one queued
     * command entry.
     */
    ~SNetCommand();
  };
  static_assert(sizeof(SNetCommand) == 0x30, "SNetCommand size must be 0x30");

  class CGpgNetInterface :
    public CPullTask<CGpgNetInterface>,
    public INetNATTraversalProvider,
    public boost::enable_shared_from_this<CGpgNetInterface>
  {
  public:
    /**
     * Address: 0x007B6800
     */
    CGpgNetInterface();

    /**
     * Address: 0x007BCA70 (FUN_007BCA70, Moho::CGpgNetInterface::CreatePtr)
     *
     * What it does:
     * Creates one owning `boost::shared_ptr<CGpgNetInterface>` from a raw
     * instance pointer and binds `enable_shared_from_this` ownership lanes.
     */
    [[nodiscard]] static boost::shared_ptr<CGpgNetInterface> CreatePtr(CGpgNetInterface* inter);

    /**
     * Address: 0x007B68C0 (FUN_007B68C0 deleting wrapper)
     * Address: 0x007B6900 (FUN_007B6900 non-deleting body)
     * Slot: 2
     */
    ~CGpgNetInterface() override;

    /**
     * Address: 0x007B7680
     * @return
     */
    bool Shutdown();

    /**
     * Address: 0x007B9070 (FUN_007B9070)
     * Address: 0x10381F80 (sub_10381F80)
     * Slot: 0
     *
     * What it does:
     * Stores NAT traversal handler weak-pointer for SendNatPacket command path.
     */
    void SetTraversalHandler(int port, boost::shared_ptr<INetNATTraversalHandler>* handler) override;

    /**
     * Address: 0x007B9160 (FUN_007B9160)
     * Address: 0x10382070 (sub_10382070)
     * Slot: 1
     *
     * What it does:
     * Wraps NAT payload into GPGNet `ProcessNatPacket` command arguments.
     */
    void ReceivePacket(u_long address, u_short port, const char* dat, size_t size) override;

    /**
     * Address: 0x007BB250 (FUN_007BB250)
     * Slot: 3
     *
     * What it does:
     * Runs one queued-command drain pass and returns task-continue flag (`1`).
     */
    int Execute() override;

    /**
     * Address: 0x007B65C0 (FUN_007B65C0)
     *
     * What it does:
     * Throws argument-type error for expected integer argument.
     */
    void ExpectedInt() noexcept(false);

    /**
     * Address: 0x007B6630 (FUN_007B6630)
     *
     * What it does:
     * Returns string payload reference or throws type-error if arg is not string.
     */
    const msvc8::string& ExpectedString(const SNetCommandArg* arg) noexcept(false);

    /**
     * Address: 0x007B66B0 (FUN_007B66B0)
     *
     * What it does:
     * Throws argument-type error for expected binary-data argument.
     */
    void ExpectedData() noexcept(false);

    /**
     * Address: 0x007B67A0 (FUN_007B67A0)
     *
     * What it does:
     * Enqueues a named command with zero arguments and explicit value.
     */
    void EnqueueCommand0(const char* str, int val);

    /**
     * Address: 0x007B6A30
     *
     * @param address
     * @param port
     */
    void Connect(u_long address, u_short port);

    /**
     * Address: 0x007B6DB0
     *
     * @param name
     * @param args
     */
    void WriteCommand(const char* name, const msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B6F00
     */
    void SendBottleneckCleared();

    /**
     * Address: 0x007B6FF0
     *
     * @param name
     * @param arg
     */
    void WriteCommandWith1Arg(const char* name, const SNetCommandArg* arg);

    /**
     * Address: 0x007B70F0 (FUN_007B70F0)
     *
     * @param name
     * @param arg1
     * @param arg2
     */
    void WriteCommandWith2Args(const char* name, const SNetCommandArg* arg1, const SNetCommandArg* arg2);

    /**
     * Address: 0x007B7200 (FUN_007B7200)
     *
     * @param name
     * @param arg1
     * @param arg2
     * @param arg3
     */
    void WriteCommandWith3Args(
      const char* name,
      const SNetCommandArg* arg1,
      const SNetCommandArg* arg2,
      const SNetCommandArg* arg3
    );

    /**
     * Address: 0x007B7310 (FUN_007B7310)
     *
     * @param name
     * @param arg1
     * @param arg2
     * @param arg3
     * @param arg4
     */
    void WriteCommandWith4Args(
      const char* name,
      const SNetCommandArg* arg1,
      const SNetCommandArg* arg2,
      const SNetCommandArg* arg3,
      const SNetCommandArg* arg4
    );

    /**
     * Address: 0x007B7420 (FUN_007B7420)
     *
     * @param name
     */
    void WriteCommandName(const char* name);

    /**
     * Address: 0x007B74A0 (FUN_007B74A0)
     *
     * @param str
     */
    void WriteString(const msvc8::string& str);

    /**
     * Address: 0x007B7520 (FUN_007B7520)
     *
     * @param arg
     */
    void WriteArg(const SNetCommandArg* arg);

    /**
     * Address: 0x007B7710
     */
    void Process();

    /**
     * Address: 0x007B7A30
     *
     * @param args
     */
    void Test(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B7C50
     *
     * @param args
     */
    void Connected(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B7DE0
     *
     * @param args
     */
    void CreateLobby(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B81D0
     *
     * @param args
     */
    void HostGame(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B83C0
     *
     * @param args
     */
    void JoinGame(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B85A0
     *
     * @param args
     */
    void ConnectToPeer(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B8780
     *
     * @param args
     */
    void DisconnectFromPeer(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B8920
     *
     * @param args
     */
    void HasSupCom(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B8A70
     *
     * @param args
     */
    void HasForgedAlliance(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B8BC0 (FUN_007B8BC0)
     *
     * What it does:
     * Validates NAT command args (`"ip:port"`, binary payload), resolves remote
     * endpoint, and forwards payload through registered NAT traversal handler.
     *
     * @param args
     */
    void SendNatPacket(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007B8E20 (FUN_007B8E20)
     *
     * What it does:
     * Resolves target client from active sim driver and executes local
     * disconnect or remote eject with localized console messaging.
     *
     * @param args
     */
    void EjectPlayer(msvc8::vector<SNetCommandArg>& args);

    /**
     * Address: 0x007BA5E0
     *
     * @param address
     * @param port
     */
    void ConnectThread(u_long address, u_short port);

    /**
     * Address: 0x007BA880 (FUN_007BA880)
     *
     * What it does:
     * Reads and decodes GPGNet command frames from active TCP socket.
     */
    void ReadFromSocket();

    /**
     * Address: 0x007BAE50 (FUN_007BAE50)
     *
     * @param name
     * @param args
     * @param val
     */
    void EnqueueCommand(const char* name, msvc8::vector<SNetCommandArg>& args, int val);

  private:
    // boost::shared_ptr<CGpgNetInterface> mSelf;
    boost::mutex mLock;
    DWORD mConnectionState{0};
    INetTCPServer* mTcpServer{nullptr};
    INetTCPSocket* mTcpSocket{nullptr};
    msvc8::deque<SNetCommand> mCommands;
    HANDLE mQueueEvent{nullptr};
    boost::thread* mConnectThreadWorker{nullptr};
    LuaPlus::LuaObject mLobbyObject;
    boost::weak_ptr<INetNATTraversalHandler> mNATHandler;
  };
  static_assert(sizeof(CGpgNetInterface) == 0x70, "CGpgNetInterface size must be 0x70");

  /**
   * Address: 0x007B9470 (FUN_007B9470, Moho::GPGNET_SetPtr)
   *
   * What it does:
   * Replaces the process-global GPGNet shared-pointer lane (`sGPGNet`).
   */
  void GPGNET_SetPtr(const boost::shared_ptr<CGpgNetInterface>& ptr);

  /**
   * What it does:
   * Returns the active process-global GPGNet interface pointer.
   */
  [[nodiscard]] boost::shared_ptr<CGpgNetInterface> GPGNET_GetPtr();

  /**
   * Address: 0x007B94C0 (FUN_007B94C0, ?GPGNET_ReportBottleneck@Moho@@YAXABUSClientBottleneckInfo@1@@Z)
   *
   * What it does:
   * Formats one bottleneck report payload and sends `"Bottleneck"` through
   * the active process-global GPGNet interface.
   */
  void GPGNET_ReportBottleneck(const SClientBottleneckInfo& info);

  /**
   * Address: 0x007B9A20 (FUN_007B9A20, Moho::GPGNET_ReportBottleneckCleared)
   *
   * What it does:
   * Sends one `"BottleneckCleared"` command through the active process-global
   * GPGNet interface pointer (when available).
   */
  void GPGNET_ReportBottleneckCleared();

  /**
   * Address: 0x007B9AC0 (FUN_007B9AC0, Moho::GPGNET_ReportDesync)
   *
   * What it does:
   * Sends one `"Desync"` command with `(beat, army, hash1, hash2)` payload over
   * the active process-global GPGNet interface (when available).
   */
  void GPGNET_ReportDesync(int beat, int army, const msvc8::string& hash1, const msvc8::string& hash2);

  /**
   * Address: 0x007B9CD0 (FUN_007B9CD0, Moho::GPGNET_SubmitArmyStats)
   *
   * What it does:
   * Sends one `"Stats"` command with the provided army-stats payload through
   * the active process-global GPGNet interface (when available).
   */
  void GPGNET_SubmitArmyStats(const msvc8::string& statsPayload);

  /**
   * Address: 0x007B9360 (FUN_007B9360, ?GPGNET_Attach@Moho@@YAXIG@Z)
   *
   * What it does:
   * Creates and connects the process-global GPGNet interface.
   */
  void GPGNET_Attach(u_long addr, u_short port);

  /**
   * Address: 0x007B9DD0 (FUN_007B9DD0, ?GPGNET_Shutdown@Moho@@YAXXZ thunk)
   * Address: 0x007BB590 (FUN_007BB590, ?GPGNET_Shutdown@Moho@@YAXXZ body)
   *
   * What it does:
   * Clears the process-global GPGNet interface shared-pointer lane.
   */
  void GPGNET_Shutdown();

  /**
   * Address: 0x007B9DE0 (FUN_007B9DE0, cfunc_GpgNetActive)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetActiveL`.
   */
  int cfunc_GpgNetActive(lua_State* luaContext);

  /**
   * Address: 0x007B9E00 (FUN_007B9E00, func_GpgNetActive_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GpgNetActive()` Lua binder in the user init set.
   */
  CScrLuaInitForm* func_GpgNetActive_LuaFuncDef();

  /**
   * Address: 0x007B9E60 (FUN_007B9E60, cfunc_GpgNetActiveL)
   *
   * What it does:
   * Validates no Lua args and pushes whether a process-global GPGNet
   * interface pointer is active.
   */
  int cfunc_GpgNetActiveL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007B9EB0 (FUN_007B9EB0, cfunc_GpgNetSend)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetSendL`.
   */
  int cfunc_GpgNetSend(lua_State* luaContext);

  /**
   * Address: 0x007B9ED0 (FUN_007B9ED0, func_GpgNetSend_LuaFuncDef)
   *
   * What it does:
   * Publishes global `GpgNetSend(command, args...)` Lua binder in the user
   * init set.
   */
  CScrLuaInitForm* func_GpgNetSend_LuaFuncDef();

  /**
   * Address: 0x007B9F30 (FUN_007B9F30, cfunc_GpgNetSendL)
   *
   * What it does:
   * Validates and marshals Lua args into `SNetCommandArg` lanes, then sends
   * one command through active process-global GPGNet interface (if present).
   */
  int cfunc_GpgNetSendL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007BA2C0 (FUN_007BA2C0, cfunc_LaunchGPGNet)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_LaunchGPGNetL`.
   */
  int cfunc_LaunchGPGNet(lua_State* luaContext);

  /**
   * Address: 0x007BA2E0 (FUN_007BA2E0, func_LaunchGPGNet_LuaFuncDef)
   *
   * What it does:
   * Publishes global `LaunchGPGNet()` binder into the user Lua init set.
   */
  CScrLuaInitForm* func_LaunchGPGNet_LuaFuncDef();

  /**
   * Address: 0x007BA340 (FUN_007BA340, cfunc_LaunchGPGNetL)
   *
   * What it does:
   * Resolves the GPGNet client executable path (dev override, registry,
   * fallback) and launches it via `ShellExecuteExW`, pushing the boolean
   * launch result back to Lua.
   */
  int cfunc_LaunchGPGNetL(LuaPlus::LuaState* state);
} // namespace moho
