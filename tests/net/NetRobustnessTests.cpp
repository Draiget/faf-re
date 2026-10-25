// Robustness tests for the code that parses what other players send: the Lua
// byte-stream decoder, message framing, the command-stream decoder, client
// control messages and the lobby. Each test feeds malformed input straight to
// the engine's own functions and checks that it is refused cleanly (nothing
// escapes, nothing reaches the sink, the Lua stack is left as it was), and that
// the matching well-formed input still goes through.
//
// Build: cmake --build --preset clang-x64-release --target faf_net_tests
// Run:   build\clang-x64-release\tests\faf_net_tests.exe   (exit code = failures)

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <limits>
#include <random>
#include <string>
#include <vector>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "lua/LuaObject.h"
#include "lua/LuaParser.h"
#include "lua/LuaPrimitives.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CVFSImpl.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/command/ICommandSink.h"
#include "moho/command/SSTITarget.h"
#include "moho/misc/CDecoder.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/net/CLobby.h"
#include "moho/net/CMessage.h"
#include "moho/net/CNetClient.h"
#include "moho/net/EClientMsg.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/ELobbyMsg.h"
#include "gpg/core/algorithms/SHA256.h"
#include "moho/net/CommandStreamCheck.h"
#include "moho/net/IClientMgrUIInterface.h"
#include "moho/net/NetConVars.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"
#include "moho/net/SPeer.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/WldSessionInfo.h"

using namespace moho;

namespace
{
  // --- Harness ---------------------------------------------------------------------------

  int gFailures = 0;
  int gChecks = 0;

#define CHECK(cond)                                                                \
  do {                                                                             \
    ++gChecks;                                                                     \
    if (!(cond)) {                                                                 \
      ++gFailures;                                                                 \
      std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                \
    }                                                                              \
  } while (0)

  struct TestCase
  {
    const char* name;
    void (*body)();
  };

  void RunTest(const TestCase& test)
  {
    const int failuresBefore = gFailures;
    try {
      test.body();
    } catch (const std::exception& e) {
      ++gFailures;
      std::printf("  FAIL %s: exception escaped: %s\n", test.name, e.what());
    } catch (...) {
      ++gFailures;
      std::printf("  FAIL %s: non-std exception escaped\n", test.name);
    }
    std::printf("%s %s\n", gFailures == failuresBefore ? "ok  " : "FAIL", test.name);
    std::fflush(stdout);
  }

  // --- Byte building -----------------------------------------------------------------------

  struct Bytes
  {
    std::string data;

    template <class T>
    Bytes& Put(const T& value)
    {
      data.append(reinterpret_cast<const char*>(&value), sizeof(value));
      return *this;
    }
    Bytes& U8(std::uint8_t v) { return Put(v); }
    Bytes& I32(std::int32_t v) { return Put(v); }
    Bytes& U32(std::uint32_t v) { return Put(v); }
    Bytes& F32(float v) { return Put(v); }
    Bytes& Str(const char* s)
    {
      data.append(s, std::strlen(s) + 1);
      return *this;
    }
    Bytes& Raw(const std::string& s)
    {
      data += s;
      return *this;
    }
  };

  // SCR byte-stream values (LuaObject::ToByteStream's tags).
  std::string LuaNumber(const float v) { return Bytes{}.U8(0).F32(v).data; }
  std::string LuaString(const char* s) { return Bytes{}.U8(1).Str(s).data; }
  std::string LuaNil() { return std::string(1, '\x02'); }
  std::string LuaTable(const std::string& entries) { return "\x04" + entries + "\x05"; }

  // `depth` tables, each the value of key "k" in the one around it.
  std::string LuaNested(const int depth)
  {
    std::string out;
    for (int i = 1; i < depth; ++i) {
      out += "\x04" + LuaString("k");
    }
    out += "\x04\x05";
    out.append(static_cast<std::size_t>(depth - 1), '\x05');
    return out;
  }

  template <class E>
  CMessage MakeMessage(const E type, const std::string& payload)
  {
    CMessage msg(type);
    if (!payload.empty()) {
      msg.Append(payload.data(), payload.size());
    }
    return msg;
  }

  // --- Lua decoding ------------------------------------------------------------------------

  LuaPlus::LuaState& TestLuaState()
  {
    static LuaPlus::LuaState state(LuaPlus::LuaState::LIB_BASE);
    return state;
  }

  enum class DecodeMode
  {
    Network,
    Local
  };

  // Decodes `bytes`; returns whether it succeeded. Checks the Lua stack is left
  // as it was either way.
  bool Decode(const std::string& bytes, LuaPlus::LuaObject& out, const DecodeMode mode = DecodeMode::Network)
  {
    LuaPlus::LuaState& state = TestLuaState();
    const int top = lua_gettop(state.GetCState());

    const gpg::MemBuffer<const char> buffer = gpg::CopyMemBuffer(bytes.data(), bytes.size());
    gpg::MemBufferStream stream(buffer);
    gpg::BinaryReader reader(&stream);

    bool decoded = true;
    try {
      if (mode == DecodeMode::Network) {
        out.SCR_FromByteStream(out, &state, &reader);
      } else {
        out.SCR_FromLocalByteStream(out, &state, &reader);
      }
    } catch (const std::exception&) {
      decoded = false;
    }

    CHECK(lua_gettop(state.GetCState()) == top);
    return decoded;
  }

  bool DecodeFails(const std::string& bytes)
  {
    LuaPlus::LuaObject out;
    return !Decode(bytes, out);
  }

  void TestLuaValidValues()
  {
    LuaPlus::LuaObject out;
    CHECK(Decode(LuaNumber(2.5f), out) && out.IsNumber() && out.GetNumber() == 2.5);
    CHECK(Decode(LuaString("hello"), out) && out.IsString() && std::strcmp(out.GetString(), "hello") == 0);

    const std::string table = LuaTable(LuaString("Type") + LuaString("Chat") + LuaNumber(1.0f) + LuaNumber(7.0f));
    CHECK(Decode(table, out) && out.IsTable());
    CHECK(out["Type"].IsString() && std::strcmp(out["Type"].GetString(), "Chat") == 0);
    CHECK(out[1].IsNumber() && out[1].GetNumber() == 7.0);

    // Top-level nil, stray end tag and unknown tag decode to nil, as in the binary.
    CHECK(Decode(LuaNil(), out) && out.IsNil());
    CHECK(Decode(std::string(1, '\x05'), out) && out.IsNil());
    CHECK(Decode(std::string(1, '\x09'), out) && out.IsNil());
  }

  // Follows key "k" `steps` times.
  LuaPlus::LuaObject Descend(LuaPlus::LuaObject table, const int steps)
  {
    for (int i = 0; i < steps && table.IsTable(); ++i) {
      table = table["k"];
    }
    return table;
  }

  void TestLuaNestingLimit()
  {
    LuaPlus::LuaObject out;
    CHECK(Decode(LuaNested(256), out) && out.IsTable());
    CHECK(Descend(out, 255).IsTable());

    // One level more: the table past the limit is left out, the rest stays.
    CHECK(Decode(LuaNested(257), out) && out.IsTable());
    CHECK(Descend(out, 255).IsTable());
    CHECK(Descend(out, 256).IsNil());

    // A 64 KB message of table-begin tags: refused, not a stack overflow.
    CHECK(DecodeFails(std::string(65535, '\x04')));
    CHECK(DecodeFails(std::string(1, '\x04') + LuaString("k") + std::string(60000, '\x04')));
  }

  void TestLuaDeepFieldKeepsSiblings()
  {
    LuaPlus::LuaObject out;
    const std::string table = LuaTable(LuaString("a") + LuaNumber(1.0f) + LuaString("deep") + LuaNested(300) +
                                       LuaString("b") + LuaString("kept"));
    CHECK(Decode(table, out) && out.IsTable());
    CHECK(out["a"].IsNumber() && out["a"].GetNumber() == 1.0);
    CHECK(out["b"].IsString() && std::strcmp(out["b"].GetString(), "kept") == 0);
    CHECK(out["deep"].IsTable());
  }

  void TestLuaLobbyRelayDepth()
  {
    // FAF's lobby: a joiner's AddPlayer {Type, PlayerOptions = {...}} reaches
    // everyone two levels deeper in the host's {Type, GameInfo = {PlayerOptions
    // = {[slot] = {...}}}} Launch message. A field the host accepted must not
    // make the Launch undecodable.
    const std::string field = LuaString("Junk") + LuaNested(254);
    const std::string addPlayer =
      LuaTable(LuaString("Type") + LuaString("AddPlayer") + LuaString("PlayerOptions") + LuaTable(field));
    const std::string launch = LuaTable(
      LuaString("Type") + LuaString("Launch") + LuaString("GameInfo") +
      LuaTable(LuaString("PlayerOptions") + LuaTable(LuaNumber(1.0f) + LuaTable(LuaString("PlayerName") + LuaString("p") + field)))
    );

    LuaPlus::LuaObject out;
    CHECK(Decode(addPlayer, out) && out.IsTable());
    CHECK(Decode(launch, out) && out.IsTable());
    CHECK(std::strcmp(out["Type"].GetString(), "Launch") == 0);
    CHECK(out["GameInfo"]["PlayerOptions"][1]["PlayerName"].IsString());
  }

  void TestLuaLocalDecodeHasNoNestingLimit()
  {
    // The sim's Sync table can hold a remote table a few levels down.
    LuaPlus::LuaObject out;
    CHECK(Decode(LuaNested(300), out, DecodeMode::Local) && out.IsTable());
  }

  void TestLuaMalformedTables()
  {
    const float nan = std::numeric_limits<float>::quiet_NaN();
    CHECK(DecodeFails(LuaTable(LuaNil() + LuaString("v"))));                   // nil key
    CHECK(DecodeFails(LuaTable(LuaString("k") + LuaNil())));                   // nil value
    CHECK(DecodeFails(LuaTable(LuaNumber(nan) + LuaString("v"))));             // NaN key
    CHECK(DecodeFails(LuaTable(LuaString("k") + std::string(1, '\x09'))));     // unknown tag as value
    CHECK(DecodeFails(LuaTable(std::string(1, '\x09') + LuaString("v"))));     // unknown tag as key

    // Truncated anywhere inside a table.
    const std::string table = LuaTable(LuaString("key") + LuaNumber(3.0f));
    for (std::size_t length = 1; length < table.size(); ++length) {
      CHECK(DecodeFails(table.substr(0, length)));
    }
  }

  // --- Lua encoding ------------------------------------------------------------------------

  // Runs `script` in the test state and returns global `name`.
  LuaPlus::LuaObject LuaGlobal(const char* const script, const char* const name)
  {
    LuaPlus::LuaState& state = TestLuaState();
    (void)lua_dostring(state.GetCState(), script);
    return state.GetGlobal(name);
  }

  std::string Encode(LuaPlus::LuaObject value, bool& encoded)
  {
    gpg::MemBufferStream stream(256u);
    encoded = value.ToByteStream(stream);
    return std::string(stream.mWriteStart, stream.BytesWritten());
  }

  void TestLuaEncoderLeavesOutWhatItCannotCarry()
  {
    bool encoded = true;
    const std::string bytes =
      Encode(LuaGlobal("faf_test_t = { a = 1, f = print, b = 'x', [print] = 2 }", "faf_test_t"), encoded);
    CHECK(!encoded);

    // The binary wrote nil for the function, which no decoder accepts.
    LuaPlus::LuaObject out;
    CHECK(Decode(bytes, out) && out.IsTable());
    CHECK(out["a"].IsNumber() && out["a"].GetNumber() == 1.0);
    CHECK(out["b"].IsString());
    CHECK(out["f"].IsNil());
  }

  void TestLuaEncoderStopsAtCycles()
  {
    bool encoded = true;
    const std::string bytes = Encode(
      LuaGlobal("faf_test_c = { n = 1 } faf_test_c.self = faf_test_c faf_test_c.sub = { up = faf_test_c, v = 2 }", "faf_test_c"),
      encoded
    );
    CHECK(!encoded);

    LuaPlus::LuaObject out;
    CHECK(Decode(bytes, out) && out.IsTable());
    CHECK(out["n"].IsNumber());
    CHECK(out["self"].IsNil());
    CHECK(out["sub"]["v"].IsNumber() && out["sub"]["up"].IsNil());
  }

  void TestLuaEncoderDepthLimit()
  {
    bool encoded = true;
    const std::string bytes = Encode(
      LuaGlobal("local t = {} faf_test_d = t for i = 1, 1500 do local n = {} t.k = n t = n end", "faf_test_d"), encoded
    );
    CHECK(!encoded);

    LuaPlus::LuaObject out;
    CHECK(Decode(bytes, out, DecodeMode::Local) && out.IsTable());
    CHECK(Descend(out, 1023).IsTable());
    CHECK(Descend(out, 1024).IsNil());
  }

  void TestLuaEncoderValidDataUnchanged()
  {
    // What the encoder could always write is written byte for byte as before.
    LuaPlus::LuaObject value;
    CHECK(Decode(LuaNested(300), value, DecodeMode::Local));
    bool encoded = false;
    CHECK(Encode(value, encoded) == LuaNested(300));
    CHECK(encoded);

    const std::string flat = LuaTable(LuaString("k") + LuaNumber(2.5f));
    CHECK(Decode(flat, value));
    CHECK(Encode(value, encoded) == flat && encoded);
  }

  // --- Message framing ---------------------------------------------------------------------

  void TestMessageFraming()
  {
    {
      // A header whose size is below the 3-byte header itself never frames.
      const std::string wire = Bytes{}.U8(106).U8(2).U8(0).Raw("xyz").data;
      const gpg::MemBuffer<const char> buffer = gpg::CopyMemBuffer(wire.data(), wire.size());
      gpg::MemBufferStream stream(buffer);
      CMessage msg;
      CHECK(!msg.Read(&stream));
      CHECK(msg.HasInvalidLength());
    }
    {
      const std::string wire = Bytes{}.U8(106).U8(5).U8(0).Raw("ab").data;
      const gpg::MemBuffer<const char> buffer = gpg::CopyMemBuffer(wire.data(), wire.size());
      gpg::MemBufferStream stream(buffer);
      CMessage msg;
      CHECK(msg.Read(&stream));
      CHECK(!msg.HasInvalidLength());
      CHECK(msg.GetMessageSize() == 2);
    }
  }

  // --- Command-stream decoder --------------------------------------------------------------

  class CountingSink final : public ICommandSink
  {
  public:
    int calls[24]{};
    int total = 0;
    EntId lastEntity = 0;

    void Note(const ECmdStreamOp op)
    {
      ++calls[static_cast<int>(op)];
      ++total;
    }

    void SetCommandSource(CommandSourceId) override { Note(ECmdStreamOp::CMDST_SetCommandSource); }
    void OnCommandSourceTerminated() override { Note(ECmdStreamOp::CMDST_CommandSourceTerminated); }
    void VerifyChecksum(gpg::MD5Digest const&, CSeqNo) override { Note(ECmdStreamOp::CMDST_VerifyChecksum); }
    void RequestPause() override { Note(ECmdStreamOp::CMDST_RequestPause); }
    void Resume() override { Note(ECmdStreamOp::CMDST_Resume); }
    void SingleStep() override { Note(ECmdStreamOp::CMDST_SingleStep); }
    void CreateUnit(uint32_t, RResId const&, SCoordsVec2 const&, float) override { Note(ECmdStreamOp::CMDST_CreateUnit); }
    void CreateProp(const char*, Wm3::Vec3f const&) override { Note(ECmdStreamOp::CMDST_CreateProp); }
    void DestroyEntity(const EntId id) override
    {
      lastEntity = id;
      Note(ECmdStreamOp::CMDST_DestroyEntity);
    }
    void WarpEntity(EntId, VTransform const&) override { Note(ECmdStreamOp::CMDST_WarpEntity); }
    void ProcessInfoPair(EntId, gpg::StrArg, gpg::StrArg) override { Note(ECmdStreamOp::CMDST_ProcessInfoPair); }
    void IssueCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const&, bool) override
    {
      Note(ECmdStreamOp::CMDST_IssueCommand);
    }
    void IssueFactoryCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const&, bool) override
    {
      Note(ECmdStreamOp::CMDST_IssueFactoryCommand);
    }
    void IncreaseCommandCount(CmdId, int) override { Note(ECmdStreamOp::CMDST_IncreaseCommandCount); }
    void DecreaseCommandCount(CmdId, int) override { Note(ECmdStreamOp::CMDST_DecreaseCommandCount); }
    void SetCommandTarget(CmdId, SSTITarget const&) override { Note(ECmdStreamOp::CMDST_SetCommandTarget); }
    void SetCommandType(CmdId, EUnitCommandType) override { Note(ECmdStreamOp::CMDST_SetCommandType); }
    void SetCommandCells(CmdId, gpg::core::FastVector<SOCellPos> const&, Wm3::Vector3<float> const&) override
    {
      Note(ECmdStreamOp::CMDST_SetCommandCells);
    }
    void RemoveCommandFromUnitQueue(CmdId, EntId) override { Note(ECmdStreamOp::CMDST_RemoveCommandFromQueue); }
    void ExecuteLuaInSim(const char*, LuaPlus::LuaObject const&) override { Note(ECmdStreamOp::CMDST_ExecuteLuaInSim); }
    void LuaSimCallback(const char*, LuaPlus::LuaObject const&, BVSet<EntId, EntIdUniverse> const&) override
    {
      Note(ECmdStreamOp::CMDST_LuaSimCallback);
    }
    void ExecuteDebugCommand(const char*, Wm3::Vector3<float> const&, uint32_t, BVSet<EntId, EntIdUniverse> const&) override
    {
      Note(ECmdStreamOp::CMDST_DebugCommand);
    }
    void AdvanceBeat(int) override { Note(ECmdStreamOp::CMDST_Advance); }
    void EndGame() override { Note(ECmdStreamOp::CMDST_EndGame); }
  };

  struct DecoderFixture
  {
    CountingSink sink;
    msvc8::auto_ptr<gpg::Stream> recording;
    CDecoder decoder{&sink, recording, nullptr, &TestLuaState()};

    void Feed(const ECmdStreamOp op, const std::string& payload)
    {
      CMessage msg = MakeMessage(op, payload);
      decoder.ReceiveMessage(&msg, nullptr);
    }
  };

  void TestDecoderEmptyPayloads()
  {
    DecoderFixture f;
    for (int op = 0; op < 256; ++op) {
      f.Feed(static_cast<ECmdStreamOp>(op), std::string{});
    }
    // Only the opcodes without a payload get through.
    const int payloadless[] = {2, 4, 5, 6, 23};
    for (const int op : payloadless) {
      CHECK(f.sink.calls[op] == 1);
    }
    CHECK(f.sink.total == 5);
  }

  void TestDecoderTruncation()
  {
    const std::string entities = Bytes{}.U32(2).I32(5).I32(9).data;
    const struct
    {
      ECmdStreamOp op;
      std::string payload;
    } commands[] = {
      {ECmdStreamOp::CMDST_DestroyEntity, Bytes{}.I32(42).data},
      {ECmdStreamOp::CMDST_VerifyChecksum, Bytes{}.Raw(std::string(16, '\x11')).I32(50).data},
      {ECmdStreamOp::CMDST_SetCommandCells, Bytes{}.I32(7).I32(1).Raw(std::string(sizeof(SOCellPos), '\x01')).F32(1).F32(2).F32(3).data},
      {ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("Ping").Raw(LuaTable(LuaString("k") + LuaNumber(1))).Raw(entities).data},
      {ECmdStreamOp::CMDST_DebugCommand, Bytes{}.Str("dbg").F32(0).F32(0).F32(0).U8(1).Raw(entities).data},
    };

    for (const auto& command : commands) {
      DecoderFixture f;
      for (std::size_t length = 0; length < command.payload.size(); ++length) {
        f.Feed(command.op, command.payload.substr(0, length));
      }
      CHECK(f.sink.total == 0);
      f.Feed(command.op, command.payload);
      CHECK(f.sink.calls[static_cast<int>(command.op)] == 1);
    }
  }

  void TestDecoderCounts()
  {
    DecoderFixture f;
    const std::string args = LuaTable(std::string{});

    // An entity count far beyond the message.
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(args).U32(0xFFFFFFFFu).data);
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(args).U32(1000).I32(1).data);
    // Ids of two types (the last one is the one the binary never checks).
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(args).U32(2).U32(0x00000001u).U32(0xF0000001u).data);
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(args).U32(3).U32(1).U32(0x10000001u).U32(2).data);
    // Cell counts that are negative or larger than the message.
    f.Feed(ECmdStreamOp::CMDST_SetCommandCells, Bytes{}.I32(7).I32(-1).F32(0).F32(0).F32(0).data);
    f.Feed(ECmdStreamOp::CMDST_SetCommandCells, Bytes{}.I32(7).I32(0x7FFFFFFF).F32(0).F32(0).F32(0).data);
    CHECK(f.sink.total == 0);

    // The same commands, well formed.
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(args).U32(2).U32(1).U32(0x00000009u).data);
    f.Feed(ECmdStreamOp::CMDST_SetCommandCells, Bytes{}.I32(7).I32(0).F32(0).F32(0).F32(0).data);
    CHECK(f.sink.calls[static_cast<int>(ECmdStreamOp::CMDST_LuaSimCallback)] == 1);
    CHECK(f.sink.calls[static_cast<int>(ECmdStreamOp::CMDST_SetCommandCells)] == 1);
  }

  void TestDecoderLuaPayloads()
  {
    DecoderFixture f;
    const std::string none = Bytes{}.U32(0).data;
    const float nan = std::numeric_limits<float>::quiet_NaN();

    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(LuaTable(LuaNil() + LuaNumber(1))).Raw(none).data);
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(LuaTable(LuaNumber(nan) + LuaNumber(1))).Raw(none).data);
    f.Feed(ECmdStreamOp::CMDST_ExecuteLuaInSim, Bytes{}.Str("fn").Raw(std::string(60000, '\x04')).data);
    CHECK(f.sink.total == 0);

    // Deep arguments are cut at the nesting limit, not refused.
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(LuaNested(200)).Raw(none).data);
    f.Feed(ECmdStreamOp::CMDST_LuaSimCallback, Bytes{}.Str("cb").Raw(LuaNested(300)).Raw(none).data);
    CHECK(f.sink.calls[static_cast<int>(ECmdStreamOp::CMDST_LuaSimCallback)] == 2);
  }

  void TestDecoderValidCommand()
  {
    DecoderFixture f;
    f.Feed(ECmdStreamOp::CMDST_DestroyEntity, Bytes{}.I32(0x00100007).data);
    CHECK(f.sink.calls[static_cast<int>(ECmdStreamOp::CMDST_DestroyEntity)] == 1);
    CHECK(f.sink.lastEntity == 0x00100007);
  }

  // --- Connections -------------------------------------------------------------------------

  class FakeConnection final : public INetConnection
  {
  public:
    u_long address;
    u_short port;
    int writes = 0;
    int destroyRequests = 0;

    FakeConnection(const u_long addr, const u_short p)
      : address(addr)
      , port(p)
    {}

    u_long GetAddr() override { return address; }
    u_short GetPort() override { return port; }
    float GetPing() override { return 0.0f; }
    float GetTime() override { return 0.0f; }
    void Write(NetDataSpan*) override { ++writes; }
    void Close() override {}
    msvc8::string ToString() override { return gpg::STR_Printf("fake:%u", static_cast<unsigned>(port)); }
    void ScheduleDestroy() override { ++destroyRequests; }
  };

  class FakeConnector final : public INetConnector
  {
  public:
    std::vector<FakeConnection*> connections;
    int connects = 0;

    FakeConnection* Last() const { return connections.empty() ? nullptr : connections.back(); }

    void Destroy() override {}
    ENetProtocolType GetProtocol() override { return ENetProtocolType::kUdp; }
    u_short GetLocalPort() override { return 6000; }
    INetConnection* Connect(const u_long address, const u_short port) override
    {
      ++connects;
      connections.push_back(new FakeConnection(address, port));
      return connections.back();
    }
    bool FindNextAddress(u_long&, u_short&) override { return false; }
    INetConnection* Accept(const u_long address, const u_short port) override
    {
      connections.push_back(new FakeConnection(address, port));
      return connections.back();
    }
    void Reject(u_long, u_short) override {}
    void Pull() override {}
    void Push() override {}
    void SelectEvent(HANDLE) override {}
    SSendStampWindow SnapshotSendStamps(int32_t) override { return SSendStampWindow{0, 0}; }
  };

  // --- Client control messages --------------------------------------------------------------

  class QuietUi final : public IClientMgrUIInterface
  {};

  struct ClientFixture
  {
    QuietUi ui;
    FakeConnection connection{0x7F000001u, 6001};
    // Left alive on purpose: the clients unlink from `connection` on teardown.
    CClientManagerImpl* manager = CLIENT_CreateClientManager(2, nullptr, 0, true);
    CNetClient* remote = nullptr;

    ClientFixture()
    {
      manager->mInterface = &ui;
      manager->CreateLocalClient("local", 0, 1, 0);
      remote = static_cast<CNetClient*>(manager->CreateNetClient("remote", 1, 2, 1, &connection));
    }

    template <class E>
    void Receive(const E type, const std::string& payload)
    {
      CMessage msg = MakeMessage(type, payload);
      remote->ReceiveMessage(&msg, &connection);
    }
  };

  void TestClientShortMessages()
  {
    ClientFixture* const f = new ClientFixture();
    for (int type = 0; type < 60; ++type) {
      if (type == static_cast<int>(EClientMsg::CLIMSG_ReceiveChat)) {
        continue; // reaches the UI; covered by its own check below
      }
      f->Receive(static_cast<ECmdStreamOp>(type), std::string{});
      f->Receive(static_cast<ECmdStreamOp>(type), std::string(1, '\x01'));
    }
    f->Receive(EClientMsg::CLIMSG_ReceiveChat, std::string{});
    CHECK(true); // reaching here means nothing escaped
  }

  void TestClientSpeedRequests()
  {
    ClientFixture* const f = new ClientFixture();
    f->Receive(EClientMsg::CLIMSG_AdjustSimSpeed, Bytes{}.I32(1).I32(-1000).data);
    CHECK(f->manager->mGameSpeed == -10);
    f->Receive(EClientMsg::CLIMSG_AdjustSimSpeed, Bytes{}.I32(2).I32(1000).data);
    CHECK(f->manager->mGameSpeed == 50);
    f->Receive(EClientMsg::CLIMSG_AdjustSimSpeed, Bytes{}.I32(3).I32(4).data);
    CHECK(f->manager->mGameSpeed == 4);

    f->Receive(EClientMsg::CLIMSG_IntParam, Bytes{}.I32(-1000).data);
    const int rate = f->manager->GetSimRate();
    CHECK(rate >= -10 && rate <= 50);
  }

  void TestClientEndGameFromPeerIgnored()
  {
    ClientFixture* const f = new ClientFixture();
    const auto before = f->remote->mPipe.GetLength();
    f->Receive(ECmdStreamOp::CMDST_EndGame, std::string{});
    CHECK(f->remote->mPipe.GetLength() == before);

    // An ordinary command still queues.
    f->Receive(ECmdStreamOp::CMDST_DestroyEntity, Bytes{}.I32(1).data);
    CHECK(f->remote->mPipe.GetLength() > before);
  }

  // --- Lobby -------------------------------------------------------------------------------

  constexpr u_long kHostAddress = 0x0A000001u;
  constexpr u_short kHostPort = 7000;
  constexpr int32_t kHostUid = 1;
  constexpr int32_t kLocalUid = 10;

  struct LobbyFixture
  {
    FakeConnector connector;
    CLobby* lobby = nullptr;
    FakeConnection* host = nullptr;

    LobbyFixture()
    {
      LuaPlus::LuaObject lobbyClass;
      lobbyClass.AssignNewTable(&TestLuaState(), 0, 0);
      lobby = new CLobby(lobbyClass, &connector, 16, false, "local", kLocalUid);
      lobby->JoinGame(kHostAddress, kHostPort, "host", kHostUid);
      host = connector.Last();
      Deliver(host, ELobbyMsg::LOBMSG_ConnMade, std::string{});
    }

    template <class E>
    void Deliver(FakeConnection* const from, const E type, const std::string& payload)
    {
      CMessage msg = MakeMessage(type, payload);
      lobby->ReceiveMessage(&msg, from);
    }

    SPeer* Peer(const int32_t uid)
    {
      for (SPeer* const peer : lobby->peers.owners()) {
        if (peer->uid == uid) {
          return peer;
        }
      }
      return nullptr;
    }

    std::string Welcome() const
    {
      return Bytes{}.Str("host").I32(kHostUid).I32(kLocalUid).Str("local").I32(0).data;
    }

    std::string NewPeer(const char* name, const u_long address, const u_short port, const int32_t uid) const
    {
      return Bytes{}.Str(name).Put(address).Put(port).I32(uid).data;
    }
  };

  void TestLobbyJoinHandshake()
  {
    LobbyFixture* const f = new LobbyFixture();
    SPeer* const host = f->Peer(kHostUid);
    CHECK(host != nullptr && host->state == ENetworkPlayerState::kConnected);
    CHECK(f->host->writes == 1); // the Join

    // A second connection-made event is the peer's own message: ignored.
    f->Deliver(f->host, ELobbyMsg::LOBMSG_ConnMade, std::string{});
    CHECK(host->state == ENetworkPlayerState::kConnected);
    CHECK(f->host->writes == 1);

    f->Deliver(f->host, ELobbyMsg::LOBMSG_Welcome, f->Welcome());
    CHECK(host->state == ENetworkPlayerState::kEstablished);
  }

  void TestLobbyTruncatedMessages()
  {
    LobbyFixture* const f = new LobbyFixture();
    const std::string full[] = {f->Welcome(), f->NewPeer("bob", 0x0A000002u, 7001, 20), Bytes{}.I32(20).data};
    const ELobbyMsg types[] = {ELobbyMsg::LOBMSG_Welcome, ELobbyMsg::LOBMSG_NewPeer, ELobbyMsg::LOBMSG_DeletePeer};
    for (int i = 0; i < 3; ++i) {
      for (std::size_t length = 0; length < full[i].size(); ++length) {
        f->Deliver(f->host, types[i], full[i].substr(0, length));
      }
    }
    // Every lobby and connection-event type with no payload, from the host.
    for (int type = 100; type < 210; ++type) {
      f->Deliver(f->host, static_cast<ELobbyMsg>(type), std::string{});
    }
    CHECK(f->Peer(20) == nullptr);
    CHECK(f->Peer(kHostUid) != nullptr);
  }

  void TestLobbyHostMessages()
  {
    LobbyFixture* const f = new LobbyFixture();
    f->Deliver(f->host, ELobbyMsg::LOBMSG_Welcome, f->Welcome());

    // NewPeer naming us, or a peer twice: refused, lobby keeps going.
    f->Deliver(f->host, ELobbyMsg::LOBMSG_NewPeer, f->NewPeer("me", 0x0A000003u, 7002, kLocalUid));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_NewPeer, f->NewPeer("bob", 0x0A000002u, 7001, 20));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_NewPeer, f->NewPeer("bob", 0x0A000002u, 7001, 20));
    CHECK(f->Peer(kLocalUid) == nullptr);
    CHECK(f->Peer(20) != nullptr);

    // DeletePeer naming the host itself: ignored.
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DeletePeer, Bytes{}.I32(kHostUid).data);
    CHECK(f->Peer(kHostUid) != nullptr);
    CHECK(f->host->destroyRequests == 0);
    CHECK(f->lobby->peerConnection == f->host);

    // DeletePeer naming another peer still works.
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DeletePeer, Bytes{}.I32(20).data);
    CHECK(f->Peer(20) == nullptr);
  }

  void TestLobbyScriptData()
  {
    LobbyFixture* const f = new LobbyFixture();
    f->Deliver(f->host, ELobbyMsg::LOBMSG_Welcome, f->Welcome());
    const int top = lua_gettop(TestLuaState().GetCState());

    f->Deliver(f->host, ELobbyMsg::LOBMSG_BroadcastScriptData, LuaNumber(1.0f));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_BroadcastScriptData, LuaString("not a table"));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DirectScriptData, LuaNested(400));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DirectScriptData, std::string(65000, '\x04'));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DirectScriptData, LuaTable(LuaNil() + LuaNumber(1)));
    f->Deliver(f->host, ELobbyMsg::LOBMSG_DirectScriptData, LuaTable(LuaString("Type") + LuaString("Hi")));

    CHECK(lua_gettop(TestLuaState().GetCState()) == top);
  }

  void TestLobbyPeerEvents()
  {
    LobbyFixture* const f = new LobbyFixture();
    f->Deliver(f->host, ELobbyMsg::LOBMSG_Welcome, f->Welcome());

    // A peer with a higher uid than ours connects to us: we accept it.
    f->Deliver(f->host, ELobbyMsg::LOBMSG_NewPeer, f->NewPeer("bob", 0x0A000002u, 7001, 20));
    FakeConnection* const bob = f->connector.Last();
    SPeer* const peer = f->Peer(20);
    CHECK(peer != nullptr && peer->state == ENetworkPlayerState::kPending);
    f->Deliver(bob, ELobbyMsg::LOBMSG_ConnMade, std::string{});
    CHECK(peer->state == ENetworkPlayerState::kWaitingJoin);

    // Connection events sent by the peer itself.
    const int connectsBefore = f->connector.connects;
    f->Deliver(bob, ELobbyMsg::LOBMSG_ConnMade, std::string{});
    f->Deliver(bob, ELobbyMsg::LOBMSG_ConnFailed, std::string{});
    CHECK(peer->state == ENetworkPlayerState::kWaitingJoin);
    CHECK(f->connector.connects == connectsBefore);
    CHECK(peer->peerConnection == bob);

    // Host-only messages from a peer.
    f->Deliver(bob, ELobbyMsg::LOBMSG_NewPeer, f->NewPeer("eve", 0x0A000004u, 7003, 30));
    f->Deliver(bob, ELobbyMsg::LOBMSG_DeletePeer, Bytes{}.I32(kHostUid).data);
    f->Deliver(bob, ELobbyMsg::LOBMSG_Rejected, Bytes{}.Str("nope").data);
    CHECK(f->Peer(30) == nullptr);
    CHECK(f->Peer(kHostUid) != nullptr);

    // The peer's Join, truncated at every length, then whole.
    const std::string join = Bytes{}.Str("bob").I32(20).data;
    for (std::size_t length = 0; length < join.size(); ++length) {
      f->Deliver(bob, ELobbyMsg::LOBMSG_Join, join.substr(0, length));
    }
    CHECK(f->Peer(20) != nullptr);
  }

  // --- Order stream check ------------------------------------------------------------------

  std::string HexOf(const gpg::SHA256::Digest& digest)
  {
    static const char* const kHex = "0123456789abcdef";
    std::string out;
    for (const std::uint8_t byte : digest) {
      out += kHex[byte >> 4];
      out += kHex[byte & 15];
    }
    return out;
  }

  void TestSha256Vectors()
  {
    const auto hashOf = [](const std::string& text) {
      gpg::SHA256 hash;
      hash.Update(text.data(), text.size());
      return HexOf(hash.Snapshot());
    };
    CHECK(hashOf("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hashOf("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const std::string twoBlocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CHECK(hashOf(twoBlocks) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // In pieces, and with a snapshot in between, it is the same hash.
    gpg::SHA256 pieces;
    for (const char c : twoBlocks) {
      pieces.Update(&c, 1);
      (void)pieces.Snapshot();
    }
    CHECK(HexOf(pieces.Snapshot()) == hashOf(twoBlocks));
  }

  CMessage CommandMessage(const ECmdStreamOp op, const std::string& payload)
  {
    return MakeMessage(op, payload);
  }

  void TestStreamCheckReports()
  {
    CommandStreamCheck check(3, false);
    const CMessage advance = CommandMessage(ECmdStreamOp::CMDST_Advance, Bytes{}.I32(1).data);

    // Stream 0 reaches beats 1 and 2 here; client 1 reports the same hashes.
    check.Append(0, advance);
    const auto beat1 = check.NoteBoundary(0, 1);
    check.Append(0, advance);
    const auto beat2 = check.NoteBoundary(0, 2);
    check.NoteReport(1, 0, 1, beat1);
    check.NoteReport(1, 0, 2, beat2);
    CHECK(!check.Diverged());

    // A reporter ahead of us waits until we get there, then matches.
    check.NoteReport(2, 0, 3, beat2); // wrong hash, but not checkable yet
    CHECK(!check.Diverged());
    check.Append(0, CommandMessage(ECmdStreamOp::CMDST_DestroyEntity, Bytes{}.I32(5).data));
    check.Append(0, advance);
    (void)check.NoteBoundary(0, 3);
    CHECK(check.Diverged());
    CHECK(check.FirstDivergence().sender == 0 && check.FirstDivergence().reporter == 2);
    CHECK(check.FirstDivergence().beat == 3);

    // A beat the stream never stopped at is a different stream too.
    CommandStreamCheck other(2, false);
    other.Append(0, CommandMessage(ECmdStreamOp::CMDST_Advance, Bytes{}.I32(2).data));
    const auto twoBeats = other.NoteBoundary(0, 2);
    other.NoteReport(1, 0, 1, twoBeats);
    CHECK(other.Diverged());
  }

  // Three client managers wired together in memory: player m's manager has its
  // local client at index m and a CNetClient for each other player, whose
  // connection hands what it writes to that player's manager.
  struct Wire
  {
    struct Packet
    {
      int toManager;
      int fromIndex;
      std::string bytes;
    };
    std::vector<Packet> queue;
  };

  class WireConnection final : public INetConnection
  {
  public:
    Wire* wire = nullptr;
    int toManager = 0;
    int fromIndex = 0;

    u_long GetAddr() override { return 0x7F000001u; }
    u_short GetPort() override { return static_cast<u_short>(7000 + toManager); }
    float GetPing() override { return 0.0f; }
    float GetTime() override { return 0.0f; }
    void Write(NetDataSpan* const data) override
    {
      wire->queue.push_back({toManager, fromIndex, std::string(reinterpret_cast<const char*>(data->start), data->size())});
    }
    void Close() override {}
    msvc8::string ToString() override { return "wire"; }
    void ScheduleDestroy() override {}
  };

  struct ThreePlayerGame
  {
    static constexpr int kPlayers = 3;
    Wire wire;
    QuietUi ui;
    WireConnection connections[kPlayers][kPlayers];
    CClientManagerImpl* managers[kPlayers]{};

    ThreePlayerGame()
    {
      for (int m = 0; m < kPlayers; ++m) {
        managers[m] = CLIENT_CreateClientManager(kPlayers, nullptr, 0, false);
        managers[m]->mInterface = &ui;
        managers[m]->CreateLocalClient(gpg::STR_Printf("p%d", m).c_str(), m, m + 1, static_cast<unsigned>(m));
        for (int p = 0; p < kPlayers; ++p) {
          if (p == m) {
            continue;
          }
          WireConnection& connection = connections[m][p];
          connection.wire = &wire;
          connection.toManager = p;
          connection.fromIndex = m;
          managers[m]->CreateNetClient(gpg::STR_Printf("p%d", p).c_str(), p, p + 1, static_cast<unsigned>(p), &connection);
        }
      }
    }

    void Deliver(const int toManager, const int fromIndex, CMessage& msg)
    {
      auto* const receiver = static_cast<CNetClient*>(managers[toManager]->mClients[fromIndex]);
      receiver->ReceiveMessage(&msg, &connections[toManager][fromIndex]);
    }

    void Deliver(const Wire::Packet& packet)
    {
      CMessage msg(static_cast<ECmdStreamOp>(static_cast<std::uint8_t>(packet.bytes[0])));
      if (packet.bytes.size() > 3) {
        msg.Append(packet.bytes.data() + 3, packet.bytes.size() - 3);
      }
      Deliver(packet.toManager, packet.fromIndex, msg);
    }

    // Delivers everything sent so far, including what the deliveries send.
    void Pump()
    {
      while (!wire.queue.empty()) {
        const Wire::Packet packet = wire.queue.front();
        wire.queue.erase(wire.queue.begin());
        Deliver(packet);
      }
    }

    // Delivers up to `limit` packets as a laggy network would: connections in
    // a random order, each connection's packets still in order.
    void PumpShuffled(std::mt19937& random, std::size_t limit)
    {
      for (; limit > 0 && !wire.queue.empty(); --limit) {
        const std::size_t pick = std::uniform_int_distribution<std::size_t>(0, wire.queue.size() - 1)(random);
        const int toManager = wire.queue[pick].toManager;
        const int fromIndex = wire.queue[pick].fromIndex;
        const auto oldest = std::find_if(wire.queue.begin(), wire.queue.end(), [&](const Wire::Packet& packet) {
          return packet.toManager == toManager && packet.fromIndex == fromIndex;
        });
        const Wire::Packet packet = *oldest;
        wire.queue.erase(oldest);
        Deliver(packet);
      }
    }

    // Player m sends one beat: a checksum report, then an advance.
    void SendBeat(const int m, const int beat)
    {
      const std::string hash(16, static_cast<char>(0x40 + (m * 7 + beat) % 64));
      CMessage checksum = CommandMessage(ECmdStreamOp::CMDST_VerifyChecksum, Bytes{}.Raw(hash).I32(beat).data);
      managers[m]->ProcessClients(checksum);
      CMessage advance = CommandMessage(ECmdStreamOp::CMDST_Advance, Bytes{}.I32(1).data);
      managers[m]->ProcessClients(advance);
    }

    bool AnyDiverged() const
    {
      for (const CClientManagerImpl* const manager : managers) {
        if (manager->mStreamCheck->Diverged() || manager->mStreamCheck->HasFindings()) {
          return true;
        }
      }
      return false;
    }
  };

  void TestStreamCheckLagAndReordering()
  {
    // Players run at their own pace (player 2 falls far behind, then catches
    // up) and packets cross the wire in a random order. Nothing may be found.
    std::mt19937 random(20261025u);
    ThreePlayerGame* const game = new ThreePlayerGame();
    constexpr int kBeats = 300;
    const int pacePercent[ThreePlayerGame::kPlayers] = {90, 60, 25};
    int sent[ThreePlayerGame::kPlayers] = {};
    while (sent[0] < kBeats || sent[1] < kBeats || sent[2] < kBeats) {
      for (int m = 0; m < ThreePlayerGame::kPlayers; ++m) {
        if (sent[m] < kBeats && static_cast<int>(random() % 100) < pacePercent[m]) {
          game->SendBeat(m, ++sent[m]);
        }
      }
      game->PumpShuffled(random, random() % 16);
    }
    game->Pump();

    CHECK(!game->AnyDiverged());
    for (const CClientManagerImpl* const manager : game->managers) {
      for (const CClientBase* const client : manager->mClients) {
        CHECK(client->mQueuedBeat == static_cast<std::uint32_t>(kBeats));
      }
    }
  }

  void TestStreamCheckFalseReportProvesNothing()
  {
    ThreePlayerGame* const game = new ThreePlayerGame();
    for (int beat = 1; beat <= 5; ++beat) {
      for (int m = 0; m < ThreePlayerGame::kPlayers; ++m) {
        game->SendBeat(m, beat);
      }
      game->Pump();
    }

    // Player 2 tells players 0 and 1 that player 0's stream at beat 5 hashed
    // differently. That is noticed, but cannot pin anything on player 0.
    for (const int to : {0, 1}) {
      CMessage fakeAck = MakeMessage(EClientMsg::CLIMSG_Ack, Bytes{}.U8(0).I32(5).Raw(std::string(16, '\x11')).data);
      game->Deliver(to, 2, fakeAck);
      CClientManagerImpl* const manager = game->managers[to];
      CHECK(manager->mStreamCheck->Diverged());
      CHECK(manager->mStreamCheck->FirstDivergence().sender == 0);
      CHECK(manager->mStreamCheck->FirstDivergence().reporter == 2);
      CHECK(!manager->mStreamCheck->ProvenAltered(0));
      CHECK(!manager->OrdersAlteredFrom(0));
    }
  }

  void TestStreamCheckHonestGame()
  {
    // Left alive on purpose, as in the client tests.
    ThreePlayerGame* const game = new ThreePlayerGame();
    for (int beat = 1; beat <= 20; ++beat) {
      for (int m = 0; m < ThreePlayerGame::kPlayers; ++m) {
        game->SendBeat(m, beat);
      }
      game->Pump();
    }
    CHECK(!game->AnyDiverged());
    for (const CClientManagerImpl* const manager : game->managers) {
      for (const CClientBase* const client : manager->mClients) {
        CHECK(client->mQueuedBeat == 20u);
      }
    }
  }

  void RunDifferentOrdersGame(const int checkMode)
  {
    net_CheckOrderStreams = checkMode;
    ThreePlayerGame* const game = new ThreePlayerGame();
    net_CheckOrderStreams = 1;
    for (int beat = 1; beat <= 5; ++beat) {
      for (int m = 0; m < ThreePlayerGame::kPlayers; ++m) {
        game->SendBeat(m, beat);
      }
      game->Pump();
    }
    CHECK(!game->AnyDiverged());

    // Beat 6: player 0's checksum report reaches player 2 altered.
    net_DebugAlterOrdersTo = 2;
    game->SendBeat(0, 6);
    net_DebugAlterOrdersTo = -1;
    game->SendBeat(1, 6);
    game->SendBeat(2, 6);
    game->Pump();

    // Every player notices, and it names player 0's stream at beat 6. Only
    // mode 2 stops the game; by default a false report must not stop anything.
    for (CClientManagerImpl* const manager : game->managers) {
      CHECK(manager->mStreamCheck->Diverged());
      CHECK(manager->mStreamCheck->FirstDivergence().sender == 0);
      CHECK(manager->mStreamCheck->FirstDivergence().beat == 6u);
      CHECK(manager->mStreamCheck->StopsGame() == (checkMode >= 2));
    }

    // Only player 2, who got the altered report, has player 0's own word
    // against it: its desyncs against player 0 are withheld, nobody else's.
    CHECK(game->managers[2]->mStreamCheck->ProvenAltered(0));
    CHECK(game->managers[2]->OrdersAlteredFrom(0));
    CHECK(!game->managers[2]->OrdersAlteredFrom(1));
    for (const int m : {0, 1}) {
      CHECK(!game->managers[m]->mStreamCheck->ProvenAltered(0));
      CHECK(!game->managers[m]->OrdersAlteredFrom(0));
    }
  }

  void TestStreamCheckReportsDifferentOrders() { RunDifferentOrdersGame(1); }

  void TestStreamCheckStopsOnDifferentOrders() { RunDifferentOrdersGame(2); }

  // --- Lua file access (what a lobby's map or mod can reach) -----------------------------

  // Runs `source` in `state` and returns its first result as a string, or
  // "error: ..." when it fails to load or run.
  std::string RunLua(LuaPlus::LuaState& state, const std::string& source)
  {
    lua_State* const L = state.GetCState();
    const int top = lua_gettop(L);
    std::string result;
    if (luaL_loadbuffer(L, source.data(), source.size(), "=test") != 0 || LuaCallProtected(L, 0, 1) != 0) {
      const char* const error = lua_tostring(L, -1);
      result = std::string("error: ") + (error != nullptr ? error : "?");
    } else {
      const char* const text = lua_tostring(L, -1);
      result = text != nullptr ? text : "(not a string)";
    }
    lua_settop(L, top);
    return result;
  }

  // A folder mounted at "/" with lua/ok.lua, and a file beside the folder,
  // outside the mount, that no game path may reach.
  struct MountedFolder
  {
    std::filesystem::path root;
    std::filesystem::path secret;
    CVFSImpl* vfs = nullptr;
    CVirtualFileSystem* previous = nullptr;

    MountedFolder()
    {
      root = std::filesystem::temp_directory_path() / ("faf_vfs_test_" + std::to_string(::GetCurrentProcessId()));
      std::filesystem::create_directories(root / "game" / "lua" / "sub");
      WriteText(root / "game" / "lua" / "ok.lua", "return 'mounted'");
      secret = root / "secret.lua";
      WriteText(secret, "return 'outside'");

      msvc8::vector<SVFSMountPoint> mounts;
      mounts.push_back(SVFSMountPoint((root / "game").string().c_str(), "/"));
      vfs = new CVFSImpl(mounts, root);
      previous = DISK_ExchangeVFS(vfs);
      DISK_InvalidateFileLookups();
    }

    ~MountedFolder()
    {
      (void)DISK_ExchangeVFS(previous);
      delete vfs;
      DISK_InvalidateFileLookups();
      std::error_code ignored;
      std::filesystem::remove_all(root, ignored);
    }

    static void WriteText(const std::filesystem::path& path, const std::string& text)
    {
      std::FILE* const file = std::fopen(path.string().c_str(), "wb");
      if (file != nullptr) {
        std::fwrite(text.data(), 1, text.size(), file);
        std::fclose(file);
      }
    }

    bool Finds(const char* const path)
    {
      msvc8::string found;
      (void)vfs->FindFile(&found, path, nullptr);
      return !found.empty();
    }
  };

  void TestVfsStaysInsideMounts()
  {
    MountedFolder folder;
    CHECK(folder.Finds("/lua/ok.lua"));
    CHECK(folder.Finds("/lua/sub/../ok.lua"));
    CHECK(folder.Finds("/lua/./ok.lua"));
    CHECK(!folder.Finds("/../secret.lua"));
    CHECK(!folder.Finds("/lua/../../secret.lua"));
    CHECK(!folder.Finds("/lua\\..\\..\\secret.lua"));
    CHECK(!folder.vfs->GetFileInfo("/../secret.lua", nullptr));
    msvc8::vector<msvc8::string> listed;
    folder.vfs->EnumerateFiles("/../", "*.lua", false, &listed);
    CHECK(listed.empty());
  }

  void TestLuaFilesComeFromTheGame()
  {
    MountedFolder folder;
    std::string secretPath = folder.secret.string();
    std::replace(secretPath.begin(), secretPath.end(), '\\', '/');

    // A game state (opened without io) reads the mounted files only.
    LuaPlus::LuaState game(LuaPlus::LuaState::LIB_BASE);
    CHECK(RunLua(game, "return dofile('/lua/ok.lua')") == "mounted");
    CHECK(RunLua(game, "return tostring(loadfile('/../secret.lua'))") == "nil");
    CHECK(RunLua(game, "return tostring(loadfile('" + secretPath + "'))") == "nil");
    CHECK(RunLua(game, "return tostring(LuaDumpBinary)") == "nil");

    // The start-up state, which runs the user's own init file, keeps real paths.
    LuaPlus::LuaState startup(LuaPlus::LuaState::LIB_OSIO);
    CHECK(RunLua(startup, "return dofile('" + secretPath + "')") == "outside");
  }

  void TestGameDataVersion()
  {
    // FAF's lua/version.lua as deployed (double quotes) and as in the source tree.
    const std::string deployed =
      "local GameType = \"FAF\"  -- The use of `'` instead of `\"` is **intentional**\n"
      "local Commit = \"2ae081b063aba82df3c679780f0ba8460e06a63e\"\n\n"
      "local Version = \"3835\"\n---@alias PATCH \"3835\"\n---@alias VERSION \"1.5.3835\"\n";
    CHECK(FAF_ParseLuaVersionFile(deployed) == 3835);
    CHECK(FAF_ParseLuaVersionFile("local Version='3839'") == 3839);
    CHECK(FAF_ParseLuaVersionFile("local Version = \"38x9\"") == 0);
    CHECK(FAF_ParseLuaVersionFile("local VersionText = \"3839\"") == 0);
    CHECK(FAF_ParseLuaVersionFile("---@alias VERSION \"1.5.3839\"") == 0);
    CHECK(FAF_ParseLuaVersionFile("") == 0);

    // Read from the mounted game data; without the file the session gets FAF's oldest patches.
    MountedFolder folder;
    CHECK(FAF_GetGameDataVersion() == kFafGameVersionOldestSupported);
    MountedFolder::WriteText(folder.root / "game" / "lua" / "version.lua", deployed + "local Version = \"9999\"\n");
    DISK_InvalidateFileLookups();
    CHECK(FAF_GetGameDataVersion() == 3835);
  }

  void TestLuaCompiledChunksRefused()
  {
    LuaPlus::LuaState& state = TestLuaState();
    const std::string load =
      "local f, err = loadstring(string.char(27) .. 'Lua' .. string.rep('x', 32)) return tostring(err)";
    CHECK(RunLua(state, load).find("compiled Lua chunks are not loaded") != std::string::npos);

    // Switched on, the chunk reaches the undumper (which rejects this junk).
    lua_AllowPrecompiledChunks = true;
    const std::string allowed = RunLua(state, load);
    lua_AllowPrecompiledChunks = false;
    CHECK(allowed.find("compiled Lua chunks are not loaded") == std::string::npos);
    CHECK(allowed != "nil");
  }

  // --- Replay files ------------------------------------------------------------------------

  void TestReplayDamagedHeaderRefused()
  {
    // A replay header as VCR_CreateReplay writes it, up to the init seed.
    const auto lengthPrefixed = [](const std::string& s) { return Bytes{}.U32(static_cast<std::uint32_t>(s.size())).Raw(s).data; };
    const std::string preamble =
      Bytes{}.Str("Supreme Commander v1.50.3835").Str("\r\n").Raw("Replay v1.9\r\n").Str("/maps/x/x.scmap").Str("\r\n\x1a").data;
    const auto makeHeader = [&](const std::string& mods, const std::string& scenario, const std::string& army) {
      return Bytes{}
        .Raw(preamble)
        .Raw(lengthPrefixed(mods))
        .Raw(lengthPrefixed(scenario))
        .U8(1).Str("player").I32(0)
        .U8(0)
        .U8(1).Raw(lengthPrefixed(army)).U8(0).U8(0xFF)
        .data;
    };
    const std::string goodMods = LuaTable(std::string{});
    const std::string goodScenario = LuaTable(LuaString("name") + LuaString("x"));
    const std::string goodArmy = LuaTable(LuaString("PlayerName") + LuaString("p"));
    const std::string header = makeHeader(goodMods, goodScenario, goodArmy);

    char directory[MAX_PATH]{};
    GetTempPathA(MAX_PATH, directory);
    const std::string path = std::string(directory) + "faf_net_tests_replay.scfareplay";

    int refused = 0;
    int tried = 0;
    const auto tryHeader = [&](const std::string& bytes) {
      if (FILE* const file = std::fopen(path.c_str(), "wb")) {
        std::fwrite(bytes.data(), 1, bytes.size(), file);
        std::fclose(file);
      }
      ++tried;
      // Refused, and with a reason the player can be shown.
      msvc8::string reason;
      if (VCR_SetupReplaySession(path.c_str(), &reason).get() == nullptr && !reason.empty()) {
        ++refused;
      }
    };

    // Cut anywhere before the init seed is complete.
    for (std::size_t length = 0; length < header.size() + 4; ++length) {
      tryHeader((header + Bytes{}.I32(1234).data).substr(0, length));
    }
    // A length prefix that does not fit (negative as the reader takes it).
    tryHeader(preamble + Bytes{}.U32(0xFFFFFFF0u).data);
    // A complete header whose game settings do not decode: the session would
    // fail on them later, where nothing catches it.
    const std::string seed = Bytes{}.I32(1234).data;
    const std::string nilValue = LuaTable(LuaString("k") + LuaNil());
    tryHeader(makeHeader(nilValue, goodScenario, goodArmy) + seed);
    tryHeader(makeHeader(goodMods, nilValue, goodArmy) + seed);
    tryHeader(makeHeader(goodMods, goodScenario, nilValue) + seed);
    tryHeader(makeHeader(goodMods, std::string{}, goodArmy) + seed);

    std::remove(path.c_str());
    CHECK(tried > 0 && refused == tried);
  }

  const TestCase kTests[] = {
    {"lua: valid values", &TestLuaValidValues},
    {"files: the mounted file system stays inside its mounts", &TestVfsStaysInsideMounts},
    {"files: game Lua states read only the game's files", &TestLuaFilesComeFromTheGame},
    {"files: compiled Lua chunks are refused", &TestLuaCompiledChunksRefused},
    {"game version: live sessions follow the game data", &TestGameDataVersion},
    {"lua: nesting limit", &TestLuaNestingLimit},
    {"lua: deep field keeps its siblings", &TestLuaDeepFieldKeepsSiblings},
    {"lua: lobby relay depth", &TestLuaLobbyRelayDepth},
    {"lua: local decode has no nesting limit", &TestLuaLocalDecodeHasNoNestingLimit},
    {"lua: malformed tables", &TestLuaMalformedTables},
    {"lua encode: leaves out what it cannot carry", &TestLuaEncoderLeavesOutWhatItCannotCarry},
    {"lua encode: stops at cycles", &TestLuaEncoderStopsAtCycles},
    {"lua encode: depth limit", &TestLuaEncoderDepthLimit},
    {"lua encode: valid data unchanged", &TestLuaEncoderValidDataUnchanged},
    {"message: framing", &TestMessageFraming},
    {"decoder: empty payloads", &TestDecoderEmptyPayloads},
    {"decoder: truncation", &TestDecoderTruncation},
    {"decoder: counts", &TestDecoderCounts},
    {"decoder: lua payloads", &TestDecoderLuaPayloads},
    {"decoder: valid command", &TestDecoderValidCommand},
    {"client: short messages", &TestClientShortMessages},
    {"client: speed requests", &TestClientSpeedRequests},
    {"client: end game from peer ignored", &TestClientEndGameFromPeerIgnored},
    {"lobby: join handshake", &TestLobbyJoinHandshake},
    {"lobby: truncated messages", &TestLobbyTruncatedMessages},
    {"lobby: host messages", &TestLobbyHostMessages},
    {"lobby: script data", &TestLobbyScriptData},
    {"lobby: peer events", &TestLobbyPeerEvents},
    {"replay: damaged header refused", &TestReplayDamagedHeaderRefused},
    {"order check: sha256 vectors", &TestSha256Vectors},
    {"order check: reports", &TestStreamCheckReports},
    {"order check: honest 3-player game", &TestStreamCheckHonestGame},
    {"order check: lag and reordering find nothing", &TestStreamCheckLagAndReordering},
    {"order check: a false report proves nothing", &TestStreamCheckFalseReportProvesNothing},
    {"order check: different orders reported (default)", &TestStreamCheckReportsDifferentOrders},
    {"order check: different orders stop the game (mode 2)", &TestStreamCheckStopsOnDifferentOrders},
  };
} // namespace

int main()
{
  for (const TestCase& test : kTests) {
    RunTest(test);
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
