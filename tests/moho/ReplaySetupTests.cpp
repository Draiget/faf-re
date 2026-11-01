#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "gpg/core/streams/MemBufferStream.h"
#include "moho/misc/SessionStartup.h"
#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/sim/WldSessionInfo.h"
#include "moho/sim/CWldSession.h"
#include "moho/misc/LaunchInfoBase.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"
#include "moho/sim/WldSessionState.h"
#include "gpg/core/algorithms/MD5.h"
#include "moho/command/ICommandSink.h"
#include "moho/command/SSTITarget.h"
#include "moho/misc/CDecoder.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/SOCellPos.h"
#include <cmath>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace
{
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

  std::string LuaString(const char* s) { return Bytes{}.U8(1).Str(s).data; }
  std::string LuaTable(const std::string& entries) { return "\x04" + entries + "\x05"; }

  moho::CMessage MakeAdvanceMessage(const std::int32_t beatDelta)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_Advance);
    moho::CMessageStream stream(msg);
    stream.WriteInt32(beatDelta);
    return msg;
  }

  moho::CMessage MakeOtherMessage(const moho::ECmdStreamOp op, const std::string& payload)
  {
    moho::CMessage msg(op);
    if (!payload.empty()) {
      msg.Append(payload.data(), payload.size());
    }
    return msg;
  }

  void WriteMessage(gpg::Stream& dest, const moho::CMessage& msg)
  {
    dest.Write(msg.mBuff.data(), msg.mBuff.size());
  }

  void TestEmptyStream()
  {
    gpg::MemBufferStream stream(256);
    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 0);
  }

  void TestNullStream()
  {
    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(nullptr);
    CHECK(beats == 0);
  }

  void TestSingleAdvanceMessage()
  {
    gpg::MemBufferStream stream(256);
    const moho::CMessage advance = MakeAdvanceMessage(42);
    WriteMessage(stream, advance);

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 42);

    // Verify stream was rewound to position 0
    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);

    // Verify message can be read again
    moho::CMessage readBack;
    CHECK(readBack.ReadMessage(&stream));
    CHECK(readBack.GetType().raw() == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_Advance));
  }

  void TestMultipleAdvanceAndOtherMessages()
  {
    gpg::MemBufferStream stream(1024);

    // Mixed stream of commands:
    // non-advance, advance(10), non-advance, advance(25), advance(65)
    WriteMessage(stream, MakeOtherMessage(moho::ECmdStreamOp::CMDST_SetCommandSource, "\x01"));
    WriteMessage(stream, MakeAdvanceMessage(10));
    WriteMessage(stream, MakeOtherMessage(moho::ECmdStreamOp::CMDST_ProcessInfoPair, "\x00\x01\x02\x03"));
    WriteMessage(stream, MakeAdvanceMessage(25));
    WriteMessage(stream, MakeAdvanceMessage(65));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 100);

    // Verify stream was rewound to 0
    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);

    // Verify reading first message yields the initial SetCommandSource
    moho::CMessage firstMsg;
    CHECK(firstMsg.ReadMessage(&stream));
    CHECK(firstMsg.GetType().raw() == static_cast<std::uint8_t>(moho::ECmdStreamOp::CMDST_SetCommandSource));
  }

  void TestStreamOffsetRewind()
  {
    gpg::MemBufferStream stream(1024);

    // Simulate dummy header data at start
    const std::string dummyHeader = "PREAMBLE_DATA_1234567890";
    stream.Write(dummyHeader.data(), dummyHeader.size());

    // Advance stream read head past header
    char buf[32];
    const size_t bytesRead = stream.Read(buf, dummyHeader.size());
    CHECK(bytesRead == dummyHeader.size());
    const std::uint64_t headerEndPos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(headerEndPos == dummyHeader.size());

    // Now write advance messages into stream
    WriteMessage(stream, MakeAdvanceMessage(15));
    WriteMessage(stream, MakeAdvanceMessage(30));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 45);

    // Crucial check: verify stream position rewound to headerEndPos, not 0!
    const std::uint64_t rewoundPos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(rewoundPos == headerEndPos);
  }

  void TestTruncatedStream()
  {
    gpg::MemBufferStream stream(256);
    WriteMessage(stream, MakeAdvanceMessage(50));

    // Append partial packet (e.g. 2 bytes only)
    const char partialHeader[] = {'\x00', '\x07'}; // opcode 0, size low byte 7, missing rest
    stream.Write(partialHeader, sizeof(partialHeader));

    const std::int32_t beats = moho::VCR_ScanReplayTotalBeats(&stream);
    CHECK(beats == 50);

    const std::uint64_t pos = stream.VirtTell(gpg::Stream::ModeReceive);
    CHECK(pos == 0);
  }

  void TestSessionInfoDefaultTotalBeats()
  {
    moho::SWldSessionInfo sessionInfo{};
    CHECK(sessionInfo.mTotalBeats == 0);
  }

  void TestVCRSetupReplaySessionCalculatesTotalBeats()
  {
    const auto lengthPrefixed = [](const std::string& s) {
      return Bytes{}.U32(static_cast<std::uint32_t>(s.size())).Raw(s).data;
    };
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
    const std::string seed = Bytes{}.I32(1234).data;
    const std::string header = makeHeader(goodMods, goodScenario, goodArmy) + seed;

    char directory[MAX_PATH]{};
    GetTempPathA(MAX_PATH, directory);
    const std::string path = std::string(directory) + "faf_replay_setup_test.scfareplay";

    FILE* const file = std::fopen(path.c_str(), "wb");
    CHECK(file != nullptr);
    if (file != nullptr) {
      std::fwrite(header.data(), 1, header.size(), file);

      // Write three advance packets: 10 + 25 + 65 = 100 beats
      const moho::CMessage adv1 = MakeAdvanceMessage(10);
      const moho::CMessage adv2 = MakeAdvanceMessage(25);
      const moho::CMessage adv3 = MakeAdvanceMessage(65);
      std::fwrite(adv1.mBuff.data(), 1, adv1.mBuff.size(), file);
      std::fwrite(adv2.mBuff.data(), 1, adv2.mBuff.size(), file);
      std::fwrite(adv3.mBuff.data(), 1, adv3.mBuff.size(), file);
      std::fclose(file);
    }

    msvc8::string reason;
    msvc8::auto_ptr<moho::SWldSessionInfo> sessionInfo = moho::VCR_SetupReplaySession(path.c_str(), &reason);

    CHECK(sessionInfo.get() != nullptr);
    if (sessionInfo.get() != nullptr) {
      CHECK(sessionInfo->mIsReplay == true);
      CHECK(sessionInfo->mTotalBeats == 100);
    }

    sessionInfo.reset();
    std::remove(path.c_str());

    FILE* const realF = std::fopen("C:/ProgramData/FAForever/replays/28013017.scfareplay", "rb");
    if (realF != nullptr) {
      std::fclose(realF);
      msvc8::string reasonReal;
      msvc8::auto_ptr<moho::SWldSessionInfo> realSession =
        moho::VCR_SetupReplaySession("C:/ProgramData/FAForever/replays/28013017.scfareplay", &reasonReal);
      CHECK(realSession.get() != nullptr);
      if (realSession.get() != nullptr) {
        CHECK(realSession->mTotalBeats == 9608);
      }
    }
  }

  void TestCWldSessionScrubbingStateTransitions()
  {
    // Test static pending restart target
    moho::CWldSession::sPendingRestartScrubTarget = -1;
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);

    // Mock CWldSession buffer
    alignas(moho::CWldSession) std::uint8_t buffer[sizeof(moho::CWldSession)];
    std::memset(buffer, 0, sizeof(buffer));
    moho::CWldSession* const session = reinterpret_cast<moho::CWldSession*>(buffer);

    session->mScrubTargetBeat = -1;
    session->mScrubStartBeat = 0;
    session->mIsScrubbing = false;
    session->mTotalReplayBeats = 1000;
    session->mGameTick = 100;
    session->IsReplay = false;

    // Test 1: Non-replay guard - refuse to scrub if not replay
    session->StartScrubToBeat(500);
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // Test 2: Forward scrub when IsReplay is true
    session->IsReplay = true;
    session->StartScrubToBeat(500);
    CHECK(session->IsScrubbing() == true);
    CHECK(session->mScrubStartBeat == 100);
    CHECK(session->mScrubTargetBeat == 500);
    CHECK(session->GetTotalReplayBeats() == 1000);

    // Test 3: Scrub progress calculation
    session->mGameTick = 100;
    CHECK(session->GetScrubProgress() == 0.0f);
    session->mGameTick = 300;
    CHECK(std::abs(session->GetScrubProgress() - 0.5f) < 1e-4f);
    session->mGameTick = 500;
    CHECK(session->GetScrubProgress() == 1.0f);

    // Test 4: Clamp to total replay beats
    session->mGameTick = 200;
    session->StartScrubToBeat(1500);
    CHECK(session->mScrubTargetBeat == 1000);

    // Test 5: Target <= current tick cancels/completes
    session->StartScrubToBeat(200);
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // Test 6a: Backward seek without mLaunchInfo bails out safely
    session->mGameTick = 500;
    session->StartScrubToBeat(250);
    CHECK(session->IsScrubbing() == false);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);

    // Test 6b: Backward seek safely no-ops and cancels scrub without hanging session
    session->StartScrubToBeat(250);
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // Test 7: CancelScrub resets state and clears pending restart target
    moho::CWldSession::sPendingRestartScrubTarget = 100;
    session->mIsScrubbing = true;
    session->mScrubTargetBeat = 800;
    session->CancelScrub();
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);
  }

  void TestReplayScrubbingUserLuaBindings()
  {
    LuaPlus::LuaState state(LuaPlus::LuaState::LIB_BASE);

    // Register replay scrubbing Lua functions
    moho::func_GetReplayTotalTicks_LuaFuncDef()->Run(&state);
    moho::func_ScrubReplay_LuaFuncDef()->Run(&state);
    moho::func_CancelReplayScrub_LuaFuncDef()->Run(&state);
    moho::func_IsReplayScrubbing_LuaFuncDef()->Run(&state);
    moho::func_GetReplayScrubProgress_LuaFuncDef()->Run(&state);
    moho::func_GetGameTickUser_LuaFuncDef()->Run(&state);
    moho::func_GameTick_LuaFuncDef()->Run(&state);

    // Verify all functions are bound and callable in Lua global scope
    CHECK(state.GetGlobal("GetReplayTotalTicks").IsFunction());
    CHECK(state.GetGlobal("ScrubReplay").IsFunction());
    CHECK(state.GetGlobal("CancelReplayScrub").IsFunction());
    CHECK(state.GetGlobal("IsReplayScrubbing").IsFunction());
    CHECK(state.GetGlobal("GetReplayScrubProgress").IsFunction());
    CHECK(state.GetGlobal("GetGameTick").IsFunction());
    CHECK(state.GetGlobal("GameTick").IsFunction());

    // Mock CWldSession buffer
    alignas(moho::CWldSession) std::uint8_t buffer[sizeof(moho::CWldSession)];
    std::memset(buffer, 0, sizeof(buffer));
    moho::CWldSession* const session = reinterpret_cast<moho::CWldSession*>(buffer);

    moho::CWldSession* const savedActiveSession = moho::gActiveWldSession;

    // --- Scenario 1: No active session (gActiveWldSession == nullptr) ---
    moho::gActiveWldSession = nullptr;

    CHECK(moho::SCR_LuaDoString("ticks = GetReplayTotalTicks()", &state));
    CHECK(state.GetGlobal("ticks").GetNumber() == 0.0);

    CHECK(moho::SCR_LuaDoString("isScrub = IsReplayScrubbing()", &state));
    CHECK(state.GetGlobal("isScrub").GetBoolean() == false);

    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    CHECK(state.GetGlobal("prog").IsNil());

    // ScrubReplay and CancelReplayScrub should safely no-op without session
    CHECK(moho::SCR_LuaDoString("ScrubReplay(100)", &state));
    CHECK(moho::SCR_LuaDoString("CancelReplayScrub()", &state));

    // --- Scenario 2: Active session is NOT a replay (IsReplay == false) ---
    session->IsReplay = false;
    session->mTotalReplayBeats = 1200;
    session->mGameTick = 50;
    session->mScrubTargetBeat = -1;
    session->mScrubStartBeat = 0;
    session->mIsScrubbing = false;
    moho::gActiveWldSession = session;

    CHECK(moho::SCR_LuaDoString("ticks = GetReplayTotalTicks()", &state));
    CHECK(state.GetGlobal("ticks").GetNumber() == 0.0);

    CHECK(moho::SCR_LuaDoString("isScrub = IsReplayScrubbing()", &state));
    CHECK(state.GetGlobal("isScrub").GetBoolean() == false);

    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    CHECK(state.GetGlobal("prog").IsNil());

    // Scrubbing initiation should be refused
    CHECK(moho::SCR_LuaDoString("ScrubReplay(500)", &state));
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    // --- Scenario 3: Active session IS a replay (IsReplay == true) ---
    session->IsReplay = true;
    session->mTotalReplayBeats = 1500;
    session->mGameTick = 200;
    session->mScrubTargetBeat = -1;
    session->mScrubStartBeat = 0;
    session->mIsScrubbing = false;

    CHECK(moho::SCR_LuaDoString("ticks = GetReplayTotalTicks()", &state));
    CHECK(state.GetGlobal("ticks").GetNumber() == 1500.0);

    CHECK(moho::SCR_LuaDoString("isScrub = IsReplayScrubbing()", &state));
    CHECK(state.GetGlobal("isScrub").GetBoolean() == false);

    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    CHECK(state.GetGlobal("prog").IsNil());

    // Start scrubbing to tick 800
    CHECK(moho::SCR_LuaDoString("ScrubReplay(800)", &state));
    CHECK(session->IsScrubbing() == true);
    CHECK(session->mScrubStartBeat == 200);
    CHECK(session->mScrubTargetBeat == 800);

    CHECK(moho::SCR_LuaDoString("isScrub = IsReplayScrubbing()", &state));
    CHECK(state.GetGlobal("isScrub").GetBoolean() == true);

    // Verify progress table at start of scrub (progress == 0.0)
    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    LuaPlus::LuaObject prog = state.GetGlobal("prog");
    CHECK(prog.IsTable());
    CHECK(std::abs(prog["progress"].GetNumber() - 0.0f) < 1e-4f);
    CHECK(prog["currentTick"].GetInteger() == 200);
    CHECK(prog["startTick"].GetInteger() == 200);
    CHECK(prog["targetTick"].GetInteger() == 800);
    CHECK(prog["totalTicks"].GetInteger() == 1500);

    // Simulate progress advance to midway (tick 500: (500-200)/(800-200) = 0.5)
    session->mGameTick = 500;

    CHECK(moho::SCR_LuaDoString("gt = GetGameTick()", &state));
    CHECK(state.GetGlobal("gt").GetInteger() == 500);

    CHECK(moho::SCR_LuaDoString("gt2 = GameTick()", &state));
    CHECK(state.GetGlobal("gt2").GetInteger() == 500);

    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    prog = state.GetGlobal("prog");
    CHECK(prog.IsTable());
    CHECK(std::abs(prog["progress"].GetNumber() - 0.5f) < 1e-4f);
    CHECK(prog["currentTick"].GetInteger() == 500);
    CHECK(prog["startTick"].GetInteger() == 200);
    CHECK(prog["targetTick"].GetInteger() == 800);

    // Cancel scrubbing via Lua
    CHECK(moho::SCR_LuaDoString("CancelReplayScrub()", &state));
    CHECK(session->IsScrubbing() == false);
    CHECK(session->mScrubTargetBeat == -1);

    CHECK(moho::SCR_LuaDoString("isScrub = IsReplayScrubbing()", &state));
    CHECK(state.GetGlobal("isScrub").GetBoolean() == false);

    CHECK(moho::SCR_LuaDoString("prog = GetReplayScrubProgress()", &state));
    CHECK(state.GetGlobal("prog").IsNil());

    // Restore active session
    moho::gActiveWldSession = savedActiveSession;
  }

  static std::string ReadFileToString(const char* path)
  {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
      return "";
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
  }

  void TestReplayTimelineLuaSyntaxAndExecution()
  {
    LuaPlus::LuaState state(LuaPlus::LuaState::LIB_BASE);

    // Mock UI environment
    const char* const mockEnv =
      "local function MakeProp(val)\n"
      "    local p = { _val = val or 0 }\n"
      "    p.Set = function(self, v) self._val = v end\n"
      "    setmetatable(p, {\n"
      "        __call = function(self)\n"
      "            if type(self._val) == 'function' then return self._val() end\n"
      "            return self._val\n"
      "        end\n"
      "    })\n"
      "    return p\n"
      "end\n"
      "local G = {\n"
      "    __init = function(self, parent, name)\n"
      "        self._parent = parent\n"
      "        self._name = name\n"
      "        self._hidden = false\n"
      "        self.Depth = MakeProp(10)\n"
      "        self.Left = MakeProp(0)\n"
      "        self.Right = MakeProp(500)\n"
      "        self.Top = MakeProp(0)\n"
      "        self.Bottom = MakeProp(100)\n"
      "        self.Width = MakeProp(500)\n"
      "        self.Height = MakeProp(100)\n"
      "    end,\n"
      "    Hide = function(self) self._hidden = true end,\n"
      "    Show = function(self) self._hidden = false end,\n"
      "    IsHidden = function(self) return self._hidden end,\n"
      "    SetNeedsFrameUpdate = function(self, b) end,\n"
      "    Destroy = function(self) end,\n"
      "    GetTopmostDepth = function(self) return 10 end,\n"
      "}\n"
      "setmetatable(G, {\n"
      "    __call = function(cls, parent, name)\n"
      "        local inst = {}\n"
      "        for k, v in cls do inst[k] = v end\n"
      "        inst:__init(parent, name)\n"
      "        return inst\n"
      "    end\n"
      "})\n"
      "function import(mod)\n"
      "    if mod == '/lua/ui/uiutil.lua' then\n"
      "        return {\n"
      "            bodyFont = 'Arial',\n"
      "            titleFont = 'Arial',\n"
      "            UIFile = function(p) return p end,\n"
      "            SkinnableFile = function(p) return p end,\n"
      "            CreateText = function(parent, text, size, font)\n"
      "                local t = { _text = text, _size = size, _color = 'ffffffff', _hidden = false }\n"
      "                t.Depth = MakeProp(10)\n"
      "                t.Left = MakeProp(0)\n"
      "                t.Right = MakeProp(100)\n"
      "                t.Top = MakeProp(0)\n"
      "                t.Bottom = MakeProp(20)\n"
      "                t.Width = MakeProp(100)\n"
      "                t.Height = MakeProp(20)\n"
      "                t.SetText = function(self, s) self._text = s end\n"
      "                t.GetText = function(self) return self._text end\n"
      "                t.SetColor = function(self, c) self._color = c end\n"
      "                t.Hide = function(self) self._hidden = true end\n"
      "                t.Show = function(self) self._hidden = false end\n"
      "                return t\n"
      "            end,\n"
      "            CreateButtonWithDropshadow = function(parent, path, text)\n"
      "                local b = { _text = text, _hidden = false }\n"
      "                b.Depth = MakeProp(10)\n"
      "                b.Left = MakeProp(0)\n"
      "                b.Right = MakeProp(80)\n"
      "                b.Top = MakeProp(0)\n"
      "                b.Bottom = MakeProp(25)\n"
      "                b.Width = MakeProp(80)\n"
      "                b.Height = MakeProp(25)\n"
      "                return b\n"
      "            end,\n"
      "            SurroundWithNinePatch = function(control, path, fx, fy) end,\n"
      "            CreateNinePatchStd = function(parent, path)\n"
      "                return {\n"
      "                    Depth = MakeProp(5),\n"
      "                    Surround = function(self, c, x, y) end,\n"
      "                }\n"
      "            end,\n"
      "        }\n"
      "    elseif mod == '/lua/maui/layouthelpers.lua' then\n"
      "        local lh = {}\n"
      "        lh.ScaleNumber = function(n) return n end\n"
      "        lh.FillParent = function(c, p) end\n"
      "        lh.FillParentFixedBorder = function(c, p, b) end\n"
      "        lh.DepthUnderParent = function(c, p, d) end\n"
      "        lh.SetDimensions = function(c, w, h) end\n"
      "        lh.AtCenterIn = function(c, p) end\n"
      "        lh.AtHorizontalCenterIn = function(c, p) end\n"
      "        lh.AtVerticalCenterIn = function(c, p) end\n"
      "        lh.AtBottomIn = function(c, p, o) end\n"
      "        lh.AtTopIn = function(c, p, o) end\n"
      "        lh.AtLeftIn = function(c, p, o) end\n"
      "        lh.AtRightIn = function(c, p, o) end\n"
      "        lh.Below = function(c, p, o) end\n"
      "        lh.Above = function(c, p, o) end\n"
      "        lh.SetWidth = function(c, w) end\n"
      "        lh.SetHeight = function(c, h) end\n"
      "        return lh\n"
      "    elseif mod == '/lua/maui/group.lua' then\n"
      "        return { Group = G }\n"
      "    elseif mod == '/lua/maui/bitmap.lua' then\n"
      "        local B = function(parent)\n"
      "            local b = { _parent = parent, _color = 'ffffffff' }\n"
      "            b.Depth = MakeProp(10)\n"
      "            b.Left = MakeProp(0)\n"
      "            b.Right = MakeProp(100)\n"
      "            b.Top = MakeProp(0)\n"
      "            b.Bottom = MakeProp(20)\n"
      "            b.Width = MakeProp(100)\n"
      "            b.Height = MakeProp(20)\n"
      "            b.SetSolidColor = function(self, c) self._color = c end\n"
      "            return b\n"
      "        end\n"
      "        return { Bitmap = B }\n"
      "    elseif mod == '/lua/maui/slider.lua' then\n"
      "        local S = function(parent, isVert, min, max, inc)\n"
      "            local s = { _min = min, _max = max, _val = min, _endValue = max }\n"
      "            s.Depth = MakeProp(10)\n"
      "            s.Left = MakeProp(0)\n"
      "            s.Right = MakeProp(200)\n"
      "            s.Top = MakeProp(0)\n"
      "            s.Bottom = MakeProp(20)\n"
      "            s.Width = MakeProp(200)\n"
      "            s.Height = MakeProp(20)\n"
      "            s._background = {\n"
      "                Left = MakeProp(0),\n"
      "                Right = MakeProp(200),\n"
      "                Top = MakeProp(0),\n"
      "                Bottom = MakeProp(20),\n"
      "                Depth = MakeProp(9),\n"
      "            }\n"
      "            s._thumb = {\n"
      "                Depth = MakeProp(11),\n"
      "            }\n"
      "            s.SetValue = function(self, v) self._val = v end\n"
      "            s.GetValue = function(self) return self._val end\n"
      "            s.SetEndValue = function(self, v) self._endValue = v end\n"
      "            return s\n"
      "        end\n"
      "        return { IntegerSlider = S }\n"
      "    elseif mod == '/lua/ui/dialogs/eschandler.lua' then\n"
      "        return {\n"
      "            PushEscapeHandler = function(fn) end,\n"
      "            PopEscapeHandler = function() end,\n"
      "        }\n"
      "    end\n"
      "    error('Unknown mock import: ' .. tostring(mod))\n"
      "end\n"
      "\n"
      "function ClassUI(...)\n"
      "    return function(members)\n"
      "        local c = {}\n"
      "        for k, v in G do c[k] = v end\n"
      "        for k, v in members do\n"
      "            c[k] = v\n"
      "        end\n"
      "        setmetatable(c, {\n"
      "            __call = function(cls, p1, p2, p3, p4)\n"
      "                local inst = {}\n"
      "                for k, v in cls do inst[k] = v end\n"
      "                if inst.__init then\n"
      "                    inst:__init(p1, p2, p3, p4)\n"
      "                end\n"
      "                return inst\n"
      "            end\n"
      "        })\n"
      "        return c\n"
      "    end\n"
      "end\n"
      "\n"
      "function GetFrame(n)\n"
      "    local f = { _depth = 1 }\n"
      "    f.GetTopmostDepth = function(self) return 10 end\n"
      "    f.Depth = MakeProp(10)\n"
      "    f.Top = MakeProp(0)\n"
      "    f.Bottom = MakeProp(1080)\n"
      "    f.Left = MakeProp(0)\n"
      "    f.Right = MakeProp(1920)\n"
      "    f.Width = MakeProp(1920)\n"
      "    f.Height = MakeProp(1080)\n"
      "    return f\n"
      "end\n";

    CHECK(moho::SCR_LuaDoString(mockEnv, &state));

    // Register engine replay functions into test state
    moho::func_GetReplayTotalTicks_LuaFuncDef()->Run(&state);
    moho::func_ScrubReplay_LuaFuncDef()->Run(&state);
    moho::func_CancelReplayScrub_LuaFuncDef()->Run(&state);
    moho::func_IsReplayScrubbing_LuaFuncDef()->Run(&state);
    moho::func_GetReplayScrubProgress_LuaFuncDef()->Run(&state);
    moho::func_GetGameTickUser_LuaFuncDef()->Run(&state);

    std::string timelineLua = ReadFileToString("data/fafengine/lua/ui/game/replay_timeline.lua");
    if (timelineLua.empty()) {
      timelineLua = ReadFileToString("../data/fafengine/lua/ui/game/replay_timeline.lua");
    }
    if (timelineLua.empty()) {
      timelineLua = ReadFileToString("../../data/fafengine/lua/ui/game/replay_timeline.lua");
    }
    if (timelineLua.empty()) {
      timelineLua = ReadFileToString("../../../data/fafengine/lua/ui/game/replay_timeline.lua");
    }
    CHECK(!timelineLua.empty());

    // Execute replay_timeline.lua in engine Lua state
    CHECK(moho::SCR_LuaDoString(timelineLua.c_str(), &state));

    // Verify functions exported
    CHECK(state.GetGlobal("CreateReplayTimeline").IsFunction());
    CHECK(state.GetGlobal("GetTimelineControl").IsFunction());
    CHECK(state.GetGlobal("GetScrubOverlay").IsFunction());

    // Create the timeline
    CHECK(moho::SCR_LuaDoString("tb = CreateReplayTimeline(GetFrame(0))", &state));
    CHECK(!state.GetGlobal("tb").IsNil());

    // Verify overlay
    CHECK(moho::SCR_LuaDoString("ov = GetScrubOverlay()", &state));
    CHECK(!state.GetGlobal("ov").IsNil());

    // Test overlay Show/Update/Hide cycle
    CHECK(moho::SCR_LuaDoString("ov:ShowOverlay(1200)", &state));
    CHECK(moho::SCR_LuaDoString("ish = ov:IsHidden()", &state));
    CHECK(state.GetGlobal("ish").GetBoolean() == false);

    CHECK(moho::SCR_LuaDoString("ov:UpdateProgress({ progress = 0.5, currentTick = 600, targetTick = 1200 })", &state));

    CHECK(moho::SCR_LuaDoString("ov:HideOverlay()", &state));
    CHECK(moho::SCR_LuaDoString("ish = ov:IsHidden()", &state));
    CHECK(state.GetGlobal("ish").GetBoolean() == true);

    // Test timeline frame update
    CHECK(moho::SCR_LuaDoString("tb:OnFrame(0.016)", &state));

    // Test gamemain.lua hook
    std::string gamemainLua = ReadFileToString("data/fafengine/lua/ui/game/gamemain.lua");
    if (gamemainLua.empty()) {
      gamemainLua = ReadFileToString("../data/fafengine/lua/ui/game/gamemain.lua");
    }
    if (gamemainLua.empty()) {
      gamemainLua = ReadFileToString("../../data/fafengine/lua/ui/game/gamemain.lua");
    }
    if (gamemainLua.empty()) {
      gamemainLua = ReadFileToString("../../../data/fafengine/lua/ui/game/gamemain.lua");
    }
    CHECK(!gamemainLua.empty());

    // Setup mock gamemain base functions
    const char* const mockGameMainBase =
      "CreateUICalled = false\n"
      "OnFirstUpdateCalled = false\n"
      "function CreateUI(isReplay)\n"
      "    CreateUICalled = true\n"
      "end\n"
      "function OnFirstUpdate()\n"
      "    OnFirstUpdateCalled = true\n"
      "end\n"
      "function SessionIsReplay()\n"
      "    return true\n"
      "end\n";
    CHECK(moho::SCR_LuaDoString(mockGameMainBase, &state));

    // Execute gamemain.lua hook
    CHECK(moho::SCR_LuaDoString(gamemainLua.c_str(), &state));

    // Call hooked CreateUI
    CHECK(moho::SCR_LuaDoString("CreateUI(true)", &state));
    CHECK(state.GetGlobal("CreateUICalled").GetBoolean() == true);

    // Call hooked OnFirstUpdate
    CHECK(moho::SCR_LuaDoString("OnFirstUpdate()", &state));
    CHECK(state.GetGlobal("OnFirstUpdateCalled").GetBoolean() == true);

    // Cleanup
    CHECK(moho::SCR_LuaDoString("tb:OnDestroy()", &state));
    CHECK(moho::SCR_LuaDoString("ctrl = GetTimelineControl()", &state));
    CHECK(state.GetGlobal("ctrl").GetBoolean() == false);
  }

  moho::CMessage MakeVerifyChecksumMessage(const gpg::MD5Digest& digest, const std::int32_t beat)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_VerifyChecksum);
    msg.Append(reinterpret_cast<const char*>(&digest), sizeof(digest));
    msg.Append(reinterpret_cast<const char*>(&beat), sizeof(beat));
    return msg;
  }

  moho::CMessage MakeSetCommandSourceMessage(const std::uint8_t sourceId)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_SetCommandSource);
    msg.Append(reinterpret_cast<const char*>(&sourceId), sizeof(sourceId));
    return msg;
  }

  moho::CMessage MakeProcessInfoPairMessage(const moho::EntId id, const char* const key, const char* const val)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_ProcessInfoPair);
    msg.Append(reinterpret_cast<const char*>(&id), sizeof(id));
    msg.Append(key, std::strlen(key) + 1);
    msg.Append(val, std::strlen(val) + 1);
    return msg;
  }

  moho::CMessage MakeDestroyEntityMessage(const moho::EntId id)
  {
    moho::CMessage msg(moho::ECmdStreamOp::CMDST_DestroyEntity);
    msg.Append(reinterpret_cast<const char*>(&id), sizeof(id));
    return msg;
  }

  bool AreDigestsEqual(const gpg::MD5Digest& a, const gpg::MD5Digest& b)
  {
    return a.vals[0] == b.vals[0] &&
           a.vals[1] == b.vals[1] &&
           a.vals[2] == b.vals[2] &&
           a.vals[3] == b.vals[3];
  }

  class ParityTestStateSink final : public moho::ICommandSink
  {
  public:
    std::int32_t currentBeat{0};
    std::uint8_t currentSource{0};
    std::map<moho::EntId, std::map<std::string, std::string>> entityInfo;
    std::vector<std::pair<std::int32_t, gpg::MD5Digest>> verifiedChecksums;
    std::vector<std::string> log;

    void SetCommandSource(const moho::CommandSourceId sourceId) override
    {
      currentSource = sourceId;
      log.push_back("SetSource:" + std::to_string(sourceId));
    }
    void OnCommandSourceTerminated() override {}
    void VerifyChecksum(const gpg::MD5Digest& digest, const moho::CSeqNo seqNo) override
    {
      (void)seqNo;
      verifiedChecksums.push_back({currentBeat, digest});
      log.push_back("VerifyChecksum:beat=" + std::to_string(currentBeat));
    }
    void RequestPause() override {}
    void Resume() override {}
    void SingleStep() override {}
    void CreateUnit(std::uint32_t, const moho::RResId&, const moho::SCoordsVec2&, float) override {}
    void CreateProp(const char*, const Wm3::Vec3f&) override {}
    void DestroyEntity(const moho::EntId id) override
    {
      entityInfo.erase(id);
      log.push_back("Destroy:" + std::to_string(id));
    }
    void WarpEntity(moho::EntId, const moho::VTransform&) override {}
    void ProcessInfoPair(const moho::EntId id, const gpg::StrArg key, const gpg::StrArg value) override
    {
      entityInfo[id][key != nullptr ? key : ""] = value != nullptr ? value : "";
      log.push_back("InfoPair:" + std::to_string(id) + ":" + (key != nullptr ? key : "") + "=" + (value != nullptr ? value : ""));
    }
    void IssueCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>&,
      const moho::SSTICommandIssueData&,
      bool
    ) override {}
    void IssueFactoryCommand(
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>&,
      const moho::SSTICommandIssueData&,
      bool
    ) override {}
    void IncreaseCommandCount(moho::CmdId, int) override {}
    void DecreaseCommandCount(moho::CmdId, int) override {}
    void SetCommandTarget(moho::CmdId, const moho::SSTITarget&) override {}
    void SetCommandType(moho::CmdId, moho::EUnitCommandType) override {}
    void SetCommandCells(
      moho::CmdId,
      const gpg::core::FastVector<moho::SOCellPos>&,
      const Wm3::Vector3<float>&
    ) override {}
    void RemoveCommandFromUnitQueue(moho::CmdId, moho::EntId) override {}
    void ExecuteLuaInSim(const char*, const LuaPlus::LuaObject&) override {}
    void LuaSimCallback(
      const char*,
      const LuaPlus::LuaObject&,
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>&
    ) override {}
    void ExecuteDebugCommand(
      const char*,
      const Wm3::Vector3<float>&,
      std::uint32_t,
      const moho::BVSet<moho::EntId, moho::EntIdUniverse>&
    ) override {}
    void AdvanceBeat(const int delta) override
    {
      currentBeat += delta;
      log.push_back("Advance:" + std::to_string(delta) + "->beat=" + std::to_string(currentBeat));
    }
    void EndGame() override {}

    [[nodiscard]] gpg::MD5Digest ComputeStateDigest() const
    {
      gpg::MD5Context ctx;
      ctx.Reset();
      ctx.Update(&currentBeat, sizeof(currentBeat));
      ctx.Update(&currentSource, sizeof(currentSource));
      for (const auto& pair : entityInfo) {
        const moho::EntId entityId = pair.first;
        ctx.Update(&entityId, sizeof(entityId));
        for (const auto& kv : pair.second) {
          ctx.Update(kv.first.data(), kv.first.size());
          ctx.Update(kv.second.data(), kv.second.size());
        }
      }
      for (const auto& ck : verifiedChecksums) {
        ctx.Update(&ck.first, sizeof(ck.first));
        ctx.Update(ck.second.vals, sizeof(ck.second.vals));
      }
      return ctx.Digest();
    }
  };

  void DispatchFrameWithMaxBeats(
    moho::CWldSession* const session,
    moho::CDecoder& decoder,
    const std::vector<std::vector<moho::CMessage>>& beats,
    const std::int32_t customMaxBeats,
    const float deltaSeconds = 0.05f
  )
  {
    if (session->mLastBeatWasTick == 0 || session->mIsScrubbing) {
      session->mTimeSinceLastTick = 1.0f;
    } else {
      session->mTimeSinceLastTick += 1.0f * deltaSeconds * 10.0f;
    }

    const std::int32_t targetTick =
      session->mGameTick + static_cast<std::int32_t>(std::floor(session->mTimeSinceLastTick));
    const bool wasScrubbing = session->mIsScrubbing;

    std::int32_t beatsApplied = 0;
    if (session->mIsScrubbing) {
      while (beatsApplied < customMaxBeats && session->mGameTick < session->mScrubTargetBeat &&
             session->mGameTick < static_cast<std::int32_t>(beats.size()) - 1) {
        const std::int32_t nextBeat = session->mGameTick + 1;
        for (const auto& msg : beats[nextBeat]) {
          moho::CMessage copy = msg;
          decoder.ReceiveMessage(&copy, nullptr);
        }
        session->mGameTick = nextBeat;
        session->mLastBeatWasTick = 1;
        ++beatsApplied;
      }

      if (session->mGameTick >= session->mScrubTargetBeat ||
          (session->mTotalReplayBeats > 0 && session->mGameTick >= session->mTotalReplayBeats)) {
        session->mIsScrubbing = false;
        session->mScrubTargetBeat = -1;
      }
    } else {
      for (; beatsApplied < 100; ++beatsApplied) {
        if (session->mGameTick >= targetTick) {
          break;
        }
        if (session->mGameTick >= static_cast<std::int32_t>(beats.size()) - 1) {
          break;
        }
        const std::int32_t nextBeat = session->mGameTick + 1;
        for (const auto& msg : beats[nextBeat]) {
          moho::CMessage copy = msg;
          decoder.ReceiveMessage(&copy, nullptr);
        }
        session->mGameTick = nextBeat;
        session->mLastBeatWasTick = 1;
      }
    }

    if (!wasScrubbing) {
      const float remainder = session->mTimeSinceLastTick - static_cast<float>(beatsApplied);
      session->mTimeSinceLastTick = std::max(0.0f, std::min(remainder, 1.0f));
    } else if (wasScrubbing && !session->mIsScrubbing) {
      session->mTimeSinceLastTick = 0.0f;
    }
  }

  void DispatchFrame(
    moho::CWldSession* const session,
    moho::CDecoder& decoder,
    const std::vector<std::vector<moho::CMessage>>& beats,
    const float deltaSeconds = 0.05f
  )
  {
    DispatchFrameWithMaxBeats(session, decoder, beats, 500, deltaSeconds);
  }

  std::vector<std::vector<moho::CMessage>> BuildTestReplayStream(const int totalBeats)
  {
    std::vector<std::vector<moho::CMessage>> beats(totalBeats + 1);

    const gpg::MD5Digest digest15{{0x15151515, 0x01, 0x02, 0x03}};
    const gpg::MD5Digest digest45{{0x45454545, 0x04, 0x05, 0x06}};
    const gpg::MD5Digest digest75{{0x75757575, 0x07, 0x08, 0x09}};
    const gpg::MD5Digest digest100{{0x10001000, 0x0A, 0x0B, 0x0C}};

    for (int b = 1; b <= totalBeats; ++b) {
      beats[b].push_back(MakeAdvanceMessage(1));
    }

    beats[1].push_back(MakeSetCommandSourceMessage(0));
    beats[10].push_back(MakeProcessInfoPairMessage(100, "state", "initializing"));
    beats[15].push_back(MakeVerifyChecksumMessage(digest15, 15));
    beats[25].push_back(MakeSetCommandSourceMessage(1));
    beats[30].push_back(MakeProcessInfoPairMessage(200, "state", "building"));
    beats[45].push_back(MakeVerifyChecksumMessage(digest45, 45));
    beats[50].push_back(MakeProcessInfoPairMessage(100, "upgrade", "tech2"));
    beats[65].push_back(MakeDestroyEntityMessage(200));
    beats[75].push_back(MakeVerifyChecksumMessage(digest75, 75));
    beats[90].push_back(MakeProcessInfoPairMessage(100, "state", "combat"));
    beats[100].push_back(MakeVerifyChecksumMessage(digest100, 100));

    return beats;
  }

  void TestReplayScrubbingChecksumParity()
  {
    constexpr int kTotalBeats = 100;
    const auto beats = BuildTestReplayStream(kTotalBeats);

    // 1. Normal pacing run to beat 75
    alignas(moho::CWldSession) std::uint8_t bufferNormal[sizeof(moho::CWldSession)];
    std::memset(bufferNormal, 0, sizeof(bufferNormal));
    moho::CWldSession* const sessionNormal = reinterpret_cast<moho::CWldSession*>(bufferNormal);
    sessionNormal->IsReplay = true;
    sessionNormal->mTotalReplayBeats = kTotalBeats;
    sessionNormal->mGameTick = 0;
    sessionNormal->mScrubTargetBeat = -1;
    sessionNormal->mIsScrubbing = false;

    ParityTestStateSink sinkNormal;
    LuaPlus::LuaState luaNormal(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingNormal;
    moho::CDecoder decoderNormal(&sinkNormal, recordingNormal, nullptr, &luaNormal);

    while (sessionNormal->mGameTick < 75) {
      DispatchFrame(sessionNormal, decoderNormal, beats, 0.05f);
    }

    CHECK(sessionNormal->mGameTick == 75);
    CHECK(sinkNormal.currentBeat == 75);
    CHECK(sinkNormal.verifiedChecksums.size() == 3); // 15, 45, 75

    const gpg::MD5Digest goldenDigest75 = sinkNormal.ComputeStateDigest();

    // 2. Fast-forward scrub run from beat 0 to beat 75
    alignas(moho::CWldSession) std::uint8_t bufferScrub[sizeof(moho::CWldSession)];
    std::memset(bufferScrub, 0, sizeof(bufferScrub));
    moho::CWldSession* const sessionScrub = reinterpret_cast<moho::CWldSession*>(bufferScrub);
    sessionScrub->IsReplay = true;
    sessionScrub->mTotalReplayBeats = kTotalBeats;
    sessionScrub->mGameTick = 0;
    sessionScrub->mScrubTargetBeat = -1;
    sessionScrub->mIsScrubbing = false;

    ParityTestStateSink sinkScrub;
    LuaPlus::LuaState luaScrub(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingScrub;
    moho::CDecoder decoderScrub(&sinkScrub, recordingScrub, nullptr, &luaScrub);

    sessionScrub->StartScrubToBeat(75);
    CHECK(sessionScrub->IsScrubbing() == true);
    CHECK(sessionScrub->mScrubStartBeat == 0);
    CHECK(sessionScrub->mScrubTargetBeat == 75);
    CHECK(sessionScrub->GetScrubProgress() == 0.0f);

    // Turbo frame processing reaches target
    DispatchFrame(sessionScrub, decoderScrub, beats, 0.05f);

    CHECK(sessionScrub->mGameTick == 75);
    CHECK(sessionScrub->IsScrubbing() == false);
    CHECK(sessionScrub->mScrubTargetBeat == -1);
    CHECK(sessionScrub->GetScrubProgress() == 0.0f);
    CHECK(sinkScrub.currentBeat == 75);
    CHECK(sinkScrub.verifiedChecksums.size() == 3);

    // 3. Bit-for-bit parity verification
    const gpg::MD5Digest scrubDigest75 = sinkScrub.ComputeStateDigest();
    CHECK(AreDigestsEqual(scrubDigest75, goldenDigest75));
    CHECK(sinkScrub.entityInfo == sinkNormal.entityInfo);
    for (std::size_t i = 0; i < sinkNormal.verifiedChecksums.size(); ++i) {
      CHECK(sinkScrub.verifiedChecksums[i].first == sinkNormal.verifiedChecksums[i].first);
      CHECK(AreDigestsEqual(sinkScrub.verifiedChecksums[i].second, sinkNormal.verifiedChecksums[i].second));
    }
  }

  void TestReplayScrubbingCancellation()
  {
    constexpr int kTotalBeats = 100;
    const auto beats = BuildTestReplayStream(kTotalBeats);

    // 1. Establish golden state at beat 45 under normal pacing
    alignas(moho::CWldSession) std::uint8_t bufferNormal[sizeof(moho::CWldSession)];
    std::memset(bufferNormal, 0, sizeof(bufferNormal));
    moho::CWldSession* const sessionNormal = reinterpret_cast<moho::CWldSession*>(bufferNormal);
    sessionNormal->IsReplay = true;
    sessionNormal->mTotalReplayBeats = kTotalBeats;
    sessionNormal->mGameTick = 0;
    sessionNormal->mScrubTargetBeat = -1;
    sessionNormal->mIsScrubbing = false;

    ParityTestStateSink sinkNormal;
    LuaPlus::LuaState luaNormal(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingNormal;
    moho::CDecoder decoderNormal(&sinkNormal, recordingNormal, nullptr, &luaNormal);

    while (sessionNormal->mGameTick < 45) {
      DispatchFrame(sessionNormal, decoderNormal, beats, 0.05f);
    }
    CHECK(sessionNormal->mGameTick == 45);
    const gpg::MD5Digest goldenDigest45 = sinkNormal.ComputeStateDigest();

    // 2. Start scrub to beat 80 on new session
    alignas(moho::CWldSession) std::uint8_t bufferCancel[sizeof(moho::CWldSession)];
    std::memset(bufferCancel, 0, sizeof(bufferCancel));
    moho::CWldSession* const sessionCancel = reinterpret_cast<moho::CWldSession*>(bufferCancel);
    sessionCancel->IsReplay = true;
    sessionCancel->mTotalReplayBeats = kTotalBeats;
    sessionCancel->mGameTick = 0;
    sessionCancel->mScrubTargetBeat = -1;
    sessionCancel->mIsScrubbing = false;

    ParityTestStateSink sinkCancel;
    LuaPlus::LuaState luaCancel(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingCancel;
    moho::CDecoder decoderCancel(&sinkCancel, recordingCancel, nullptr, &luaCancel);

    sessionCancel->StartScrubToBeat(80);
    CHECK(sessionCancel->IsScrubbing() == true);
    CHECK(sessionCancel->mScrubTargetBeat == 80);

    // 3. Process a subset of beats in scrub mode: 25 beats
    DispatchFrameWithMaxBeats(sessionCancel, decoderCancel, beats, 25);
    CHECK(sessionCancel->mGameTick == 25);
    CHECK(sessionCancel->IsScrubbing() == true);
    CHECK(std::abs(sessionCancel->GetScrubProgress() - (25.0f / 80.0f)) < 1e-4f);

    // 4. Cancel scrubbing mid-way
    sessionCancel->CancelScrub();
    CHECK(sessionCancel->IsScrubbing() == false);
    CHECK(sessionCancel->mScrubTargetBeat == -1);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == -1);

    // 5. Verify normal pacing resumes cleanly
    // A frame with small delta time (0.05s * 10 = 0.5 ticks) does not step
    DispatchFrame(sessionCancel, decoderCancel, beats, 0.05f);
    CHECK(sessionCancel->mGameTick == 25);

    // Second frame reaches 1.0 tick, advancing exactly 1 tick
    DispatchFrame(sessionCancel, decoderCancel, beats, 0.05f);
    CHECK(sessionCancel->mGameTick == 26);

    // Continue normal pacing to beat 45
    while (sessionCancel->mGameTick < 45) {
      DispatchFrame(sessionCancel, decoderCancel, beats, 0.05f);
    }
    CHECK(sessionCancel->mGameTick == 45);

    // Parity at beat 45 must match golden state bit-for-bit
    const gpg::MD5Digest cancelDigest45 = sinkCancel.ComputeStateDigest();
    CHECK(AreDigestsEqual(cancelDigest45, goldenDigest45));
    CHECK(sinkCancel.entityInfo == sinkNormal.entityInfo);
    CHECK(sinkCancel.verifiedChecksums.size() == sinkNormal.verifiedChecksums.size());
  }

  void TestReplayScrubbingBackwardSeek()
  {
    constexpr int kTotalBeats = 100;
    const auto beats = BuildTestReplayStream(kTotalBeats);

    // 1. Establish golden state at beat 30 under normal pacing
    alignas(moho::CWldSession) std::uint8_t bufferNormal[sizeof(moho::CWldSession)];
    std::memset(bufferNormal, 0, sizeof(bufferNormal));
    moho::CWldSession* const sessionNormal = reinterpret_cast<moho::CWldSession*>(bufferNormal);
    sessionNormal->IsReplay = true;
    sessionNormal->mTotalReplayBeats = kTotalBeats;
    sessionNormal->mGameTick = 0;
    sessionNormal->mScrubTargetBeat = -1;
    sessionNormal->mIsScrubbing = false;

    ParityTestStateSink sinkNormal;
    LuaPlus::LuaState luaNormal(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingNormal;
    moho::CDecoder decoderNormal(&sinkNormal, recordingNormal, nullptr, &luaNormal);

    while (sessionNormal->mGameTick < 30) {
      DispatchFrame(sessionNormal, decoderNormal, beats, 0.05f);
    }
    CHECK(sessionNormal->mGameTick == 30);
    const gpg::MD5Digest goldenDigest30 = sinkNormal.ComputeStateDigest();
    const auto goldenEntityInfo30 = sinkNormal.entityInfo;
    const auto goldenChecksums30 = sinkNormal.verifiedChecksums;

    // Continue normal run to beat 75
    while (sessionNormal->mGameTick < 75) {
      DispatchFrame(sessionNormal, decoderNormal, beats, 0.05f);
    }
    CHECK(sessionNormal->mGameTick == 75);

    // 2. User seeks backward from 75 to 30: backward seek safely cancels/no-ops without hanging session
    sessionNormal->StartScrubToBeat(30);
    CHECK(sessionNormal->IsScrubbing() == false);
    CHECK(sessionNormal->mScrubTargetBeat == -1);

    // 3. Create fresh replay session from beat 0 to verify scrub to 30
    alignas(moho::CWldSession) std::uint8_t bufferRestarted[sizeof(moho::CWldSession)];
    std::memset(bufferRestarted, 0, sizeof(bufferRestarted));
    moho::CWldSession* const sessionRestarted = reinterpret_cast<moho::CWldSession*>(bufferRestarted);
    sessionRestarted->IsReplay = true;
    sessionRestarted->mTotalReplayBeats = kTotalBeats;
    sessionRestarted->mGameTick = 0;
    sessionRestarted->mScrubTargetBeat = -1;
    sessionRestarted->mIsScrubbing = false;

    ParityTestStateSink sinkRestarted;
    LuaPlus::LuaState luaRestarted(LuaPlus::LuaState::LIB_BASE);
    msvc8::auto_ptr<gpg::Stream> recordingRestarted;
    moho::CDecoder decoderRestarted(&sinkRestarted, recordingRestarted, nullptr, &luaRestarted);

    sessionRestarted->StartScrubToBeat(30);
    CHECK(sessionRestarted->IsScrubbing() == true);
    CHECK(sessionRestarted->mScrubTargetBeat == 30);
    CHECK(sessionRestarted->mScrubStartBeat == 0);

    // Turbo scrub frame reaches beat 30
    DispatchFrame(sessionRestarted, decoderRestarted, beats, 0.05f);

    CHECK(sessionRestarted->mGameTick == 30);
    CHECK(sessionRestarted->IsScrubbing() == false);
    CHECK(sessionRestarted->mScrubTargetBeat == -1);
    CHECK(sessionRestarted->GetScrubProgress() == 0.0f);
    CHECK(sinkRestarted.currentBeat == 30);

    // 6. Verify bit-for-bit parity at beat 30
    const gpg::MD5Digest restartedDigest30 = sinkRestarted.ComputeStateDigest();
    CHECK(AreDigestsEqual(restartedDigest30, goldenDigest30));
    CHECK(sinkRestarted.entityInfo == goldenEntityInfo30);
    CHECK(sinkRestarted.verifiedChecksums.size() == goldenChecksums30.size());
    for (std::size_t i = 0; i < goldenChecksums30.size(); ++i) {
      CHECK(sinkRestarted.verifiedChecksums[i].first == goldenChecksums30[i].first);
      CHECK(AreDigestsEqual(sinkRestarted.verifiedChecksums[i].second, goldenChecksums30[i].second));
    }
  }

  struct TestCase
  {
    const char* name;
    void (*func)();
  };

  const TestCase kTests[] = {
    {"empty stream", &TestEmptyStream},
    {"null stream", &TestNullStream},
    {"single advance", &TestSingleAdvanceMessage},
    {"multiple mixed messages", &TestMultipleAdvanceAndOtherMessages},
    {"stream offset rewind", &TestStreamOffsetRewind},
    {"truncated stream", &TestTruncatedStream},
    {"session info default total beats", &TestSessionInfoDefaultTotalBeats},
    {"vcr setup replay session calculates total beats", &TestVCRSetupReplaySessionCalculatesTotalBeats},
    {"wldsession scrubbing state transitions", &TestCWldSessionScrubbingStateTransitions},
    {"replay scrubbing user lua bindings", &TestReplayScrubbingUserLuaBindings},
    {"replay timeline lua syntax and execution", &TestReplayTimelineLuaSyntaxAndExecution},
    {"replay scrubbing checksum parity", &TestReplayScrubbingChecksumParity},
    {"replay scrubbing cancellation", &TestReplayScrubbingCancellation},
    {"replay scrubbing backward seek", &TestReplayScrubbingBackwardSeek},
  };
} // namespace

int main()
{
  for (const TestCase& test : kTests) {
    const int failuresBefore = gFailures;
    test.func();
    if (gFailures == failuresBefore) {
      std::printf("ok   %s\n", test.name);
    } else {
      std::printf("FAIL %s\n", test.name);
    }
  }
  std::printf("%d checks, %d failures\n", gChecks, gFailures);
  return gFailures;
}
