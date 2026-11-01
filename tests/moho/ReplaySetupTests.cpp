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
#include <cmath>
#include <fstream>
#include <sstream>

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
    std::remove(path.c_str());

    CHECK(sessionInfo.get() != nullptr);
    if (sessionInfo.get() != nullptr) {
      CHECK(sessionInfo->mIsReplay == true);
      CHECK(sessionInfo->mTotalBeats == 100);
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

    // Test 6b: Backward seek with mLaunchInfo triggers pending restart target
    struct DummyLaunchInfo : moho::LaunchInfoBase
    {
      void Create(boost::SharedPtrRaw<void>& outCreated) override {}
    };
    session->mLaunchInfo.reset(new DummyLaunchInfo());
    session->StartScrubToBeat(250);
    CHECK(session->IsScrubbing() == false);
    CHECK(moho::CWldSession::sPendingRestartScrubTarget == 250);
    session->mLaunchInfo.reset();

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
      "        }\n"
      "    elseif mod == '/lua/maui/layouthelpers.lua' then\n"
      "        local lh = {}\n"
      "        lh.ScaleNumber = function(n) return n end\n"
      "        lh.FillParent = function(c, p) end\n"
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
      timelineLua = ReadFileToString("../../data/fafengine/lua/ui/game/replay_timeline.lua");
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
      gamemainLua = ReadFileToString("../../data/fafengine/lua/ui/game/gamemain.lua");
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
