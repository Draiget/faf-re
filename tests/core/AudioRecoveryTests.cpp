#ifdef _WIN32
#include "moho/audio/RecoverableCue.h"
#include "moho/audio/AudioOutputSelection.h"
#include "moho/audio/XactClock.h"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace
{
  class Cue final : public moho::IXACTCue
  {
  public:
    int state = XACT_CUESTATE_PLAYING;
    int destroys = 0;
    int plays = 0;
    float variable = 0;
    bool failPlay = false;
    bool failState = false;
    std::int32_t __stdcall Play() override { ++plays; return failPlay ? E_FAIL : 0; }
    void __stdcall Stop(std::int32_t) override { state = XACT_CUESTATE_STOPPED; }
    std::int32_t __stdcall GetState(std::int32_t* out) override
    {
      if (failState) return E_FAIL;
      *out = state;
      return 0;
    }
    std::int32_t __stdcall Destroy() override { ++destroys; return 0; }
    void __stdcall Reserved10() override {}
    void __stdcall Reserved14() override {}
    void __stdcall Reserved18() override {}
    void __stdcall Reserved1C() override {}
    std::int32_t __stdcall SetMatrixCoefficients(std::uint32_t, std::uint32_t, const float*) override { return 0; }
    std::uint16_t __stdcall GetVariableIndex(const char*) override { return 3; }
    std::int32_t __stdcall SetVariable(std::uint16_t, float value) override { variable = value; return 0; }
  };

  class Bank final : public moho::IXACTSoundBank
  {
  public:
    Cue cue;
    bool ready = true;
    std::uint16_t preparedIndex = 0;
    std::uint16_t __stdcall GetCueIndex(const char*) override { return 9; }
    std::int32_t __stdcall Reserved04() override { return 0; }
    std::int32_t __stdcall Reserved08() override { return 0; }
    std::int32_t __stdcall Prepare(std::uint16_t index, std::uint32_t, std::uint32_t, moho::IXACTCue** out) override
    {
      if (!ready) return E_FAIL;
      preparedIndex = index;
      *out = &cue;
      return 0;
    }
    std::int32_t __stdcall Play(std::uint16_t, std::uint32_t, std::uint32_t, moho::IXACTCue**) override { return E_FAIL; }
    std::int32_t __stdcall Reserved14() override { return 0; }
    void __stdcall Destroy() override {}
  };
}

TEST(AudioRecovery, RetainedHandleReplaysWithVariablesOnReplacementBank)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  auto* handle = new moho::RecoverableCue(registry, &old, 2, 9, false);
  handle->SetVariable(handle->GetVariableIndex("Distance"), 42);
  handle->Detach();
  EXPECT_EQ(old.destroys, 1);
  EXPECT_EQ(handle->GetVariableIndex("Distance"), 3);
  Bank bank;
  bank.ready = false;
  EXPECT_FALSE(handle->Restore(&bank));
  bank.ready = true;
  ASSERT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.preparedIndex, 9);
  EXPECT_EQ(bank.cue.plays, 1);
  EXPECT_EQ(bank.cue.variable, 42);
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 1);
  handle->Destroy();
  EXPECT_TRUE(registry.empty());
  EXPECT_EQ(bank.cue.destroys, 1);
}

TEST(AudioRecovery, StopDuringDisconnectionPreventsReplay)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, false);
  handle->Detach();
  handle->Stop(0);
  Bank bank;
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 0);
  int state = 0;
  EXPECT_EQ(handle->GetState(&state), 0);
  EXPECT_EQ(state, XACT_CUESTATE_STOPPED);
  handle->Destroy();
}

TEST(AudioRecovery, PreparedCueWaitsForExplicitPlayAndRetriesFailedPlay)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  old.state = XACT_CUESTATE_PREPARED;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, true);
  handle->Detach();
  Bank bank;
  ASSERT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 0);
  EXPECT_EQ(handle->Play(), 0);
  handle->Detach();
  bank.cue.failPlay = true;
  EXPECT_FALSE(handle->Restore(&bank));
  bank.cue.failPlay = false;
  EXPECT_TRUE(handle->Restore(&bank));
  handle->Destroy();
}

TEST(AudioRecovery, ShutdownLeavesOutstandingHandleSafeToDestroy)
{
  Cue old;
  moho::RecoverableCue* handle;
  {
    std::set<moho::RecoverableCue*> registry;
    handle = new moho::RecoverableCue(registry, &old, 0, 9, false);
    handle->Detach(true);
  }
  int state = 0;
  EXPECT_EQ(handle->GetState(&state), 0);
  EXPECT_EQ(state, XACT_CUESTATE_STOPPED);
  handle->Destroy();
  EXPECT_EQ(old.destroys, 1);
}

TEST(AudioRecovery, FailedStateQueryDuringDeviceLossPreservesActiveCue)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, false);
  old.failState = true;
  int state = 0;
  EXPECT_EQ(handle->GetState(&state), 0);
  EXPECT_EQ(state, XACT_CUESTATE_PLAYING);
  handle->Detach();
  Bank bank;
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 1);
  handle->Destroy();
}

TEST(AudioRecovery, CompletedCueDoesNotRestartAfterDeviceChange)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  old.state = XACT_CUESTATE_STOPPED;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, false);
  handle->Detach();
  Bank bank;
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 0);
  handle->Destroy();
}

TEST(AudioRecovery, ExplicitPlayOfDetachedCueSchedulesRestoration)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  old.state = XACT_CUESTATE_STOPPED;
  bool pending = false;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, false, &pending);
  handle->Detach();
  Bank bank;
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_FALSE(pending);
  EXPECT_EQ(handle->Play(), 0);
  EXPECT_TRUE(pending);
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 1);
  handle->Destroy();
}

TEST(AudioRecovery, QueuedPlaySurvivesLossWhileCueIsStillPreparing)
{
  std::set<moho::RecoverableCue*> registry;
  Cue old;
  old.state = XACT_CUESTATE_PREPARING;
  auto* handle = new moho::RecoverableCue(registry, &old, 0, 9, false);
  handle->Detach();
  Bank bank;
  EXPECT_TRUE(handle->Restore(&bank));
  EXPECT_EQ(bank.cue.plays, 1);
  handle->Destroy();
}

TEST(AudioRecovery, ContentAndStreamingErrorsDoNotResetTheOutput)
{
  EXPECT_FALSE(moho::IsAudioOutputLost(static_cast<int>(0x8AC70010u)));
  EXPECT_FALSE(moho::IsAudioOutputLost(static_cast<int>(0x8AC70016u)));
  EXPECT_FALSE(moho::IsAudioOutputLost(E_FAIL));
  EXPECT_FALSE(moho::IsAudioOutputLost(S_OK));
  EXPECT_TRUE(moho::IsAudioOutputLost(static_cast<int>(0x8AC70017u)));
  EXPECT_TRUE(moho::IsAudioOutputLost(static_cast<int>(0x88890004u)));
}

TEST(AudioRecovery, NativeStreamingUsesTheWindowsSelectedRenderer)
{
  wchar_t path[MAX_PATH]{};
  if (!GetEnvironmentVariableW(L"FAF_AUDIO_TEST_DATA", path, MAX_PATH)) {
    GTEST_SKIP() << "Set FAF_AUDIO_TEST_DATA to the installed sounds directory for the live XACT test";
  }
  struct Resources
  {
    HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IMMDeviceEnumerator* enumerator = nullptr;
    moho::IXACTEngine* engine = nullptr;
    moho::IXACTSoundBank* bank = nullptr;
    moho::IXACTWaveBank* wave = nullptr;
    moho::IXACTCue* cue = nullptr;
    HANDLE file = INVALID_HANDLE_VALUE;
    std::vector<char> globals, bankData;
    ~Resources()
    {
      if (cue) cue->Destroy();
      if (bank) bank->Destroy();
      if (wave) wave->Destroy();
      if (engine) { engine->ShutDown(); engine->Release(); }
      if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
      if (enumerator) enumerator->Release();
      if (SUCCEEDED(com)) CoUninitialize();
    }
  } resources;
  ASSERT_TRUE(SUCCEEDED(resources.com));
  ASSERT_EQ(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_INPROC_SERVER,
                            IID_PPV_ARGS(&resources.enumerator)), S_OK);
  moho::AudioOutputDevice selected;
  ASSERT_EQ(moho::ReadSelectedAudioOutput(*resources.enumerator, selected), S_OK);
  ASSERT_FALSE(selected.rendererId.empty());
  constexpr GUID clsid{0x343e68e6,0x8f82,0x4a8d,{0xa2,0xda,0x6e,0x9a,0x94,0x4b,0x37,0x8c}};
  constexpr GUID iid{0x893ff2e4,0x8d03,0x4d5f,{0xb0,0xaa,0x36,0x3a,0x9c,0xbb,0xf4,0x37}};
  ASSERT_EQ(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, iid,
                            reinterpret_cast<void**>(&resources.engine)), S_OK);
  moho::SND_InstallXactClock(&clsid);
  std::uint16_t count = 0;
  ASSERT_GE(resources.engine->GetRendererCount(&count), 0);
  bool found = false;
  for (std::uint16_t index = 0; index < count; ++index) {
    XACT_RENDERER_DETAILS details{};
    ASSERT_GE(resources.engine->GetRendererDetails(index, &details), 0);
    if (_wcsicmp(details.rendererID, selected.rendererId.c_str()) == 0) found = true;
  }
  ASSERT_TRUE(found);
  auto read = [](const std::filesystem::path& file) {
    std::ifstream stream(file, std::ios::binary);
    return std::vector<char>{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
  };
  const std::filesystem::path directory(path);
  resources.globals = read(directory / "SupCom.xgs");
  resources.bankData = read(directory / "Music.xsb");
  ASSERT_FALSE(resources.globals.empty());
  ASSERT_FALSE(resources.bankData.empty());
  moho::AudioRuntimeParams parameters{};
  parameters.lookAheadTime = 250;
  parameters.pGlobalSettingsBuffer = resources.globals.data();
  parameters.globalSettingsBufferSize = static_cast<DWORD>(resources.globals.size());
  parameters.pRendererID = selected.rendererId.data();
  ASSERT_GE(resources.engine->Initialize(&parameters), 0);
  resources.file = CreateFileW((directory / "Music.xwb").c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  ASSERT_NE(resources.file, INVALID_HANDLE_VALUE);
  XACT_STREAMING_PARAMETERS streaming{};
  streaming.file = resources.file;
  streaming.packetSize = 0x12;
  ASSERT_GE(resources.engine->CreateStreamingWaveBank(&streaming, &resources.wave), 0);
  ASSERT_GE(resources.engine->CreateSoundBank(resources.bankData.data(),
    static_cast<std::int32_t>(resources.bankData.size()), 0, 0, &resources.bank), 0);
  const auto index = resources.bank->GetCueIndex("Main_Menu");
  ASSERT_NE(index, 0xFFFFu);
  for (int attempt = 0; attempt < 100 && !resources.cue; ++attempt) {
    ASSERT_GE(resources.engine->DoWork(), 0);
    resources.bank->Play(index, 0, 0, &resources.cue);
    Sleep(10);
  }
  ASSERT_NE(resources.cue, nullptr);
  for (int frame = 0; frame < 160; ++frame) {
    ASSERT_GE(resources.engine->DoWork(), 0);
    Sleep(16);
  }
  std::int32_t state = 0;
  ASSERT_GE(resources.cue->GetState(&state), 0);
  EXPECT_NE(state & XACT_CUESTATE_PLAYING, 0);
}

#endif
