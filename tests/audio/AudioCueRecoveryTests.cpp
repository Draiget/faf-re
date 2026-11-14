// RecoverableCue (src/moho/audio/RecoverableCue.h): the cue AudioEngine::Play hands out on Windows, which
// outlives a rebuild of the XACT engine on a new sound output. Fake XACT cues and a fake sound
// bank stand in for XACT.
#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <set>
#include <vector>

#include "moho/audio/RecoverableCue.h"

namespace
{
  using moho::RecoverableCue;

  struct CueLog
  {
    int plays = 0;
    int stops = 0;
    int destroys = 0;
    std::map<std::uint16_t, float> variables;
  };

  class FakeCue final : public moho::IXACTCue
  {
  public:
    FakeCue(
      CueLog& log,
      const std::int32_t state
    )
      : mLog(log)
      , mState(state)
    {}

    std::int32_t __stdcall Play() override
    {
      ++mLog.plays;
      mState = RecoverableCue::kPlaying;
      return 0;
    }
    void __stdcall Stop(
      std::int32_t
    ) override
    {
      ++mLog.stops;
      mState = RecoverableCue::kStopped;
    }
    std::int32_t __stdcall GetState(
      std::int32_t* const outState
    ) override
    {
      *outState = mState;
      return 0;
    }
    std::int32_t __stdcall Destroy() override
    {
      ++mLog.destroys;
      delete this;
      return 0;
    }
    void __stdcall Reserved10() override {}
    void __stdcall Reserved14() override {}
    void __stdcall Reserved18() override {}
    void __stdcall Reserved1C() override {}
    std::int32_t __stdcall SetMatrixCoefficients(
      std::uint32_t,
      std::uint32_t,
      const float*
    ) override
    {
      return 0;
    }
    std::uint16_t __stdcall GetVariableIndex(
      const char*
    ) override
    {
      return 7u;
    }
    std::int32_t __stdcall SetVariable(
      const std::uint16_t index,
      const float value
    ) override
    {
      mLog.variables[index] = value;
      return 0;
    }

    CueLog& mLog;
    std::int32_t mState;
  };

  // Prepares FakeCues; `refuse` makes Prepare fail, as XACT does while a streaming wave bank is
  // still being prepared.
  class FakeBank final : public moho::IXACTSoundBank
  {
  public:
    std::uint16_t __stdcall GetCueIndex(
      const char*
    ) override
    {
      return 0u;
    }
    std::int32_t __stdcall Reserved04() override
    {
      return 0;
    }
    std::int32_t __stdcall Reserved08() override
    {
      return 0;
    }
    std::int32_t __stdcall Prepare(
      const std::uint16_t cueIndex,
      std::uint32_t,
      std::uint32_t,
      moho::IXACTCue** const outCue
    ) override
    {
      prepared.push_back(cueIndex);
      if (refuse) {
        *outCue = nullptr;
        return static_cast<std::int32_t>(0x8AC70016u); // the wave bank is not prepared
      }
      *outCue = new FakeCue(log, RecoverableCue::kPrepared);
      return 0;
    }
    std::int32_t __stdcall Play(
      std::uint16_t,
      std::uint32_t,
      std::uint32_t,
      moho::IXACTCue**
    ) override
    {
      return -1;
    }
    std::int32_t __stdcall Reserved14() override
    {
      return 0;
    }
    void __stdcall Destroy() override {}

    bool refuse = false;
    std::vector<std::uint16_t> prepared;
    CueLog log;
  };

  std::int32_t StateOf(
    moho::IXACTCue* const cue
  )
  {
    std::int32_t state = 0;
    EXPECT_EQ(cue->GetState(&state), 0);
    return state;
  }
} // namespace

TEST(
  AudioCueRecovery,
  PlayingCueComesBackPlayingWithItsVariables
)
{
  std::set<RecoverableCue*> registry;
  CueLog oldLog;
  auto* const cue = new RecoverableCue(registry, nullptr, new FakeCue(oldLog, RecoverableCue::kPlaying), 3u, 42u, true);
  EXPECT_EQ(registry.size(), 1u);
  const std::uint16_t index = cue->GetVariableIndex("Distance");
  EXPECT_EQ(cue->SetVariable(index, 0.5f), 0);

  cue->Detach();
  EXPECT_EQ(oldLog.destroys, 1);
  EXPECT_FALSE(cue->HasCue());
  // Without its XACT cue it still reads as playing, so the game neither reaps nor replays it.
  EXPECT_EQ(StateOf(cue), RecoverableCue::kPlaying);
  EXPECT_EQ(cue->GetVariableIndex("Distance"), index);

  FakeBank bank;
  EXPECT_TRUE(cue->Restore(&bank));
  EXPECT_TRUE(cue->HasCue());
  ASSERT_EQ(bank.prepared.size(), 1u);
  EXPECT_EQ(bank.prepared[0], 42u);
  EXPECT_EQ(bank.log.plays, 1);
  EXPECT_FLOAT_EQ(bank.log.variables[index], 0.5f);

  EXPECT_EQ(cue->Destroy(), 0);
  EXPECT_EQ(bank.log.destroys, 1);
  EXPECT_TRUE(registry.empty());
}

TEST(
  AudioCueRecovery,
  PreparedCueComesBackPreparedAndPlaysLater
)
{
  std::set<RecoverableCue*> registry;
  CueLog oldLog;
  auto* const cue =
    new RecoverableCue(registry, nullptr, new FakeCue(oldLog, RecoverableCue::kPrepared), 0u, 1u, false);
  cue->Detach();
  EXPECT_EQ(StateOf(cue), RecoverableCue::kPrepared);

  FakeBank bank;
  EXPECT_TRUE(cue->Restore(&bank));
  EXPECT_EQ(bank.log.plays, 0);
  EXPECT_EQ(cue->Play(), 0);
  EXPECT_EQ(bank.log.plays, 1);
  (void)cue->Destroy();
}

TEST(
  AudioCueRecovery,
  StoppedCueStaysStopped
)
{
  std::set<RecoverableCue*> registry;
  CueLog oldLog;
  auto* const cue = new RecoverableCue(registry, nullptr, new FakeCue(oldLog, RecoverableCue::kPlaying), 0u, 1u, true);
  cue->Stop(0);
  EXPECT_EQ(oldLog.stops, 1);
  cue->Detach();

  FakeBank bank;
  EXPECT_TRUE(cue->Restore(&bank));
  EXPECT_TRUE(bank.prepared.empty());
  EXPECT_EQ(StateOf(cue), RecoverableCue::kStopped);
  (void)cue->Destroy();
}

TEST(
  AudioCueRecovery,
  CueThatEndedBeforeTheRebuildIsNotPlayedAgain
)
{
  std::set<RecoverableCue*> registry;
  CueLog oldLog;
  auto* const fake = new FakeCue(oldLog, RecoverableCue::kPlaying);
  auto* const cue = new RecoverableCue(registry, nullptr, fake, 0u, 1u, true);
  fake->mState = RecoverableCue::kStopped; // a one-shot sound that finished on its own
  cue->Detach();

  FakeBank bank;
  EXPECT_TRUE(cue->Restore(&bank));
  EXPECT_TRUE(bank.prepared.empty());
  EXPECT_EQ(StateOf(cue), RecoverableCue::kStopped);
  (void)cue->Destroy();
}

TEST(
  AudioCueRecovery,
  RestoreWaitsForTheBankThenGivesUp
)
{
  std::set<RecoverableCue*> registry;
  CueLog oldLog;
  auto* const cue = new RecoverableCue(registry, nullptr, new FakeCue(oldLog, RecoverableCue::kPlaying), 0u, 1u, true);
  cue->Detach();

  EXPECT_FALSE(cue->Restore(nullptr)); // no sound bank yet
  FakeBank bank;
  bank.refuse = true;
  EXPECT_FALSE(cue->Restore(&bank)); // its streaming wave bank is still being prepared
  EXPECT_EQ(StateOf(cue), RecoverableCue::kPlaying);

  cue->Abandon();
  EXPECT_EQ(StateOf(cue), RecoverableCue::kStopped);
  bank.refuse = false;
  EXPECT_TRUE(cue->Restore(&bank));
  EXPECT_EQ(bank.prepared.size(), 1u); // only the refused try
  (void)cue->Destroy();
}

TEST(
  AudioCueRecovery,
  CueOutlivesItsEngine
)
{
  auto* const registry = new std::set<RecoverableCue*>();
  CueLog oldLog;
  auto* const cue = new RecoverableCue(*registry, nullptr, new FakeCue(oldLog, RecoverableCue::kPlaying), 0u, 1u, true);
  cue->Detach(true); // the engine is destroyed while the game still holds the cue
  delete registry;
  EXPECT_EQ(oldLog.destroys, 1);
  EXPECT_EQ(StateOf(cue), RecoverableCue::kStopped);
  EXPECT_EQ(cue->Play(), 0);
  EXPECT_EQ(StateOf(cue), RecoverableCue::kStopped);
  EXPECT_EQ(cue->Destroy(), 0); // no registry left to leave
}
