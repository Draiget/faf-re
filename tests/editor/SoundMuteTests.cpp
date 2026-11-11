// The sound's mute reasons (moho::SND_MuteFor): the game's own mute while minimized and the map editor's while its
// window isn't in front. The engines' "Global" volume is saved and silenced once when the first reason starts and given
// back once when the last ends, so one reason's zero is never saved as the volume to give back.

#include <gtest/gtest.h>

#include "moho/audio/AudioEngine.h"

namespace
{
  TEST(
    SoundMute,
    TwoReasonsSaveAndGiveBackTheVolumeOnce
  )
  {
    ASSERT_EQ(moho::SND_MuteReasons(), 0u);
    const std::uint32_t start = moho::SND_MuteTransitions();

    moho::SND_MuteFor(moho::kSndMuteUnfocused, true); // the editor's window left the front: silenced
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 1);
    moho::SND_Mute(true); // then minimized: already silent, the saved volume untouched
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 1);
    EXPECT_EQ(moho::SND_MuteReasons(), moho::kSndMuteUnfocused | moho::kSndMuteMinimized);

    moho::SND_Mute(false); // restored but still not in front: stays silent
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 1);
    EXPECT_EQ(moho::SND_MuteReasons(), moho::kSndMuteUnfocused);

    moho::SND_MuteFor(moho::kSndMuteUnfocused, false); // in front again: the volume given back
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 2);
    EXPECT_EQ(moho::SND_MuteReasons(), 0u);
  }

  TEST(
    SoundMute,
    TheSameReasonTwiceIsOneChange
  )
  {
    const std::uint32_t start = moho::SND_MuteTransitions();
    moho::SND_MuteFor(moho::kSndMuteUnfocused, true);
    moho::SND_MuteFor(moho::kSndMuteUnfocused, true);
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 1);
    moho::SND_MuteFor(moho::kSndMuteUnfocused, false);
    moho::SND_MuteFor(moho::kSndMuteUnfocused, false);
    EXPECT_EQ(moho::SND_MuteTransitions(), start + 2);
    EXPECT_EQ(moho::SND_MuteReasons(), 0u);
  }
} // namespace
