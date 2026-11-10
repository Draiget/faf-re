#pragma once

// Engine addition (issue #255): movie sound on Linux. The movie player (moho/movie/sfd) decodes
// a movie's audio only when it was given a sound device, and plays it through moho::sfd::AudioSink.
// On Windows both are DirectSound's (CMovieManager::CreateDirectSound, DirectSoundMovieSink.cpp);
// here the sink is an SDL3 audio stream (SdlMovieSink.cpp) and the device is a token that only says
// movie sound is on: nothing reads through it.

struct IDirectSound;

namespace platform::posix
{
  // The token CMovieManager hands the movie player in place of a DirectSound device.
  [[nodiscard]] IDirectSound* MovieSoundDevice() noexcept;
} // namespace platform::posix
