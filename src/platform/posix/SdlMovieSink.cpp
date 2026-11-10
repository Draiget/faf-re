// Engine addition (issue #255): moho::sfd::AudioSink (moho/movie/sfd/DirectSoundMovieSink.h) on an
// SDL3 audio stream, for the Linux client. It keeps the DirectSound sink's contract: 48 kHz 16-bit
// stereo, at most two seconds queued, Clock() the seconds the device has taken (updated by Pump),
// Submitted() the seconds written, playback held while paused or empty, volume as DirectSound
// attenuation in hundredths of a decibel.

#include "platform/posix/SdlMovieSink.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <SDL3/SDL.h>

#include "moho/movie/sfd/DirectSoundMovieSink.h"

namespace
{
  constexpr std::uint64_t kBytesPerSecond = 48000u * 2u * 2u;
  constexpr std::uint64_t kCapacity = kBytesPerSecond * 2u;

  // Any non-null address will do: the movie player only tests the device for null.
  unsigned char gMovieSoundToken = 0;
} // namespace

IDirectSound* platform::posix::MovieSoundDevice() noexcept
{
  return reinterpret_cast<IDirectSound*>(&gMovieSoundToken);
}

namespace moho::sfd
{
  struct AudioSink::Impl
  {
    SDL_AudioStream* stream = nullptr;
    std::uint64_t played = 0;
    std::uint64_t written = 0;
    bool paused = true;
    bool running = false;

    // What the device has taken: everything written that the stream no longer holds.
    void Refresh()
    {
      const int queued = SDL_GetAudioStreamQueued(stream);
      if (queued >= 0) {
        played = written - std::min<std::uint64_t>(written, static_cast<std::uint64_t>(queued));
      }
    }
  };

  AudioSink::AudioSink(IDirectSound* const device)
    : impl(std::make_unique<Impl>())
  {
    if (device == nullptr) {
      throw std::runtime_error("No movie audio device");
    }
    if (!SDL_InitSubSystem(SDL_INIT_AUDIO)) {
      throw std::runtime_error(std::string("Movie audio: ") + SDL_GetError());
    }
    const SDL_AudioSpec spec{SDL_AUDIO_S16LE, 2, 48000};
    // The device starts paused, as the DirectSound buffer starts stopped.
    impl->stream = SDL_OpenAudioDeviceStream(SDL_AUDIO_DEVICE_DEFAULT_PLAYBACK, &spec, nullptr, nullptr);
    if (impl->stream == nullptr) {
      const std::string error = SDL_GetError();
      SDL_QuitSubSystem(SDL_INIT_AUDIO);
      throw std::runtime_error("Movie audio: " + error);
    }
  }

  AudioSink::~AudioSink()
  {
    if (impl->stream != nullptr) {
      SDL_DestroyAudioStream(impl->stream); // closes its device too
      SDL_QuitSubSystem(SDL_INIT_AUDIO);
    }
  }

  void AudioSink::Pump()
  {
    Impl& s = *impl;
    s.Refresh();
    if (s.running && s.played == s.written) {
      (void)SDL_PauseAudioStreamDevice(s.stream);
      s.running = false;
    }
    if (!s.running && !s.paused && s.written > s.played) {
      if (!SDL_ResumeAudioStreamDevice(s.stream)) {
        throw std::runtime_error(std::string("Movie audio: ") + SDL_GetError());
      }
      s.running = true;
    }
  }

  std::size_t AudioSink::Write(const std::span<const std::int16_t> stereo)
  {
    Impl& s = *impl;
    s.Refresh();
    const std::uint64_t free = kCapacity - std::min(kCapacity, s.written - s.played);
    const std::uint64_t bytes = std::min<std::uint64_t>(stereo.size_bytes(), free) & ~std::uint64_t{3};
    if (bytes == 0) {
      return 0;
    }
    if (!SDL_PutAudioStreamData(s.stream, stereo.data(), static_cast<int>(bytes))) {
      throw std::runtime_error(std::string("Movie audio: ") + SDL_GetError());
    }
    s.written += bytes;
    return static_cast<std::size_t>(bytes / sizeof(std::int16_t));
  }

  void AudioSink::Pause(const bool paused)
  {
    Pump();
    Impl& s = *impl;
    s.paused = paused;
    if (paused && s.running) {
      (void)SDL_PauseAudioStreamDevice(s.stream);
      s.running = false;
    }
    if (!paused) {
      Pump();
    }
  }

  void AudioSink::Stop()
  {
    Impl& s = *impl;
    (void)SDL_PauseAudioStreamDevice(s.stream);
    (void)SDL_ClearAudioStream(s.stream);
    s.running = false;
    s.paused = true;
    s.played = 0;
    s.written = 0;
  }

  void AudioSink::SetVolume(const long attenuation)
  {
    // Hundredths of a decibel, -10000 (-100 dB) to 0, as DirectSound's SetVolume takes them.
    const double decibels = static_cast<double>(std::clamp(attenuation, -10000L, 0L)) / 100.0;
    (void)SDL_SetAudioStreamGain(impl->stream, static_cast<float>(std::pow(10.0, decibels / 20.0)));
  }

  double AudioSink::Clock() const
  {
    return static_cast<double>(impl->played) / static_cast<double>(kBytesPerSecond);
  }

  double AudioSink::Submitted() const
  {
    return static_cast<double>(impl->written) / static_cast<double>(kBytesPerSecond);
  }

  bool AudioSink::Empty() const
  {
    return impl->played == impl->written;
  }
} // namespace moho::sfd
