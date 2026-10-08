#include "DirectSoundMovieSink.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>

// DirectSound requires the multimedia types even with WIN32_LEAN_AND_MEAN.
// clang-format off
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>
// clang-format on

namespace moho::sfd
{
  namespace
  {
    constexpr DWORD bytesPerSecond = 48000 * 2 * 2;
    constexpr DWORD capacity = bytesPerSecond * 2;
    constexpr DWORD guardBytes = bytesPerSecond / 20;
    void Check(
      HRESULT result
    )
    {
      if (FAILED(result))
        throw std::runtime_error("DirectSound movie streaming buffer failed");
    }
    struct BufferDelete
    {
      void operator()(
        IDirectSoundBuffer* p
      ) const
      {
        if (p)
          p->Release();
      }
    };
  } // namespace
  struct AudioSink::Impl
  {
    std::unique_ptr<IDirectSoundBuffer, BufferDelete> buffer;
    std::uint64_t played{}, written{};
    DWORD cursor{};
    bool paused{true}, running{};
    std::chrono::steady_clock::time_point lastPoll{};
    void Copy(
      DWORD offset,
      const void* source,
      DWORD count
    )
    {
      void *first{}, *second{};
      DWORD firstBytes{}, secondBytes{};
      Check(buffer->Lock(offset, count, &first, &firstBytes, &second, &secondBytes, 0));
      if (source) {
        std::memcpy(first, source, firstBytes);
        if (secondBytes)
          std::memcpy(second, static_cast<const std::byte*>(source) + firstBytes, secondBytes);
      } else {
        std::memset(first, 0, firstBytes);
        if (secondBytes)
          std::memset(second, 0, secondBytes);
      }
      Check(buffer->Unlock(first, firstBytes, second, secondBytes));
    }
  };
  AudioSink::AudioSink(
    IDirectSound* device
  )
    : impl(std::make_unique<Impl>())
  {
    if (!device)
      throw std::runtime_error("No movie audio device");
    WAVEFORMATEX format{};
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = 2;
    format.nSamplesPerSec = 48000;
    format.nAvgBytesPerSec = bytesPerSecond;
    format.nBlockAlign = 4;
    format.wBitsPerSample = 16;
    DSBUFFERDESC description{};
    description.dwSize = sizeof(description);
    description.dwFlags = DSBCAPS_CTRLVOLUME | DSBCAPS_GETCURRENTPOSITION2 | DSBCAPS_GLOBALFOCUS;
    description.dwBufferBytes = capacity;
    description.lpwfxFormat = &format;
    IDirectSoundBuffer* buffer{};
    Check(device->CreateSoundBuffer(&description, &buffer, nullptr));
    impl->buffer.reset(buffer);
    impl->Copy(0, nullptr, capacity);
  }
  AudioSink::~AudioSink()
  {
    if (impl->buffer)
      impl->buffer->Stop();
  }
  void AudioSink::Pump()
  {
    auto& s = *impl;
    const auto now = std::chrono::steady_clock::now();
    if (s.running) {
      // Multiple wraps cannot be reconstructed from one hardware cursor. Fail
      // explicitly after a stalled worker instead of replaying stale PCM.
      if (now - s.lastPoll >= std::chrono::seconds(2))
        throw std::runtime_error("Movie audio clock polling stalled");
      DWORD play{}, write{};
      Check(s.buffer->GetCurrentPosition(&play, &write));
      play -= play % 4;
      const DWORD consumed = (play + capacity - s.cursor) % capacity;
      s.played = std::min(s.written, s.played + consumed);
      // Retire consumed PCM to silence. Keeping only a short silent tail would
      // let an underrun expose samples left over from an earlier buffer wrap.
      if (consumed)
        s.Copy(s.cursor, nullptr, consumed);
      s.cursor = play;
      if (s.played == s.written) {
        Check(s.buffer->Stop());
        s.running = false;
        s.cursor = static_cast<DWORD>(s.written % capacity);
        Check(s.buffer->SetCurrentPosition(s.cursor));
      }
    }
    s.lastPoll = now;
    if (!s.running && !s.paused && s.written > s.played) {
      Check(s.buffer->Play(0, 0, DSBPLAY_LOOPING));
      s.running = true;
    }
  }
  std::size_t AudioSink::Write(
    std::span<const std::int16_t> stereo
  )
  {
    auto& s = *impl;
    const auto free = capacity - guardBytes - (s.written - s.played);
    const auto bytes = static_cast<DWORD>(std::min<std::uint64_t>(stereo.size_bytes(), free)) & ~DWORD{3};
    if (!bytes)
      return 0;
    s.Copy(static_cast<DWORD>(s.written % capacity), stereo.data(), bytes);
    s.written += bytes;
    // Keep a silent guard after the tail, so a scheduling hiccup cannot replay
    // bytes from an earlier wrap while the worker detects the underrun.
    s.Copy(static_cast<DWORD>(s.written % capacity), nullptr, guardBytes);
    return bytes / sizeof(std::int16_t);
  }
  void AudioSink::Pause(
    bool paused
  )
  {
    Pump();
    auto& s = *impl;
    s.paused = paused;
    if (paused && s.running) {
      Check(s.buffer->Stop());
      s.running = false;
    }
    if (!paused)
      Pump();
  }
  void AudioSink::Stop()
  {
    auto& s = *impl;
    Check(s.buffer->Stop());
    Check(s.buffer->SetCurrentPosition(0));
    s.running = false;
    s.paused = true;
    s.played = s.written = s.cursor = 0;
    s.Copy(0, nullptr, capacity);
  }
  void AudioSink::SetVolume(
    long attenuation
  )
  {
    Check(impl->buffer->SetVolume(std::clamp(attenuation, -10000L, 0L)));
  }
  double AudioSink::Clock() const
  {
    return static_cast<double>(impl->played) / bytesPerSecond;
  }
  double AudioSink::Submitted() const
  {
    return static_cast<double>(impl->written) / bytesPerSecond;
  }
  bool AudioSink::Empty() const
  {
    return impl->played == impl->written;
  }
} // namespace moho::sfd
