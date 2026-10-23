#include "IndependentSfdBackend.h"
#include "DirectSoundMovieSink.h"
#include "SfdMetadata.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
#include <windows.h>

namespace moho::sfd
{
  namespace
  {
    using Clock = std::chrono::steady_clock;
    std::mutex registryMutex;
    std::set<Player*> players;
    IDirectSound* soundDevice{}; // CMovieManager owns the device; shutdown precedes release.
    long volume{};
    std::atomic<ErrorCallback> errorCallback{};
    std::atomic<std::uint32_t> errorParameter{};
  } // namespace
  void ReportError(
    const char* message
  )
  {
    if (const auto callback = errorCallback.load())
      callback(errorParameter.load(), message);
    else {
      OutputDebugStringA(message);
      OutputDebugStringA("\n");
    }
  }
  void SetErrorCallback(
    ErrorCallback callback,
    std::uint32_t parameter
  )
  {
    errorParameter = parameter;
    errorCallback = callback;
  }
  struct Player::Impl
  {
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::thread worker;
    bool quitting{}, paused{true}, eof{}, audioFinished{};
    int status{1};
    Metadata metadata;
    std::string filename;
    std::unique_ptr<FfmpegDecoder> decoder;
    std::unique_ptr<AudioSink> sink;
    std::deque<std::shared_ptr<DecodedVideoFrame>> video;
    std::deque<DecodedAudioFrame> audio;
    std::size_t audioOffset{};
    std::shared_ptr<DecodedVideoFrame> current;
    double frozenTime{}, endTime{};
    Clock::time_point anchor{Clock::now()};

    double Time() const
    {
      if (paused)
        return frozenTime;
      if (sink && !audioFinished)
        return sink->Clock();
      return frozenTime + std::chrono::duration<double>(Clock::now() - anchor).count();
    }
    void Fail(
      const std::exception& error
    )
    {
      status = 4;
      sink.reset();
      ReportError(("FAF SFD: " + filename + ": " + error.what()).c_str());
    }
    void Decode()
    {
      DecodeBatch batch;
      if (!decoder->Read(batch))
        eof = true;
      for (auto& frame : batch.video) {
        if (frame->width != metadata.header.width || frame->height != metadata.header.height)
          throw std::runtime_error("Decoded dimensions disagree with SFD header");
        endTime = std::max(endTime, frame->pts + frame->duration);
        video.push_back(std::move(frame));
      }
      for (auto& frame : batch.audio) {
        endTime = std::max(endTime, frame.pts + static_cast<double>(frame.samples.size()) / 96000);
        if (sink)
          audio.push_back(std::move(frame));
      }
      // A corrupt or radically noninterleaved file must not grow memory without bound.
      std::size_t queuedBytes{};
      for (const auto& frame : video)
        queuedBytes += frame->bgra.size();
      for (const auto& frame : audio)
        queuedBytes += frame.samples.size() * sizeof(std::int16_t);
      if (video.size() > 120 || audio.size() > 512 || queuedBytes > 128 * 1024 * 1024)
        throw std::runtime_error("Excessive SFD stream interleave");
    }
    void SupplyAudio()
    {
      if (!sink)
        return;
      sink->Pump();
      constexpr std::array<std::int16_t, 4096> silence{};
      while (!audio.empty()) {
        auto& frame = audio.front();
        const auto target =
          static_cast<std::int64_t>(std::llround(frame.pts * 48000)) + static_cast<std::int64_t>(audioOffset / 2);
        const auto submitted = static_cast<std::int64_t>(std::llround(sink->Submitted() * 48000));
        const auto gap = target - submitted;
        if (gap > 1) {
          const auto count = static_cast<std::size_t>(std::min<std::int64_t>(gap * 2, silence.size()));
          if (!sink->Write(std::span(silence).first(count)))
            break;
          continue;
        }
        if (gap < -1)
          audioOffset += static_cast<std::size_t>(std::min<std::int64_t>(-gap * 2, frame.samples.size() - audioOffset));
        const auto remaining = std::span(frame.samples).subspan(audioOffset);
        const auto written = sink->Write(remaining);
        audioOffset += written;
        if (audioOffset == frame.samples.size()) {
          audio.pop_front();
          audioOffset = 0;
        } else if (!written)
          break;
      }
      if (eof && audio.empty() && sink->Empty() && !audioFinished) {
        frozenTime = sink->Clock();
        anchor = Clock::now();
        audioFinished = true;
      }
    }
    void Tick()
    {
      SupplyAudio();
      double now = Time();
      // Keep about half a second ready. A worker pumps independently of rendering,
      // including while the engine is loading or not requesting textures.
      for (unsigned budget = 0; !eof && budget < 256; ++budget) {
        const bool needVideo = video.empty() || video.back()->pts < now + 0.5;
        const bool needAudio = sink && sink->Submitted() < now + 0.5;
        if (!needVideo && !needAudio)
          break;
        Decode();
        SupplyAudio();
      }
      now = Time();
      while (!video.empty() && (video.front()->pts <= now + 0.005 || !current)) {
        current = std::move(video.front());
        video.pop_front();
      }
      if (eof && video.empty() && (!sink || (audio.empty() && sink->Empty())) && now >= endTime)
        status = 3;
    }
    void Run()
    {
      std::unique_lock lock(mutex);
      while (!quitting && status == 2) {
        if (!paused) {
          try {
            Tick();
          } catch (const std::exception& error) {
            Fail(error);
          }
        }
        wake.wait_for(lock, std::chrono::milliseconds(5), [this] {
          return quitting;
        });
      }
    }
  };
  Player::Player()
    : impl(std::make_unique<Impl>())
  {
    std::lock_guard lock(registryMutex);
    players.insert(this);
  }
  Player::~Player()
  {
    {
      std::lock_guard lock(registryMutex);
      players.erase(this);
    }
    Close();
  }
  void Player::Close()
  {
    auto& s = *impl;
    {
      std::lock_guard lock(s.mutex);
      s.quitting = true;
      s.wake.notify_all();
    }
    if (s.worker.joinable())
      s.worker.join();
    std::lock_guard lock(s.mutex);
    s.sink.reset();
    s.decoder.reset();
    s.video.clear();
    s.audio.clear();
    s.current.reset();
    s.status = 1;
  }
  bool Player::Open(
    const char* filename
  )
  {
    Close();
    IDirectSound* device{};
    long attenuation{};
    {
      std::lock_guard lock(registryMutex);
      device = soundDevice;
      attenuation = volume;
    }
    auto& s = *impl;
    std::lock_guard lock(s.mutex);
    s.filename = filename ? filename : "";
    s.quitting = false;
    s.eof = false;
    s.audioFinished = false;
    s.audioOffset = 0;
    s.frozenTime = 0;
    s.endTime = 0;
    s.anchor = Clock::now();
    try {
      std::string error;
      if (!ReadMetadata(filename, s.metadata, error))
        throw std::runtime_error(error);
      const auto& h = s.metadata.header;
      if (h.videos[0].effect != 0 || h.videos[0].colourType != 0 || h.videos[0].pictureType != 0) {
        throw std::runtime_error(
          "Unsupported composition: mode=" + std::to_string(h.compositionMode) +
          " effect=" + std::to_string(h.videos[0].effect) + " dimensions=" + std::to_string(h.width) + "x" +
          std::to_string(h.height) + " colour=" + std::to_string(h.videos[0].colourType) +
          " picture=" + std::to_string(h.videos[0].pictureType) + " flags=" + std::to_string(h.videos[0].flags)
        );
      }
#ifdef _DEBUG
      for (const auto length : s.metadata.privatePacketLengths)
        OutputDebugStringA(
          ("FAF SFD private_stream_2 candidate: " + s.filename + " length=" + std::to_string(length) + "\n").c_str()
        );
#endif
      s.decoder = std::make_unique<FfmpegDecoder>();
      s.decoder->Open(filename, device != nullptr);
      if (h.audioStreams && !s.decoder->HasAudio())
        throw std::runtime_error("Declared embedded audio stream was not found");
      if (device && s.decoder->HasAudio()) {
        s.sink = std::make_unique<AudioSink>(device);
        s.sink->SetVolume(attenuation);
      }
      // Prime while paused so OpenMovie can upload the first frame immediately.
      for (unsigned packets = 0; s.video.empty() && !s.eof && packets < 8192; ++packets) {
        s.Decode();
        s.SupplyAudio();
      }
      if (s.video.empty())
        throw std::runtime_error("No initial movie frame");
      s.current = std::move(s.video.front());
      s.video.pop_front();
      s.status = 2;
      s.anchor = Clock::now();
      if (s.sink)
        s.sink->Pause(s.paused);
      s.worker = std::thread([&s] {
        s.Run();
      });
      return true;
    } catch (const std::exception& error) {
      s.Fail(error);
      return false;
    }
  }
  bool Player::Pause(
    bool paused
  )
  {
    auto& s = *impl;
    std::lock_guard lock(s.mutex);
    if (s.status == 4)
      return false;
    if (s.paused == paused)
      return true;
    try {
      if (s.sink)
        s.sink->Pause(paused);
      s.frozenTime = s.Time();
      s.anchor = Clock::now();
      s.paused = paused;
      s.wake.notify_all();
      return true;
    } catch (const std::exception& error) {
      s.Fail(error);
      return false;
    }
  }
  bool Player::IsPaused() const
  {
    std::lock_guard lock(impl->mutex);
    return impl->paused;
  }
  int Player::Status() const
  {
    std::lock_guard lock(impl->mutex);
    return impl->status;
  }
  int Player::CompositionMode() const
  {
    std::lock_guard lock(impl->mutex);
    return impl->metadata.header.compositionMode;
  }
  std::shared_ptr<DecodedVideoFrame> Player::CurrentFrame()
  {
    std::lock_guard lock(impl->mutex);
    return impl->current;
  }
  void Player::SetVolume(
    long attenuation
  )
  {
    std::lock_guard lock(impl->mutex);
    try {
      if (impl->sink)
        impl->sink->SetVolume(attenuation);
    } catch (const std::exception& error) {
      impl->Fail(error);
    }
  }
  void SetVolume(
    long attenuation
  )
  {
    std::lock_guard lock(registryMutex);
    volume = std::clamp(attenuation, -10000L, 0L);
    for (auto* player : players)
      player->SetVolume(volume);
  }
  void SetSoundDevice(
    IDirectSound* device
  )
  {
    std::lock_guard lock(registryMutex);
    if (device != soundDevice)
      for (auto* player : players)
        player->Close();
    soundDevice = device;
  }
  void Shutdown()
  {
    std::lock_guard lock(registryMutex);
    for (auto* player : players)
      player->Close();
    soundDevice = nullptr;
  }
} // namespace moho::sfd
