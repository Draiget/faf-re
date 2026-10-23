#pragma once
#include <cstdint>
#include <memory>
#include <span>
struct IDirectSound;
namespace moho::sfd
{
  class AudioSink
  {
  public:
    explicit AudioSink(IDirectSound* device);
    ~AudioSink();
    AudioSink(const AudioSink&) = delete;
    AudioSink& operator=(const AudioSink&) = delete;
    // Pump and all access occur on the player's serialized timeline.
    void Pump();
    std::size_t Write(std::span<const std::int16_t> stereo);
    void Pause(bool paused);
    void Stop();
    void SetVolume(long attenuation);
    double Clock() const;
    double Submitted() const;
    bool Empty() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
  };
} // namespace moho::sfd
