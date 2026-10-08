#pragma once
#include "FfmpegSfdDecoder.h"
#include <cstdint>
#include <memory>
struct IDirectSound;
namespace moho::sfd
{
  using ErrorCallback = int(__cdecl*)(std::uint32_t, const char*);
  void SetSoundDevice(IDirectSound* device);
  void SetErrorCallback(ErrorCallback callback, std::uint32_t parameter);
  void SetVolume(long attenuation);
  void Shutdown();
  void ReportError(const char* message);

  class Player
  {
  public:
    Player();
    ~Player();
    Player(const Player&) = delete;
    Player& operator=(const Player&) = delete;
    bool Open(const char* filename);
    void Close();
    bool Pause(bool paused);
    bool IsPaused() const;
    int Status() const;
    int CompositionMode() const;
    std::shared_ptr<DecodedVideoFrame> CurrentFrame();
    void SetVolume(long attenuation);

  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
  };
} // namespace moho::sfd
