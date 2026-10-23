#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace moho::sfd
{
  struct DecodedVideoFrame
  {
    int width{}, height{}, pitch{};
    double pts{}, duration{};
    std::vector<std::uint8_t> bgra;
  };
  struct DecodedAudioFrame
  {
    double pts{};
    // Interleaved stereo signed PCM, 48000 samples/second per channel.
    std::vector<std::int16_t> samples;
  };
  struct DecodeBatch
  {
    std::vector<std::shared_ptr<DecodedVideoFrame>> video;
    std::vector<DecodedAudioFrame> audio;
  };
  class FfmpegDecoder
  {
  public:
    FfmpegDecoder();
    ~FfmpegDecoder();
    FfmpegDecoder(const FfmpegDecoder&) = delete;
    FfmpegDecoder& operator=(const FfmpegDecoder&) = delete;
    void Open(const char* filename, bool decodeAudio);
    // Returns false after both decoders and the resampler have been drained.
    bool Read(DecodeBatch& batch);
    bool HasAudio() const;
    int Width() const;
    int Height() const;
    int AudioSampleRate() const;
    int AudioChannels() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl;
  };
} // namespace moho::sfd
